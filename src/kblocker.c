#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/timer.h>
#include <linux/utsname.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>
#include <crypto/hash.h>
#include <net/ipv6.h>
#include <net/tcp.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("kblocker");
MODULE_DESCRIPTION("Self-discipline internet blocker - disabled by default, time-limited enable");
MODULE_VERSION("2.0");

#define MAX_IPS_V4 4096
#define MAX_IPS_V6 1024
#define PROTECT_INTERVAL_MS 1000
#define MAX_PROTECTED_PATHS 8
#define MAX_DOMAINS 64
#define MAX_DOMAIN_LEN 256

static __be32 *blocked_ips_v4;
static int blocked_count_v4;
static struct in6_addr *blocked_ips_v6;
static int blocked_count_v6;
static char blocked_domains[MAX_DOMAINS][MAX_DOMAIN_LEN];
static int blocked_domain_count;
static DEFINE_SPINLOCK(ip_list_lock);

static bool allow_unload;
static u8 unload_key[16];
static u8 key_hash[32];
static bool state_restored;
static struct kobject *kblocker_kobj;
static struct nf_hook_ops nfho_out;
static struct nf_hook_ops nfho_forward;
static bool ipv4_registered;
static bool forward_registered;

static char ko_path[256];
static bool kblocker_bypass_protection;
static struct protected_file {
	char path[256];
	bool exists;
	struct inode *inode;
	const struct inode_operations *orig_i_op;
	struct inode_operations *custom_i_op;
} protected_files[MAX_PROTECTED_PATHS];
static int num_protected_files;
static struct timer_list protect_timer;
static bool timer_active;

static bool enabled;
static u64 expiry_seconds;
static unsigned long expiry_jiffies;
static struct timer_list enable_timer;
static bool enable_timer_active;
static atomic_t ref_taken = ATOMIC_INIT(0);
static bool pgp_active;

static struct work_struct kb_disable_work;
static struct work_struct kb_protect_work;

static bool ct_memcmp_eq(const u8 *a, const u8 *b, size_t size)
{
	u8 diff = 0;
	size_t i;
	for (i = 0; i < size; i++)
		diff |= READ_ONCE(a[i]) ^ READ_ONCE(b[i]);
	return diff == 0;
}

static bool is_ip_blocked(__be32 addr)
{
	int i;
	bool found = false;

	spin_lock_bh(&ip_list_lock);
	for (i = 0; i < blocked_count_v4; i++) {
		if (blocked_ips_v4[i] == addr) {
			found = true;
			break;
		}
	}
	spin_unlock_bh(&ip_list_lock);

	return found;
}

#if IS_ENABLED(CONFIG_IPV6)
static bool is_ipv6_blocked(struct in6_addr *addr)
{
	int i;
	bool found = false;

	spin_lock_bh(&ip_list_lock);
	for (i = 0; i < blocked_count_v6; i++) {
		if (ipv6_addr_equal(&blocked_ips_v6[i], addr)) {
			found = true;
			break;
		}
	}
	spin_unlock_bh(&ip_list_lock);

	return found;
}
#endif

static bool domain_list_contains(const char *hostname)
{
	int i;
	bool found = false;

	spin_lock_bh(&ip_list_lock);
	if (!blocked_domain_count)
		goto out;
	for (i = 0; i < blocked_domain_count; i++) {
		const char *blocked = blocked_domains[i];
		int blen = strlen(blocked);
		const char *p = hostname;
		while (*p) {
			if (strncasecmp(p, blocked, blen) == 0) {
				found = true;
				goto out;
			}
			p++;
		}
	}
out:
	spin_unlock_bh(&ip_list_lock);
	return found;
}

static bool sni_matches_blocked(const struct sk_buff *skb, struct tcphdr *tcph)
{
	int thlen = tcph->doff * 4;
	const u8 *data;
	int data_len, offset;

	data = (u8 *)tcph + thlen;
	data_len = skb->len - (int)((u8 *)tcph - skb->data) - thlen;

	if (data_len < 6)
		return false;
	if (data[0] != 0x16) {
		return false;
	}
	if (data[5] != 0x01) {
		return false;
	}

	offset = 5 + 4;
	if (offset + 34 > data_len)
		return false;
	offset += 2;
	offset += 32;

	if (offset + 1 > data_len)
		return false;
	offset += 1 + data[offset];

	if (offset + 2 > data_len)
		return false;
	offset += 2 + (data[offset] << 8 | data[offset + 1]);

	if (offset + 1 > data_len)
		return false;
	offset += 1 + data[offset];

	if (offset + 2 > data_len)
		return false;
	{
		int ext_total = (data[offset] << 8) | data[offset + 1];
		offset += 2;

		while (offset + 4 <= data_len && ext_total > 0) {
			int ext_type = (data[offset] << 8) | data[offset + 1];
			int ext_len = (data[offset + 2] << 8) | data[offset + 3];
			offset += 4;
			ext_total -= 4;

			if (ext_type == 0xFE0A) {
				return true;
			}
			if (ext_type == 0x0000) {
				if (offset + 3 > data_len)
					return false;
				offset += 2;
				if (data[offset] != 0x00)
					return false;
				offset += 1;
				if (offset + 2 > data_len)
					return false;
				int name_len = (data[offset] << 8) | data[offset + 1];
				offset += 2;

				if (name_len > 0 && offset + name_len <= data_len) {
					char sni_buf[MAX_DOMAIN_LEN];
					int copy_len = min(name_len, (int)sizeof(sni_buf) - 1);
					memcpy(sni_buf, data + offset, copy_len);
					sni_buf[copy_len] = '\0';
					return domain_list_contains(sni_buf);
				}
				return false;
			}
			offset += ext_len;
			ext_total -= ext_len;
		}
	}
	return false;
}

static unsigned int kblocker_hook_v4(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state);
#if IS_ENABLED(CONFIG_IPV6)
static unsigned int kblocker_hook_v6(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
static unsigned int kblocker_hook(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
#else
static unsigned int kblocker_hook(unsigned int hooknum, struct sk_buff *skb,
				     const struct net_device *in, const struct net_device *out,
				     int (*okfn)(struct sk_buff *))
#endif
{
	if (!READ_ONCE(enabled)) return NF_ACCEPT;
	if (!skb) return NF_ACCEPT;

	if (state->pf == NFPROTO_IPV4)
		return kblocker_hook_v4(priv, skb, state);
#if IS_ENABLED(CONFIG_IPV6)
	if (state->pf == NFPROTO_IPV6)
		return kblocker_hook_v6(priv, skb, state);
#endif
	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
static unsigned int kblocker_hook_v4(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
#else
static unsigned int kblocker_hook_v4(unsigned int hooknum, struct sk_buff *skb,
				    const struct net_device *in, const struct net_device *out,
				    int (*okfn)(struct sk_buff *))
#endif
{
	struct iphdr *iph;
	struct tcphdr *tcph;

	if (READ_ONCE(blocked_count_v4)) {
		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			return NF_ACCEPT;
		iph = ip_hdr(skb);
		if (!iph) return NF_ACCEPT;
		if (is_ip_blocked(iph->daddr))
			return NF_DROP;
	}

	if (READ_ONCE(blocked_domain_count)) {
		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			return NF_ACCEPT;
		iph = ip_hdr(skb);
		if (!iph) return NF_ACCEPT;
		if (iph->protocol == IPPROTO_UDP) {
			int ip_hdr_len = iph->ihl * 4;
			if (pskb_may_pull(skb, ip_hdr_len + sizeof(struct udphdr))) {
				iph = ip_hdr(skb);
				struct udphdr *udph = (void *)iph + ip_hdr_len;
				if (udph->dest == htons(443))
					return NF_DROP;
			}
			return NF_ACCEPT;
		}
		if (iph->protocol != IPPROTO_TCP)
			return NF_ACCEPT;
		int ip_hdr_len = iph->ihl * 4;
		if (!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
			return NF_ACCEPT;
		iph = ip_hdr(skb);
		tcph = (void *)iph + ip_hdr_len;
		if (tcph->syn || !tcph->ack || tcph->rst)
			return NF_ACCEPT;
		int tcp_data_off = ip_hdr_len + (tcph->doff * 4);
		int sni_pull = tcp_data_off + 512;
		if (sni_pull > skb->len)
			sni_pull = skb->len;
		if (!pskb_may_pull(skb, sni_pull))
			return NF_ACCEPT;
		iph = ip_hdr(skb);
		tcph = (void *)iph + ip_hdr_len;
		if (sni_matches_blocked(skb, tcph))
			return NF_DROP;
	}

	return NF_ACCEPT;
}

#if IS_ENABLED(CONFIG_IPV6)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
static unsigned int kblocker_hook_v6(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
#else
static unsigned int kblocker_hook_v6(unsigned int hooknum, struct sk_buff *skb,
				    const struct net_device *in, const struct net_device *out,
				    int (*okfn)(struct sk_buff *))
#endif
{
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;

	if (!READ_ONCE(enabled)) return NF_ACCEPT;

	if (READ_ONCE(blocked_count_v6)) {
		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
			return NF_ACCEPT;
		ip6h = ipv6_hdr(skb);
		if (!ip6h) return NF_ACCEPT;
		if (is_ipv6_blocked(&ip6h->daddr))
			return NF_DROP;
	}

	if (READ_ONCE(blocked_domain_count)) {
		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
			return NF_ACCEPT;
		ip6h = ipv6_hdr(skb);
		if (!ip6h) return NF_ACCEPT;

		u8 nexthdr = ip6h->nexthdr;
		int hdr_offset = sizeof(struct ipv6hdr);

		if (nexthdr == IPPROTO_UDP) {
			if (pskb_may_pull(skb, hdr_offset + sizeof(struct udphdr))) {
				struct udphdr *udph = (struct udphdr *)((u8 *)ipv6_hdr(skb) + hdr_offset);
				if (udph->dest == htons(443))
					return NF_DROP;
			}
			return NF_ACCEPT;
		}
		if (nexthdr != IPPROTO_TCP)
			return NF_ACCEPT;
		if (!pskb_may_pull(skb, hdr_offset + sizeof(struct tcphdr)))
			return NF_ACCEPT;
		ip6h = ipv6_hdr(skb);
		tcph = (struct tcphdr *)((u8 *)ip6h + hdr_offset);
		if (tcph->syn || !tcph->ack || tcph->rst)
			return NF_ACCEPT;
		int tcp_data_off = hdr_offset + (tcph->doff * 4);
		int sni_pull = tcp_data_off + 512;
		if (sni_pull > skb->len)
			sni_pull = skb->len;
		if (!pskb_may_pull(skb, sni_pull))
			return NF_ACCEPT;
		ip6h = ipv6_hdr(skb);
		tcph = (struct tcphdr *)((u8 *)ip6h + hdr_offset);
		if (sni_matches_blocked(skb, tcph))
			return NF_DROP;
	}

	return NF_ACCEPT;
}
#endif

static void enable_blocking(unsigned int seconds);
static int update_hosts_file(void);
static void do_disable_work(struct work_struct *work);
static void generate_unload_key(void);

static void enable_timer_cb(struct timer_list *t)
{
	if (!READ_ONCE(enabled))
		return;

	if (ktime_get_real_seconds() >= expiry_seconds) {
		WRITE_ONCE(enabled, false);
		expiry_jiffies = 0;
		expiry_seconds = 0;
		WRITE_ONCE(state_restored, false);
		WRITE_ONCE(pgp_active, false);
		if (atomic_xchg(&ref_taken, 0))
			module_put(THIS_MODULE);
		printk(KERN_INFO "kblocker: timer-expired, disabling\n");
		schedule_work(&kb_disable_work);
		return;
	}

	mod_timer(&enable_timer, jiffies + HZ);
}

static void enable_blocking(unsigned int seconds)
{
	generate_unload_key();
	WRITE_ONCE(enabled, true);
	expiry_seconds = ktime_get_real_seconds() + seconds;
	expiry_jiffies = jiffies + msecs_to_jiffies((unsigned long)seconds * 1000);
	mod_timer(&enable_timer, jiffies + HZ);
	WRITE_ONCE(enable_timer_active, true);
	WRITE_ONCE(state_restored, false);
	if (!atomic_xchg(&ref_taken, 1)) {
		__module_get(THIS_MODULE);
	}
	/* Re-enable file protection if it was disabled by a prior unblock */
	WRITE_ONCE(allow_unload, false);
	if (!timer_active || !timer_pending(&protect_timer)) {
		mod_timer(&protect_timer,
			  jiffies + msecs_to_jiffies(PROTECT_INTERVAL_MS));
		timer_active = true;
	}
	update_hosts_file();
	printk(KERN_INFO "kblocker: enabled for %u seconds\n", seconds);
}

static void log_blocklist_on_disable(void)
{
	int i;

	if (READ_ONCE(blocked_count_v4)) {
		spin_lock_bh(&ip_list_lock);
		printk(KERN_DEBUG "kblocker: blocked IPv4 on disable:");
		for (i = 0; i < blocked_count_v4; i++)
			printk(KERN_DEBUG "kblocker:   %pI4", &blocked_ips_v4[i]);
		spin_unlock_bh(&ip_list_lock);
	}

	if (READ_ONCE(blocked_count_v6)) {
		spin_lock_bh(&ip_list_lock);
		printk(KERN_DEBUG "kblocker: blocked IPv6 on disable:");
		for (i = 0; i < blocked_count_v6; i++)
			printk(KERN_DEBUG "kblocker:   %pI6", &blocked_ips_v6[i]);
		spin_unlock_bh(&ip_list_lock);
	}

	if (READ_ONCE(blocked_domain_count)) {
		spin_lock_bh(&ip_list_lock);
		printk(KERN_DEBUG "kblocker: blocked domains on disable:");
		for (i = 0; i < blocked_domain_count; i++)
			printk(KERN_DEBUG "kblocker:   %s", blocked_domains[i]);
		spin_unlock_bh(&ip_list_lock);
	}
}

#define HOSTS_MARKER "# kblocker managed entries - do not edit manually"
#define HOSTS_MAX_SIZE (1024 * 1024)
#define STATE_FILE "/var/lib/kblocker/state"

static int hosts_clear_immutable(void)
{
	struct path kp;
	struct inode *inode;
	int was_set = 0;

	if (kern_path("/etc/hosts", 0, &kp))
		return 0;

	inode = d_inode(kp.dentry);
	if (inode) {
		inode_lock(inode);
		if (inode->i_flags & S_IMMUTABLE) {
			was_set = 1;
			inode_set_flags(inode, 0, S_IMMUTABLE);
		}
		inode_unlock(inode);
	}
	path_put(&kp);
	return was_set;
}

static char *hosts_read_all(struct file *f, loff_t *out_len)
{
	loff_t size = i_size_read(file_inode(f));
	char *buf;
	ssize_t ret;
	loff_t pos = 0;

	if (size <= 0 || size > HOSTS_MAX_SIZE)
		return NULL;

	buf = kmalloc(size + 1, GFP_KERNEL);
	if (!buf)
		return NULL;

	ret = kernel_read(f, buf, size, &pos);
	if (ret <= 0) {
		kfree(buf);
		return NULL;
	}
	buf[ret] = '\0';
	*out_len = ret;
	return buf;
}

static void clear_hosts_from_kernel(void)
{
	struct file *file;
	struct path kp;
	struct inode *inode;
	char *buf, *out, *p;
	loff_t len;
	ssize_t out_len;
	loff_t pos = 0;

	WRITE_ONCE(kblocker_bypass_protection, true);

	hosts_clear_immutable();
	file = filp_open("/etc/hosts", O_RDWR, 0);
	if (IS_ERR(file)) {
		WRITE_ONCE(kblocker_bypass_protection, false);
		return;
	}

	buf = hosts_read_all(file, &len);
	if (!buf) {
		filp_close(file, NULL);
		WRITE_ONCE(kblocker_bypass_protection, false);
		return;
	}

	p = strstr(buf, HOSTS_MARKER);
	if (!p) {
		printk(KERN_INFO "kblocker: clear_hosts: marker not found, nothing to clear\n");
		kfree(buf);
		filp_close(file, NULL);
		WRITE_ONCE(kblocker_bypass_protection, false);
		return;
	}
	printk(KERN_DEBUG "kblocker: clear_hosts: found marker at offset %ld\n", p - buf);

	out_len = p - buf;
	while (out_len > 0 && buf[out_len - 1] == '\n')
		out_len--;

	out = kmalloc(out_len + 2, GFP_KERNEL);
	if (!out) {
		kfree(buf);
		filp_close(file, NULL);
		WRITE_ONCE(kblocker_bypass_protection, false);
		return;
	}

	memcpy(out, buf, out_len);
	out[out_len] = '\n';
	out_len++;
	out[out_len] = '\0';

	hosts_clear_immutable();
	kernel_write(file, out, out_len, &pos);

	if (!kern_path("/etc/hosts", 0, &kp)) {
		inode = d_inode(kp.dentry);
		if (inode) {
			inode_lock(inode);
			if (inode->i_flags & S_IMMUTABLE)
				inode_set_flags(inode, 0, S_IMMUTABLE);
			inode_unlock(inode);
			vfs_truncate(&kp, out_len);
		}
		path_put(&kp);
	}

	kfree(out);
	kfree(buf);
	filp_close(file, NULL);

	printk(KERN_DEBUG "kblocker: cleared hosts file entries\n");
	WRITE_ONCE(kblocker_bypass_protection, false);
}

static int update_hosts_file(void)
{
	struct file *file;
	struct path kp;
	struct inode *inode;
	char *buf = NULL, *out, *p;
	loff_t len, base_len = 0;
	ssize_t pos;
	int i, ndom;
	size_t out_size;
	loff_t zero = 0;

	WRITE_ONCE(kblocker_bypass_protection, true);

	hosts_clear_immutable();
	file = filp_open("/etc/hosts", O_RDWR, 0);
	if (IS_ERR(file)) {
		int err = PTR_ERR(file);
		printk(KERN_ERR "kblocker: filp_open /etc/hosts failed: %d\n", err);
		WRITE_ONCE(kblocker_bypass_protection, false);
		return err;
	}

	buf = hosts_read_all(file, &len);
	if (buf) {
		p = strstr(buf, HOSTS_MARKER);
		if (p) {
			base_len = p - buf;
			while (base_len > 0 && buf[base_len - 1] == '\n')
				base_len--;
		} else {
			base_len = len;
			while (base_len > 0 && buf[base_len - 1] == '\n')
				base_len--;
		}
	} else {
		base_len = 0;
	}

	spin_lock_bh(&ip_list_lock);
	ndom = blocked_domain_count;
	if (!ndom) {
		spin_unlock_bh(&ip_list_lock);
		kfree(buf);
		filp_close(file, NULL);
		clear_hosts_from_kernel();
		return 0;
	}

	out_size = base_len + 2 + sizeof(HOSTS_MARKER) + 1;
	for (i = 0; i < ndom; i++) {
		int dlen = strlen(blocked_domains[i]);
		out_size += dlen * 4 + 64;
	}
	spin_unlock_bh(&ip_list_lock);
	out_size += 1;

	out = kmalloc(out_size, GFP_KERNEL);
	if (!out) {
		kfree(buf);
		filp_close(file, NULL);
		WRITE_ONCE(kblocker_bypass_protection, false);
		return -ENOMEM;
	}

	pos = 0;
	memcpy(out, buf ? buf : "", base_len);
	pos += base_len;
	out[pos++] = '\n';
	out[pos++] = '\n';
	memcpy(out + pos, HOSTS_MARKER, sizeof(HOSTS_MARKER) - 1);
	pos += sizeof(HOSTS_MARKER) - 1;
	out[pos++] = '\n';

	spin_lock_bh(&ip_list_lock);
	ndom = blocked_domain_count;
	for (i = 0; i < ndom; i++) {
		const char *d = blocked_domains[i];
		pos += snprintf(out + pos, out_size - pos, "0.0.0.0 %s\n", d);
		pos += snprintf(out + pos, out_size - pos, ":: %s\n", d);
		pos += snprintf(out + pos, out_size - pos, "0.0.0.0 www.%s\n", d);
		pos += snprintf(out + pos, out_size - pos, ":: www.%s\n", d);
	}
	spin_unlock_bh(&ip_list_lock);
	out[pos++] = '\n';

	kfree(buf);

	hosts_clear_immutable();
	kernel_write(file, out, pos, &zero);

	if (!kern_path("/etc/hosts", 0, &kp)) {
		inode = d_inode(kp.dentry);
		if (inode) {
			inode_lock(inode);
			if (inode->i_flags & S_IMMUTABLE)
				inode_set_flags(inode, 0, S_IMMUTABLE);
			inode_unlock(inode);
			vfs_truncate(&kp, pos);
			inode_lock(inode);
			inode_set_flags(inode, S_IMMUTABLE, S_IMMUTABLE);
			inode_unlock(inode);
		}
		path_put(&kp);
	}

	kfree(out);
	filp_close(file, NULL);

	printk(KERN_DEBUG "kblocker: updated hosts file with %d domains\n", ndom);
	WRITE_ONCE(kblocker_bypass_protection, false);
	return 0;
}

static void do_disable_cleanup(void)
{
	log_blocklist_on_disable();
	clear_hosts_from_kernel();

	if (READ_ONCE(enable_timer_active)) {
		timer_delete(&enable_timer);
		WRITE_ONCE(enable_timer_active, false);
	}
	printk(KERN_INFO "kblocker: disabled\n");
}

static void do_disable(void)
{
	WRITE_ONCE(enabled, false);
	expiry_jiffies = 0;
	expiry_seconds = 0;
	WRITE_ONCE(state_restored, false);
	if (atomic_xchg(&ref_taken, 0))
		module_put(THIS_MODULE);
	do_disable_cleanup();
}

static void do_disable_work(struct work_struct *work)
{
	do_disable_cleanup();
}

static void disable_blocking(void)
{
	do_disable();
}

static int kblocker_setattr_check(struct inode *inode, struct iattr *attr)
{
	int i;

	if (READ_ONCE(kblocker_bypass_protection))
		return 0;
	for (i = 0; i < num_protected_files; i++) {
		if (protected_files[i].exists &&
		    protected_files[i].inode == inode)
			return -EPERM;
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static int kblocker_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			   struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int ret = kblocker_setattr_check(inode, attr);
	int i;

	if (ret)
		return ret;
	for (i = 0; i < num_protected_files; i++) {
		if (protected_files[i].exists &&
		    protected_files[i].inode == inode)
			return protected_files[i].orig_i_op->setattr(
				idmap, dentry, attr);
	}
	return -EPERM;
}
#else
static int kblocker_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int ret = kblocker_setattr_check(inode, attr);
	int i;

	if (ret)
		return ret;
	for (i = 0; i < num_protected_files; i++) {
		if (protected_files[i].exists &&
		    protected_files[i].inode == inode)
			return protected_files[i].orig_i_op->setattr(
				dentry, attr);
	}
	return -EPERM;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static int kblocker_permission(struct mnt_idmap *idmap, struct inode *inode,
			      int mask)
#else
static int kblocker_permission(struct inode *inode, int mask)
#endif
{
	int i;

	if ((mask & MAY_WRITE) && !READ_ONCE(kblocker_bypass_protection)) {
		for (i = 0; i < num_protected_files; i++) {
			if (protected_files[i].exists &&
			    protected_files[i].inode == inode)
				return -EPERM;
		}
	}
	for (i = 0; i < num_protected_files; i++) {
		if (protected_files[i].exists &&
		    protected_files[i].inode == inode) {
			if (protected_files[i].orig_i_op->permission) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
				return protected_files[i].orig_i_op->permission(
					idmap, inode, mask);
#else
				return protected_files[i].orig_i_op->permission(
					inode, mask);
#endif
			}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
			return generic_permission(idmap, inode, mask);
#else
			return generic_permission(inode, mask);
#endif
		}
	}
	return 0;
}

static void install_iop_overrides(struct inode *inode,
				  const struct inode_operations *orig,
				  struct inode_operations **custom_out)
{
	struct inode_operations *custom;

	custom = kmemdup(orig, sizeof(*custom), GFP_KERNEL);
	if (!custom)
		return;

	custom->setattr = kblocker_setattr;
	custom->permission = kblocker_permission;

	*custom_out = custom;
	WRITE_ONCE(*(const struct inode_operations **)&inode->i_op, custom);
}

static void restore_iop_overrides(struct inode *inode,
				  const struct inode_operations *orig)
{
	WRITE_ONCE(*(const struct inode_operations **)&inode->i_op, orig);
}

static void protect_file(const char *path)
{
	struct path kp;
	struct inode *inode;
	int error;
	int i;

	if (READ_ONCE(kblocker_bypass_protection))
		return;

	error = kern_path(path, 0, &kp);
	if (error)
		return;

	inode = d_inode(kp.dentry);
	if (!inode)
		goto put;

	inode_lock(inode);
	for (i = 0; i < num_protected_files; i++) {
		if (!protected_files[i].exists)
			continue;
		if (protected_files[i].inode == inode) {
			/* Same inode — just check immutable + i_op */
			if (inode->i_op != protected_files[i].custom_i_op &&
			    protected_files[i].custom_i_op) {
				restore_iop_overrides(inode,
					protected_files[i].orig_i_op);
				install_iop_overrides(inode,
					protected_files[i].orig_i_op,
					&protected_files[i].custom_i_op);
			}
			break;
		}
		/* Path resolves to a different inode — inode was evicted and recreated.
		 * Release the old reference, take a new one, re-install protection. */
		if (protected_files[i].path[0] &&
		    strcmp(protected_files[i].path, path) == 0) {
			iput(protected_files[i].inode);
			ihold(inode);
			protected_files[i].inode = inode;
			protected_files[i].orig_i_op = inode->i_op;
			if (protected_files[i].custom_i_op) {
				kfree(protected_files[i].custom_i_op);
				protected_files[i].custom_i_op = NULL;
			}
			install_iop_overrides(inode, inode->i_op,
				&protected_files[i].custom_i_op);
			printk(KERN_WARNING "kblocker: re-protected %s (inode changed)\n",
			       path);
			break;
		}
	}
	if (!(inode->i_flags & S_IMMUTABLE)) {
		inode_set_flags(inode, S_IMMUTABLE, S_IMMUTABLE);
		printk(KERN_WARNING "kblocker: re-applied immutable flag on %s\n",
		       path);
	}
	inode_unlock(inode);

put:
	path_put(&kp);
}

static void do_protect_work(struct work_struct *work)
{
	int i;

	for (i = 0; i < num_protected_files; i++) {
		if (protected_files[i].exists)
			protect_file(protected_files[i].path);
	}

	if (!READ_ONCE(allow_unload))
		mod_timer(&protect_timer,
			  jiffies + msecs_to_jiffies(PROTECT_INTERVAL_MS));
}

static void protect_callback(struct timer_list *t)
{
	schedule_work(&kb_protect_work);
}

static void add_protected_file(const char *path)
{
	struct path kp;
	int error;

	if (num_protected_files >= MAX_PROTECTED_PATHS)
		return;

	strscpy(protected_files[num_protected_files].path, path,
		sizeof(protected_files[num_protected_files].path));

	error = kern_path(path, 0, &kp);
	if (error) {
		protected_files[num_protected_files].exists = false;
		protected_files[num_protected_files].inode = NULL;
		protected_files[num_protected_files].orig_i_op = NULL;
		protected_files[num_protected_files].custom_i_op = NULL;
		printk(KERN_WARNING "kblocker: cannot find %s, skipping\n", path);
	} else {
		struct inode *inode = d_inode(kp.dentry);
		if (inode) {
			inode_lock(inode);
			if (!(inode->i_flags & S_IMMUTABLE)) {
				inode_set_flags(inode, S_IMMUTABLE, S_IMMUTABLE);
				printk(KERN_INFO "kblocker: immutable %s\n", path);
			}
			ihold(inode);
			protected_files[num_protected_files].inode = inode;
			protected_files[num_protected_files].orig_i_op = inode->i_op;
			protected_files[num_protected_files].custom_i_op = NULL;
			install_iop_overrides(inode, inode->i_op,
				&protected_files[num_protected_files].custom_i_op);
			inode_unlock(inode);
		}
		path_put(&kp);
		protected_files[num_protected_files].exists = true;
	}
	num_protected_files++;
}

static int setup_file_protection(void)
{
	num_protected_files = 0;

	snprintf(ko_path, sizeof(ko_path),
		 "/lib/modules/%s/extra/kblocker.ko", utsname()->release);
	add_protected_file(ko_path);
	add_protected_file("/etc/modules-load.d/kblocker.conf");
	add_protected_file("/etc/hosts");

	timer_setup(&protect_timer, protect_callback, 0);
	mod_timer(&protect_timer,
		  jiffies + msecs_to_jiffies(PROTECT_INTERVAL_MS));
	timer_active = true;

	return 0;
}

static void cleanup_file_protection(void)
{
	int i;

	if (timer_active) {
		timer_delete_sync(&protect_timer);
		timer_active = false;
	}
	cancel_work_sync(&kb_protect_work);

	WRITE_ONCE(kblocker_bypass_protection, true);

	if (!READ_ONCE(allow_unload)) {
		WRITE_ONCE(kblocker_bypass_protection, false);
		return;
	}

	for (i = 0; i < num_protected_files; i++) {
		if (!protected_files[i].exists)
			goto cleanup_iop;

		if (protected_files[i].inode) {
			struct inode *inode = protected_files[i].inode;

			inode_lock(inode);
			if (inode->i_flags & S_IMMUTABLE) {
				inode_set_flags(inode, 0, S_IMMUTABLE);
				printk(KERN_INFO "kblocker: removed immutable %s\n",
				       protected_files[i].path);
			}
			inode_unlock(inode);
		}
cleanup_iop:
		if (protected_files[i].inode && protected_files[i].custom_i_op) {
			inode_lock(protected_files[i].inode);
			restore_iop_overrides(protected_files[i].inode,
					      protected_files[i].orig_i_op);
			inode_unlock(protected_files[i].inode);
			kfree(protected_files[i].custom_i_op);
			protected_files[i].custom_i_op = NULL;
		}
		if (protected_files[i].inode) {
			iput(protected_files[i].inode);
			protected_files[i].inode = NULL;
		}
	}
	WRITE_ONCE(kblocker_bypass_protection, false);
}

static u64 remaining_seconds(void)
{
	u64 exp;

	if (!READ_ONCE(enabled))
		return 0;

	exp = READ_ONCE(expiry_seconds);
	if (!exp || ktime_get_real_seconds() >= exp)
		return 0;

	return exp - ktime_get_real_seconds();
}

static ssize_t status_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	u64 rem = remaining_seconds();

	return sprintf(buf, "enabled: %d\nblocked_ips_v4: %d\n"
		       "blocked_ips_v6: %d\nblocked_domains: %d\nblock_count: %d\n"
		       "remaining: %llu\n"
		       "allow_unload: %d\nprotected_files: %d\n"
		       "state_restored: %d\n",
		       READ_ONCE(enabled), READ_ONCE(blocked_count_v4),
		       READ_ONCE(blocked_count_v6),
		       READ_ONCE(blocked_domain_count),
		       READ_ONCE(blocked_count_v4) + READ_ONCE(blocked_count_v6),
		       rem, READ_ONCE(allow_unload),
		       num_protected_files, READ_ONCE(state_restored));
}

static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	return sprintf(buf, "%d %llu\n", READ_ONCE(enabled), remaining_seconds());
}

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned long val;
	char *end;

	val = simple_strtoul(buf, &end, 0);

	if (end == buf)
		return -EINVAL;

	if (val == 0) {
		if (READ_ONCE(pgp_active)) {
			if (READ_ONCE(enabled))
				return -EPERM;
			clear_hosts_from_kernel();
			printk(KERN_INFO "kblocker: cleaned hosts (pgp_active, already disabled)\n");
			return count;
		}
		disable_blocking();
	} else if (READ_ONCE(pgp_active) && READ_ONCE(enabled)) {
		return -EPERM;
	} else {
		enable_blocking((unsigned int)val);
	}

	return count;
}

static ssize_t remaining_show(struct kobject *kobj, struct kobj_attribute *attr,
			      char *buf)
{
	return sprintf(buf, "%llu\n", remaining_seconds());
}

static ssize_t blocked_ips_show(struct kobject *kobj, struct kobj_attribute *attr,
				char *buf)
{
	int i, len = 0;
	spin_lock_bh(&ip_list_lock);
	for (i = 0; i < blocked_count_v4 && len < PAGE_SIZE - 50; i++) {
		__be32 addr = blocked_ips_v4[i];
		len += sprintf(buf + len, "%pI4\n", &addr);
	}
	for (i = 0; i < blocked_count_v6 && len < PAGE_SIZE - 50; i++) {
		len += sprintf(buf + len, "%pI6\n", &blocked_ips_v6[i]);
	}
	spin_unlock_bh(&ip_list_lock);
	return len;
}

static ssize_t blocked_ips_store(struct kobject *kobj, struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	char *copy, *orig_copy, *token;
	__be32 *tmp_v4;
	struct in6_addr *tmp_v6;
	int n4 = 0, n6 = 0;

	if (READ_ONCE(enabled))
		return -EPERM;

	tmp_v4 = kmalloc_array(MAX_IPS_V4, sizeof(__be32), GFP_KERNEL);
	tmp_v6 = kmalloc_array(MAX_IPS_V6, sizeof(struct in6_addr), GFP_KERNEL);
	if (!tmp_v4 || !tmp_v6) {
		kfree(tmp_v4);
		kfree(tmp_v6);
		return -ENOMEM;
	}

	copy = kmemdup(buf, count + 1, GFP_KERNEL);
	if (!copy) {
		kfree(tmp_v4);
		kfree(tmp_v6);
		return -ENOMEM;
	}
	orig_copy = copy;
	copy[count] = '\0';

	while ((token = strsep(&copy, "\n"))) {
		__be32 addr4;
		struct in6_addr addr6;

		if (token[0] == '\0' || token[0] == '#') continue;

		if (in6_pton(token, -1, (u8 *)&addr6, '\0', NULL)) {
			if (n6 < MAX_IPS_V6)
				tmp_v6[n6++] = addr6;
		} else if (in4_pton(token, -1, (u8 *)&addr4, '\0', NULL)) {
			if (n4 < MAX_IPS_V4)
				tmp_v4[n4++] = addr4;
		}
	}

	spin_lock_bh(&ip_list_lock);
	memcpy(blocked_ips_v4, tmp_v4, n4 * sizeof(__be32));
	memcpy(blocked_ips_v6, tmp_v6, n6 * sizeof(struct in6_addr));
	WRITE_ONCE(blocked_count_v4, n4);
	WRITE_ONCE(blocked_count_v6, n6);
	spin_unlock_bh(&ip_list_lock);

	kfree(tmp_v4);
	kfree(tmp_v6);
	kfree(orig_copy);
	return count;
}

static ssize_t blocked_domains_show(struct kobject *kobj, struct kobj_attribute *attr,
				    char *buf)
{
	int i, len = 0;
	spin_lock_bh(&ip_list_lock);
	for (i = 0; i < blocked_domain_count && len < PAGE_SIZE - MAX_DOMAIN_LEN; i++) {
		len += sprintf(buf + len, "%s\n", blocked_domains[i]);
	}
	spin_unlock_bh(&ip_list_lock);
	return len;
}

static ssize_t blocked_domains_store(struct kobject *kobj, struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	char *copy, *orig, *token;

	if (READ_ONCE(enabled))
		return -EPERM;

	copy = kmemdup(buf, count + 1, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	orig = copy;
	copy[count] = '\0';

	spin_lock_bh(&ip_list_lock);
	{
		int nd = 0;
		while ((token = strsep(&copy, "\n")) && nd < MAX_DOMAINS) {
			int len;

			if (token[0] == '\0' || token[0] == '#')
				continue;
			len = strlen(token);
			if (len >= MAX_DOMAIN_LEN) {
				spin_unlock_bh(&ip_list_lock);
				kfree(orig);
				return -EINVAL;
			}
			memcpy(blocked_domains[nd], token, len);
			blocked_domains[nd][len] = '\0';
			nd++;
		}
		blocked_domain_count = nd;
	}
	spin_unlock_bh(&ip_list_lock);

	kfree(orig);
	return count;
}

static ssize_t block_count_show(struct kobject *kobj, struct kobj_attribute *attr,
				char *buf)
{
	int n4, n6;

	spin_lock_bh(&ip_list_lock);
	n4 = blocked_count_v4;
	n6 = blocked_count_v6;
	spin_unlock_bh(&ip_list_lock);

	return sprintf(buf, "%d\n", n4 + n6);
}

static int hex_val(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

static int hex_decode(const char *s, u8 *out, int count)
{
	int i;
	for (i = 0; i < count; i++) {
		int hi = hex_val(s[i * 2]);
		int lo = hex_val(s[i * 2 + 1]);
		if (hi < 0 || lo < 0) return -1;
		out[i] = (hi << 4) | lo;
	}
	return 0;
}

static ssize_t unblock_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	u8 input_hash[32], parsed[16];
	struct crypto_shash *tfm;

	if (count < 32) return -EINVAL;
	if (buf[count - 1] == '\n') count--;
	if (count != 32) return -EINVAL;
	if (hex_decode(buf, parsed, 16)) return -EINVAL;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return -ENOMEM;

	SHASH_DESC_ON_STACK(desc, tfm);
	desc->tfm = tfm;

	if (!crypto_shash_digest(desc, parsed, 16, input_hash)) {
		if (ct_memcmp_eq(input_hash, key_hash, 32)) {
			WRITE_ONCE(allow_unload, true);
			WRITE_ONCE(enabled, false);
			if (atomic_xchg(&ref_taken, 0)) {
				module_put(THIS_MODULE);
			}
			memzero_explicit(unload_key, 16);
			memzero_explicit(key_hash, 32);
			WRITE_ONCE(state_restored, false);
			printk(KERN_INFO "kblocker: unload authorized, auto-disabled\n");
			crypto_free_shash(tfm);
			clear_hosts_from_kernel();
			return count;
		}
	}

	crypto_free_shash(tfm);
	printk(KERN_WARNING "kblocker: invalid unload key attempt\n");
	return -EPERM;
}

static ssize_t unload_key_show(struct kobject *kobj, struct kobj_attribute *attr,
			       char *buf)
{
	if (READ_ONCE(state_restored))
		return sprintf(buf, "restored\n");

	if (READ_ONCE(pgp_active))
		return sprintf(buf, "encrypted\n");

	char *p = buf;
	int i;
	for (i = 0; i < 16; i++)
		p += sprintf(p, "%02x", unload_key[i]);
	p += sprintf(p, "\n");
	return p - buf;
}

static void do_restore(const u8 *hash, u64 expiry_ts)
{
	if (expiry_ts <= ktime_get_real_seconds()) {
		printk(KERN_INFO "kblocker: restore skipped (already expired)\n");
		return;
	}

	memcpy(key_hash, hash, 32);
	WRITE_ONCE(state_restored, true);
	WRITE_ONCE(allow_unload, false);

	u64 delta = expiry_ts - ktime_get_real_seconds();
	expiry_seconds = expiry_ts;
	expiry_jiffies = jiffies + msecs_to_jiffies(delta * 1000);

	WRITE_ONCE(enabled, true);
	if (!atomic_xchg(&ref_taken, 1))
		__module_get(THIS_MODULE);
	mod_timer(&enable_timer, jiffies + HZ);
	WRITE_ONCE(enable_timer_active, true);
	update_hosts_file();

	printk(KERN_INFO "kblocker: state restored, %llu seconds remaining\n", delta);
}

static void try_restore_state_from_disk(void)
{
	struct file *file;
	char *buf;
	loff_t len;
	u8 hash[32];
	u64 expiry;
	char *p, *end;

	file = filp_open(STATE_FILE, O_RDONLY, 0);
	if (IS_ERR(file))
		return;

	buf = hosts_read_all(file, &len);
	if (!buf) {
		filp_close(file, NULL);
		return;
	}

	p = strstr(buf, "domains:");
	if (p) {
		p += 8;
		end = strchr(p, '\n');
		if (end && end > p) {
			char *copy = kstrdup(p, GFP_KERNEL);
			if (copy) {
				char *token, *orig = copy;
				int nd = 0;
				copy[end - p] = '\0';
				spin_lock_bh(&ip_list_lock);
				while ((token = strsep(&copy, ",")) && nd < MAX_DOMAINS) {
					int dlen = strlen(token);
					if (dlen > 0 && dlen < MAX_DOMAIN_LEN) {
						memcpy(blocked_domains[nd], token, dlen);
						blocked_domains[nd][dlen] = '\0';
						nd++;
					}
				}
				blocked_domain_count = nd;
				spin_unlock_bh(&ip_list_lock);
				kfree(orig);
			}
		}
	}

	p = strstr(buf, "blocked_ips:");
	if (p) {
		p += 12;
		end = strchr(p, '\n');
		if (end && end > p) {
			char *copy = kstrdup(p, GFP_KERNEL);
			if (copy) {
				char *token, *orig = copy;
				__be32 *tmp_v4 = kmalloc_array(MAX_IPS_V4, sizeof(__be32), GFP_KERNEL);
				struct in6_addr *tmp_v6 = kmalloc_array(MAX_IPS_V6, sizeof(struct in6_addr), GFP_KERNEL);
				int n4 = 0, n6 = 0;

				copy[end - p] = '\0';
				if (tmp_v4 && tmp_v6) {
					while ((token = strsep(&copy, ","))) {
						__be32 addr4;
						struct in6_addr addr6;
						if (token[0] == '\0') continue;
						if (in6_pton(token, -1, (u8 *)&addr6, '\0', NULL)) {
							if (n6 < MAX_IPS_V6) tmp_v6[n6++] = addr6;
						} else if (in4_pton(token, -1, (u8 *)&addr4, '\0', NULL)) {
							if (n4 < MAX_IPS_V4) tmp_v4[n4++] = addr4;
						}
					}
					spin_lock_bh(&ip_list_lock);
					memcpy(blocked_ips_v4, tmp_v4, n4 * sizeof(__be32));
					memcpy(blocked_ips_v6, tmp_v6, n6 * sizeof(struct in6_addr));
					WRITE_ONCE(blocked_count_v4, n4);
					WRITE_ONCE(blocked_count_v6, n6);
					spin_unlock_bh(&ip_list_lock);
				}
				kfree(tmp_v4);
				kfree(tmp_v6);
				kfree(orig);
			}
		}
	}

	p = strstr(buf, "key_hash:");
	if (p) {
		p += 9;
		end = strchr(p, '\n');
		if (end && (end - p) == 64 && !hex_decode(p, hash, 32)) {
			p = strstr(buf, "expiry:");
			if (p) {
				p += 7;
				expiry = simple_strtoull(p, &end, 0);
				if (end != p) {
					do_restore(hash, expiry);
				}
			}
		}
	}

	p = strstr(buf, "pgp_active:");
	if (p && READ_ONCE(state_restored)) {
		p += 11;
		if (*p == '1') {
			WRITE_ONCE(pgp_active, true);
			memzero_explicit(unload_key, sizeof(unload_key));
			printk(KERN_DEBUG "kblocker: PGP mode restored from disk\n");
		}
	}

	kfree(buf);
	filp_close(file, NULL);
}

static ssize_t restore_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	u8 parsed_hash[32];
	u64 parsed_expiry;
	char *endpot;
	int i;
	const char *delim;

	if (count < 66) return -EINVAL;
	delim = memchr(buf, ':', count);
	if (!delim) return -EINVAL;
	i = delim - buf;
	if (i != 64) return -EINVAL;

	if (hex_decode(buf, parsed_hash, 32)) return -EINVAL;

	parsed_expiry = simple_strtoull(delim + 1, &endpot, 0);
	if (endpot == delim + 1) return -EINVAL;

	do_restore(parsed_hash, parsed_expiry);
	return count;
}

static ssize_t pgp_active_show(struct kobject *kobj, struct kobj_attribute *attr,
			       char *buf)
{
	return sprintf(buf, "%d\n", READ_ONCE(pgp_active));
}

static ssize_t pgp_active_store(struct kobject *kobj, struct kobj_attribute *attr,
			        const char *buf, size_t count)
{
	unsigned long val;
	char *end;

	val = simple_strtoul(buf, &end, 0);
	if (end == buf)
		return -EINVAL;

	if (val) {
		if (!READ_ONCE(pgp_active)) {
			WRITE_ONCE(pgp_active, true);
			memzero_explicit(unload_key, sizeof(unload_key));
			WRITE_ONCE(state_restored, false);
			printk(KERN_INFO "kblocker: PGP mode active, key erased from memory\n");
		}
	} else {
		WRITE_ONCE(pgp_active, false);
		printk(KERN_INFO "kblocker: PGP mode deactivated\n");
	}

	return count;
}

static ssize_t disable_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	if (!READ_ONCE(pgp_active)) {
		disable_blocking();
		return count;
	}

	u8 input_hash[32], parsed[16];
	struct crypto_shash *tfm;

	if (count < 32) return -EINVAL;
	if (buf[count - 1] == '\n') count--;
	if (count != 32) return -EINVAL;
	if (hex_decode(buf, parsed, 16)) return -EINVAL;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return -ENOMEM;

	SHASH_DESC_ON_STACK(desc, tfm);
	desc->tfm = tfm;

	if (!crypto_shash_digest(desc, parsed, 16, input_hash)) {
		if (ct_memcmp_eq(input_hash, key_hash, 32)) {
			crypto_free_shash(tfm);
			generate_unload_key();
			WRITE_ONCE(pgp_active, false);
			WRITE_ONCE(state_restored, false);
			disable_blocking();
			printk(KERN_INFO "kblocker: authorized disable, new key generated\n");
			return count;
		}
	}

	crypto_free_shash(tfm);
	printk(KERN_WARNING "kblocker: invalid disable key attempt\n");
	return -EPERM;
}

static void generate_unload_key(void)
{
	struct crypto_shash *tfm;
	SHASH_DESC_ON_STACK(desc, tfm);

	get_random_bytes(unload_key, sizeof(unload_key));

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (!IS_ERR(tfm)) {
		desc->tfm = tfm;
		if (crypto_shash_digest(desc, unload_key, 16, key_hash))
			get_random_bytes(key_hash, sizeof(key_hash));
		crypto_free_shash(tfm);
	} else {
		get_random_bytes(key_hash, sizeof(key_hash));
	}
}

static ssize_t update_hosts_store(struct kobject *kobj, struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	int ret = update_hosts_file();
	if (ret)
		printk(KERN_ERR "kblocker: update_hosts failed: %d\n", ret);
	return count;
}

static struct kobj_attribute status_attr = __ATTR_RO(status);
static struct kobj_attribute enabled_attr = __ATTR_RW(enabled);
static struct kobj_attribute remaining_attr = __ATTR_RO(remaining);
static struct kobj_attribute blocked_ips_attr = __ATTR_RW(blocked_ips);
static struct kobj_attribute blocked_domains_attr = __ATTR_RW(blocked_domains);
static struct kobj_attribute block_count_attr = __ATTR_RO(block_count);
static struct kobj_attribute unblock_attr = __ATTR_WO(unblock);
static struct kobj_attribute key_attr = __ATTR(key, 0400, unload_key_show, NULL);
static struct kobj_attribute restore_attr = __ATTR_WO(restore);
static struct kobj_attribute pgp_active_attr = __ATTR_RW(pgp_active);
static struct kobj_attribute disable_attr = __ATTR_WO(disable);
static struct kobj_attribute update_hosts_attr = __ATTR_WO(update_hosts);

static struct attribute *attrs[] = {
	&status_attr.attr,
	&enabled_attr.attr,
	&remaining_attr.attr,
	&blocked_ips_attr.attr,
	&blocked_domains_attr.attr,
	&block_count_attr.attr,
	&unblock_attr.attr,
	&key_attr.attr,
	&restore_attr.attr,
	&pgp_active_attr.attr,
	&disable_attr.attr,
	&update_hosts_attr.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static void kblocker_cleanup_netfilter(void)
{
	if (forward_registered) {
		nf_unregister_net_hook(&init_net, &nfho_forward);
		forward_registered = false;
	}
	if (ipv4_registered) {
		nf_unregister_net_hook(&init_net, &nfho_out);
		ipv4_registered = false;
	}
}

static void __exit kblocker_exit(void)
{
	if (READ_ONCE(enabled) && !READ_ONCE(allow_unload)) {
		panic("kblocker: FORCED UNLOAD DETECTED while enabled. System halted.");
	}

	if (READ_ONCE(enable_timer_active)) {
		timer_delete_sync(&enable_timer);
		WRITE_ONCE(enable_timer_active, false);
	}
	cancel_work_sync(&kb_disable_work);
	cancel_work_sync(&kb_protect_work);

	WRITE_ONCE(allow_unload, true);
	cleanup_file_protection();
	kblocker_cleanup_netfilter();

	if (kblocker_kobj) {
		sysfs_remove_group(kblocker_kobj, &attr_group);
		kobject_put(kblocker_kobj);
	}

	memzero_explicit(unload_key, sizeof(unload_key));
	memzero_explicit(key_hash, sizeof(key_hash));
	kfree(blocked_ips_v4);
	kfree(blocked_ips_v6);
	printk(KERN_INFO "kblocker: cleanly unloaded\n");
}

static int __init kblocker_init(void)
{
	int ret;

	enabled = false;
	expiry_jiffies = 0;
	expiry_seconds = 0;
	WRITE_ONCE(state_restored, false);

	INIT_WORK(&kb_disable_work, do_disable_work);
	INIT_WORK(&kb_protect_work, do_protect_work);

	blocked_ips_v4 = kmalloc_array(MAX_IPS_V4, sizeof(__be32), GFP_KERNEL);
	if (!blocked_ips_v4) return -ENOMEM;
	blocked_ips_v6 = kmalloc_array(MAX_IPS_V6, sizeof(struct in6_addr), GFP_KERNEL);
	if (!blocked_ips_v6) {
		kfree(blocked_ips_v4);
		return -ENOMEM;
	}
	blocked_count_v4 = 0;
	blocked_count_v6 = 0;

	kblocker_kobj = kobject_create_and_add("kblocker", kernel_kobj);
	if (!kblocker_kobj) {
		kfree(blocked_ips_v4);
		kfree(blocked_ips_v6);
		return -ENOMEM;
	}

	ret = sysfs_create_group(kblocker_kobj, &attr_group);
	if (ret) {
		kobject_put(kblocker_kobj);
		kfree(blocked_ips_v4);
		kfree(blocked_ips_v6);
		return ret;
	}

	nfho_out.hook = kblocker_hook;
	nfho_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_out.pf = NFPROTO_INET;
	nfho_out.priority = NF_IP_PRI_FILTER;

	ret = nf_register_net_hook(&init_net, &nfho_out);
	if (ret) {
		printk(KERN_ERR "kblocker: failed to register LOCAL_OUT hook\n");
		goto err;
	}
	ipv4_registered = true;

	nfho_forward.hook = kblocker_hook;
	nfho_forward.hooknum = NF_INET_FORWARD;
	nfho_forward.pf = NFPROTO_INET;
	nfho_forward.priority = NF_IP_PRI_FILTER;

	ret = nf_register_net_hook(&init_net, &nfho_forward);
	if (ret)
		printk(KERN_WARNING "kblocker: FORWARD hook failed (non-fatal)\n");
	else
		forward_registered = true;

	timer_setup(&enable_timer, enable_timer_cb, 0);

	ret = setup_file_protection();
	if (ret)
		printk(KERN_WARNING "kblocker: file protection init failed\n");

	try_restore_state_from_disk();

	if (!READ_ONCE(state_restored)) {
		get_random_bytes(unload_key, sizeof(unload_key));
		{
			struct crypto_shash *tfm = crypto_alloc_shash("sha256", 0, 0);
			if (!IS_ERR(tfm)) {
				SHASH_DESC_ON_STACK(desc, tfm);
				desc->tfm = tfm;
				if (crypto_shash_digest(desc, unload_key, 16, key_hash))
					get_random_bytes(key_hash, sizeof(key_hash));
				crypto_free_shash(tfm);
			} else {
				get_random_bytes(key_hash, sizeof(key_hash));
			}
		}
	}

	printk(KERN_INFO "kblocker: loaded (disabled by default)\n");
	return 0;

err:
	kblocker_cleanup_netfilter();
	sysfs_remove_group(kblocker_kobj, &attr_group);
	kobject_put(kblocker_kobj);
	kfree(blocked_ips_v4);
	kfree(blocked_ips_v6);
	return ret;
}

module_init(kblocker_init);
module_exit(kblocker_exit);