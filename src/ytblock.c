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
#include <crypto/hash.h>
#include <net/ipv6.h>
#include <net/tcp.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("ytblock");
MODULE_DESCRIPTION("Self-discipline internet blocker - disabled by default, time-limited enable");
MODULE_VERSION("2.0");

#define MAX_IPS_V4 4096
#define MAX_IPS_V6 1024
#define PROTECT_INTERVAL_MS 10000
#define MAX_PROTECTED_PATHS 8
#define MAX_DOMAINS 64
#define MAX_DOMAIN_LEN 256

static __be32 *blocked_ips_v4;
static int blocked_count_v4;
static struct in6_addr *blocked_ips_v6;
static int blocked_count_v6;
static char blocked_domains[MAX_DOMAINS][MAX_DOMAIN_LEN];
static int blocked_domain_count;
static DEFINE_MUTEX(ip_list_mutex);

static bool allow_unload;
static u8 unload_key[16];
static u8 key_hash[32];
static bool state_restored;
static struct kobject *ytblock_kobj;
static struct nf_hook_ops nfho_out;
static struct nf_hook_ops nfho_out6;
static struct nf_hook_ops nfho_forward;
static bool ipv6_registered;
static bool ipv4_registered;
static bool forward_registered;

static char ko_path[256];
static struct protected_file {
	char path[256];
	bool exists;
} protected_files[MAX_PROTECTED_PATHS];
static int num_protected_files;
static struct timer_list protect_timer;
static bool timer_active;

static bool enabled;
static u64 expiry_seconds;
static unsigned long expiry_jiffies;
static struct timer_list enable_timer;
static bool enable_timer_active;
static bool ref_taken;

static bool is_ip_blocked(__be32 addr)
{
	int i;
	bool found = false;

	mutex_lock(&ip_list_mutex);
	for (i = 0; i < blocked_count_v4; i++) {
		if (blocked_ips_v4[i] == addr) {
			found = true;
			break;
		}
	}
	mutex_unlock(&ip_list_mutex);

	return found;
}

#if IS_ENABLED(CONFIG_IPV6)
static bool is_ipv6_blocked(struct in6_addr *addr)
{
	int i;
	bool found = false;

	mutex_lock(&ip_list_mutex);
	for (i = 0; i < blocked_count_v6; i++) {
		if (ipv6_addr_equal(&blocked_ips_v6[i], addr)) {
			found = true;
			break;
		}
	}
	mutex_unlock(&ip_list_mutex);

	return found;
}
#endif

static bool domain_list_contains(const char *hostname)
{
	int i;
	if (!READ_ONCE(blocked_domain_count))
		return false;
	for (i = 0; i < blocked_domain_count; i++) {
		const char *blocked = blocked_domains[i];
		int blen = strlen(blocked);
		const char *p = hostname;
		while (*p) {
			if (strncasecmp(p, blocked, blen) == 0)
				return true;
			p++;
		}
	}
	return false;
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
static unsigned int ytblock_hook_out(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
#else
static unsigned int ytblock_hook_out(unsigned int hooknum, struct sk_buff *skb,
				     const struct net_device *in, const struct net_device *out,
				     int (*okfn)(struct sk_buff *))
#endif
{
	struct iphdr *iph;
	struct tcphdr *tcph;

	if (!READ_ONCE(enabled)) return NF_ACCEPT;
	if (!skb) return NF_ACCEPT;

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

static unsigned int ytblock_hook_forward(void *priv, struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	return ytblock_hook_out(priv, skb, state);
}

#if IS_ENABLED(CONFIG_IPV6)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
static unsigned int ytblock_hook_out6(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
#else
static unsigned int ytblock_hook_out6(unsigned int hooknum, struct sk_buff *skb,
				     const struct net_device *in, const struct net_device *out,
				     int (*okfn)(struct sk_buff *))
#endif
{
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;

	if (!READ_ONCE(enabled)) return NF_ACCEPT;
	if (!skb) return NF_ACCEPT;

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
		if (ip6h->nexthdr == IPPROTO_UDP) {
			if (pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct udphdr))) {
				ip6h = ipv6_hdr(skb);
				struct udphdr *udph = (struct udphdr *)((u8 *)ip6h + sizeof(struct ipv6hdr));
				if (udph->dest == htons(443)) {
					return NF_DROP;
				}
			}
			return NF_ACCEPT;
		}
		if (ip6h->nexthdr != IPPROTO_TCP)
			return NF_ACCEPT;
		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct tcphdr)))
			return NF_ACCEPT;
		ip6h = ipv6_hdr(skb);
		tcph = (struct tcphdr *)((u8 *)ip6h + sizeof(struct ipv6hdr));
		if (tcph->syn || !tcph->ack || tcph->rst)
			return NF_ACCEPT;
		int tcp_data_off = sizeof(struct ipv6hdr) + (tcph->doff * 4);
		int sni_pull = tcp_data_off + 512;
		if (sni_pull > skb->len)
			sni_pull = skb->len;
		if (!pskb_may_pull(skb, sni_pull))
			return NF_ACCEPT;
		ip6h = ipv6_hdr(skb);
		tcph = (struct tcphdr *)((u8 *)ip6h + sizeof(struct ipv6hdr));
		if (sni_matches_blocked(skb, tcph)) {
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}
#endif

static void enable_timer_cb(struct timer_list *t)
{
	if (!READ_ONCE(enabled))
		return;

	if (ktime_get_real_seconds() >= expiry_seconds) {
		WRITE_ONCE(enabled, false);
		printk(KERN_INFO "ytblock: auto-disabled (timer expired)\n");
		return;
	}

	mod_timer(&enable_timer, jiffies + HZ);
}

static void enable_blocking(unsigned int seconds)
{
	WRITE_ONCE(enabled, true);
	expiry_seconds = ktime_get_real_seconds() + seconds;
	expiry_jiffies = jiffies + msecs_to_jiffies(seconds * 1000);
	mod_timer(&enable_timer, jiffies + HZ);
	enable_timer_active = true;
	state_restored = false;
	if (!ref_taken) {
		__module_get(THIS_MODULE);
		ref_taken = true;
	}
	printk(KERN_INFO "ytblock: enabled for %u seconds\n", seconds);
}

static void disable_blocking(void)
{
	if (enable_timer_active) {
		timer_delete_sync(&enable_timer);
		enable_timer_active = false;
	}
	WRITE_ONCE(enabled, false);
	expiry_jiffies = 0;
	expiry_seconds = 0;
	state_restored = false;
	if (ref_taken) {
		module_put(THIS_MODULE);
		ref_taken = false;
	}
	printk(KERN_INFO "ytblock: disabled\n");
}

static void protect_file(const char *path)
{
	struct path kp;
	struct inode *inode;
	int error;

	error = kern_path(path, 0, &kp);
	if (error)
		return;

	inode = d_inode(kp.dentry);
	if (!inode)
		goto put;

	inode_lock(inode);
	if (!(inode->i_flags & S_IMMUTABLE)) {
		inode_set_flags(inode, S_IMMUTABLE, S_IMMUTABLE);
		printk(KERN_WARNING "ytblock: re-applied immutable flag on %s\n",
		       path);
	}
	inode_unlock(inode);

put:
	path_put(&kp);
}

static void protect_callback(struct timer_list *t)
{
	int i;

	for (i = 0; i < num_protected_files; i++) {
		if (protected_files[i].exists)
			protect_file(protected_files[i].path);
	}

	if (!allow_unload)
		mod_timer(&protect_timer,
			  jiffies + msecs_to_jiffies(PROTECT_INTERVAL_MS));
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
		printk(KERN_WARNING "ytblock: cannot find %s, skipping\n", path);
	} else {
		struct inode *inode = d_inode(kp.dentry);
		if (inode) {
			inode_lock(inode);
			if (!(inode->i_flags & S_IMMUTABLE)) {
				inode_set_flags(inode, S_IMMUTABLE, S_IMMUTABLE);
				printk(KERN_INFO "ytblock: immutable %s\n", path);
			}
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
		 "/lib/modules/%s/extra/ytblock.ko", utsname()->release);
	add_protected_file(ko_path);
	add_protected_file("/etc/modules-load.d/ytblock.conf");

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

	if (!allow_unload)
		return;

	for (i = 0; i < num_protected_files; i++) {
		struct path kp;
		struct inode *inode;
		int error;

		if (!protected_files[i].exists)
			continue;

		error = kern_path(protected_files[i].path, 0, &kp);
		if (error)
			continue;

		inode = d_inode(kp.dentry);
		if (inode) {
			inode_lock(inode);
			if (inode->i_flags & S_IMMUTABLE) {
				inode_set_flags(inode, 0, S_IMMUTABLE);
				printk(KERN_INFO "ytblock: removed immutable %s\n",
				       protected_files[i].path);
			}
			inode_unlock(inode);
		}
		path_put(&kp);
	}
}

static u64 remaining_seconds(void)
{
	if (!READ_ONCE(enabled))
		return 0;

	if (ktime_get_real_seconds() >= expiry_seconds)
		return 0;

	return expiry_seconds - ktime_get_real_seconds();
}

static ssize_t status_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	u64 rem = remaining_seconds();

	return sprintf(buf, "enabled: %d\nblocked_ips_v4: %d\n"
		       "blocked_ips_v6: %d\nblocked_domains: %d\n"
		       "remaining: %llu\n"
		       "allow_unload: %d\nprotected_files: %d\n"
		       "state_restored: %d\n",
		       READ_ONCE(enabled), READ_ONCE(blocked_count_v4),
		       READ_ONCE(blocked_count_v6),
		       READ_ONCE(blocked_domain_count),
		       rem, allow_unload,
		       num_protected_files, state_restored);
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
		disable_blocking();
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
	mutex_lock(&ip_list_mutex);
	for (i = 0; i < blocked_count_v4 && len < PAGE_SIZE - 50; i++) {
		__be32 addr = blocked_ips_v4[i];
		len += sprintf(buf + len, "%pI4\n", &addr);
	}
	for (i = 0; i < blocked_count_v6 && len < PAGE_SIZE - 50; i++) {
		len += sprintf(buf + len, "%pI6\n", &blocked_ips_v6[i]);
	}
	mutex_unlock(&ip_list_mutex);
	return len;
}

static ssize_t blocked_ips_store(struct kobject *kobj, struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	char *copy, *orig_copy, *token;
	__be32 *tmp_v4;
	struct in6_addr *tmp_v6;
	int n4 = 0, n6 = 0;

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

	mutex_lock(&ip_list_mutex);
	memcpy(blocked_ips_v4, tmp_v4, n4 * sizeof(__be32));
	memcpy(blocked_ips_v6, tmp_v6, n6 * sizeof(struct in6_addr));
	WRITE_ONCE(blocked_count_v4, n4);
	WRITE_ONCE(blocked_count_v6, n6);
	mutex_unlock(&ip_list_mutex);

	kfree(tmp_v4);
	kfree(tmp_v6);
	kfree(orig_copy);
	return count;
}

static ssize_t blocked_domains_show(struct kobject *kobj, struct kobj_attribute *attr,
				    char *buf)
{
	int i, len = 0;
	mutex_lock(&ip_list_mutex);
	for (i = 0; i < blocked_domain_count && len < PAGE_SIZE - MAX_DOMAIN_LEN; i++) {
		len += sprintf(buf + len, "%s\n", blocked_domains[i]);
	}
	mutex_unlock(&ip_list_mutex);
	return len;
}

static ssize_t blocked_domains_store(struct kobject *kobj, struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	char *copy, *orig, *token;
	int nd = 0;

	copy = kmemdup(buf, count + 1, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	orig = copy;
	copy[count] = '\0';

	while ((token = strsep(&copy, "\n")) && nd < MAX_DOMAINS) {
		int len;

		if (token[0] == '\0' || token[0] == '#')
			continue;
		len = strlen(token);
		if (len >= MAX_DOMAIN_LEN)
			len = MAX_DOMAIN_LEN - 1;
		memcpy(blocked_domains[nd], token, len);
		blocked_domains[nd][len] = '\0';
		nd++;
	}

	mutex_lock(&ip_list_mutex);
	blocked_domain_count = nd;
	mutex_unlock(&ip_list_mutex);

	kfree(orig);
	return count;
}

static ssize_t block_count_show(struct kobject *kobj, struct kobj_attribute *attr,
				char *buf)
{
	return sprintf(buf, "%d\n", blocked_count_v4 + blocked_count_v6);
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
	if (hex_decode(buf, parsed, 16)) return -EINVAL;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return -ENOMEM;

	SHASH_DESC_ON_STACK(desc, tfm);
	desc->tfm = tfm;

	if (!crypto_shash_digest(desc, parsed, 16, input_hash)) {
		if (memcmp(input_hash, key_hash, 32) == 0) {
			allow_unload = true;
			WRITE_ONCE(enabled, false);
			if (ref_taken) {
				module_put(THIS_MODULE);
				ref_taken = false;
			}
			memzero_explicit(unload_key, 16);
			memzero_explicit(key_hash, 32);
			state_restored = false;
			printk(KERN_INFO "ytblock: unload authorized, auto-disabled\n");
			crypto_free_shash(tfm);
			return count;
		}
	}

	crypto_free_shash(tfm);
	printk(KERN_WARNING "ytblock: invalid unload key attempt\n");
	return -EPERM;
}

static ssize_t unload_key_show(struct kobject *kobj, struct kobj_attribute *attr,
			       char *buf)
{
	if (state_restored)
		return sprintf(buf, "restored\n");

	char *p = buf;
	int i;
	for (i = 0; i < 16; i++)
		p += sprintf(p, "%02x", unload_key[i]);
	p += sprintf(p, "\n");
	return p - buf;
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

	if (parsed_expiry <= ktime_get_real_seconds()) {
		printk(KERN_INFO "ytblock: restore skipped (already expired)\n");
		return count;
	}

	memcpy(key_hash, parsed_hash, 32);
	state_restored = true;
	allow_unload = false;

	u64 delta = parsed_expiry - ktime_get_real_seconds();
	expiry_seconds = parsed_expiry;
	expiry_jiffies = jiffies + msecs_to_jiffies(delta * 1000);

	WRITE_ONCE(enabled, true);
	if (!ref_taken) {
		__module_get(THIS_MODULE);
		ref_taken = true;
	}
	mod_timer(&enable_timer, jiffies + HZ);
	enable_timer_active = true;

	printk(KERN_INFO "ytblock: state restored, %llu seconds remaining\n", delta);
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
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static void ytblock_cleanup_netfilter(void)
{
	if (forward_registered) {
		nf_unregister_net_hook(&init_net, &nfho_forward);
		forward_registered = false;
	}
	if (ipv6_registered) {
#if IS_ENABLED(CONFIG_IPV6)
		nf_unregister_net_hook(&init_net, &nfho_out6);
		ipv6_registered = false;
#endif
	}
	if (ipv4_registered) {
		nf_unregister_net_hook(&init_net, &nfho_out);
		ipv4_registered = false;
	}
}

static void __exit ytblock_exit(void)
{
	if (READ_ONCE(enabled) && !allow_unload) {
		panic("ytblock: FORCED UNLOAD DETECTED while enabled. System halted.");
	}

	if (enable_timer_active) {
		timer_delete_sync(&enable_timer);
		enable_timer_active = false;
	}

	allow_unload = true;
	cleanup_file_protection();
	ytblock_cleanup_netfilter();

	if (ytblock_kobj) {
		sysfs_remove_group(ytblock_kobj, &attr_group);
		kobject_put(ytblock_kobj);
	}

	memzero_explicit(unload_key, sizeof(unload_key));
	memzero_explicit(key_hash, sizeof(key_hash));
	kfree(blocked_ips_v4);
	kfree(blocked_ips_v6);
	printk(KERN_INFO "ytblock: cleanly unloaded\n");
}

static int __init ytblock_init(void)
{
	int ret;

	enabled = false;
	expiry_jiffies = 0;
	expiry_seconds = 0;
	state_restored = false;

	blocked_ips_v4 = kmalloc_array(MAX_IPS_V4, sizeof(__be32), GFP_KERNEL);
	if (!blocked_ips_v4) return -ENOMEM;
	blocked_ips_v6 = kmalloc_array(MAX_IPS_V6, sizeof(struct in6_addr), GFP_KERNEL);
	if (!blocked_ips_v6) {
		kfree(blocked_ips_v4);
		return -ENOMEM;
	}
	blocked_count_v4 = 0;
	blocked_count_v6 = 0;

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

	ytblock_kobj = kobject_create_and_add("ytblock", kernel_kobj);
	if (!ytblock_kobj) {
		kfree(blocked_ips_v4);
		kfree(blocked_ips_v6);
		return -ENOMEM;
	}

	ret = sysfs_create_group(ytblock_kobj, &attr_group);
	if (ret) {
		kobject_put(ytblock_kobj);
		kfree(blocked_ips_v4);
		kfree(blocked_ips_v6);
		return ret;
	}

	nfho_out.hook = ytblock_hook_out;
	nfho_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_out.pf = NFPROTO_IPV4;
	nfho_out.priority = NF_IP_PRI_FILTER;

	ret = nf_register_net_hook(&init_net, &nfho_out);
	if (ret) {
		printk(KERN_ERR "ytblock: failed to register IPv4 hook\n");
		goto err;
	}
	ipv4_registered = true;

	nfho_forward.hook = ytblock_hook_forward;
	nfho_forward.hooknum = NF_INET_FORWARD;
	nfho_forward.pf = NFPROTO_IPV4;
	nfho_forward.priority = NF_IP_PRI_FILTER;

	ret = nf_register_net_hook(&init_net, &nfho_forward);
	if (ret)
		printk(KERN_WARNING "ytblock: FORWARD hook failed (non-fatal)\n");
	else
		forward_registered = true;

#if IS_ENABLED(CONFIG_IPV6)
	nfho_out6.hook = ytblock_hook_out6;
	nfho_out6.hooknum = NF_INET_LOCAL_OUT;
	nfho_out6.pf = NFPROTO_IPV6;
	nfho_out6.priority = NF_IP_PRI_FILTER;

	ret = nf_register_net_hook(&init_net, &nfho_out6);
	if (ret)
		printk(KERN_WARNING "ytblock: IPv6 hook failed (non-fatal)\n");
	else
		ipv6_registered = true;
#endif

	timer_setup(&enable_timer, enable_timer_cb, 0);

	ret = setup_file_protection();
	if (ret)
		printk(KERN_WARNING "ytblock: file protection init failed\n");

	printk(KERN_INFO "ytblock: loaded (disabled by default, unload key: %*phN)\n",
	       16, unload_key);
	return 0;

err:
	ytblock_cleanup_netfilter();
	sysfs_remove_group(ytblock_kobj, &attr_group);
	kobject_put(ytblock_kobj);
	kfree(blocked_ips_v4);
	kfree(blocked_ips_v6);
	return ret;
}

module_init(ytblock_init);
module_exit(ytblock_exit);