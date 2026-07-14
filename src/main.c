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
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/version.h>
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
#include "kblocker.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("kblocker");
MODULE_DESCRIPTION("Self-discipline internet blocker - disabled by default, time-limited enable");
MODULE_VERSION("2.0");

__be32 *blocked_ips_v4;
int blocked_count_v4;
struct in6_addr *blocked_ips_v6;
int blocked_count_v6;
char blocked_domains[MAX_DOMAINS][MAX_DOMAIN_LEN];
int blocked_domain_count;
DEFINE_SPINLOCK(ip_list_lock);

bool allow_unload;
u8 unload_key[16];
u8 key_hash[32];
u8 pgp_key[16];
bool pgp_key_consumed;
bool state_restored;
struct kobject *kblocker_kobj;
struct nf_hook_ops nfho_out;
struct nf_hook_ops nfho_forward;
bool ipv4_registered;
bool forward_registered;

bool kblocker_bypass_protection;
struct protected_file protected_files[MAX_PROTECTED_PATHS];
int num_protected_files;
struct timer_list protect_timer;
bool timer_active;

bool enabled;
u64 expiry_seconds;
struct timer_list enable_timer;
bool enable_timer_active;
atomic_t ref_taken = ATOMIC_INIT(0);
bool pgp_active;

struct work_struct kb_disable_work;
struct work_struct kb_protect_work;

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
	} else if (READ_ONCE(enabled)) {
		return -EPERM;
	} else {
		enable_blocking((unsigned int)val);
		/* PGP mode: if pgp_active was pre-armed (written to 1 before
		 * this store), the kernel copies the key to a one-shot buffer
		 * and locks pgp_active read-only.
		 * If pgp_active was NOT pre-armed, it stays 0 and the key
		 * is readable from /sys/kernel/kblocker/key until userspace
		 * sets pgp_active=1 itself (legacy behavior, tolerated but
		 * discouraged — use pre-arm for full atomicity). */
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

static int __init kblocker_init(void)
{
	int ret;

	enabled = false;
	expiry_seconds = 0;
	WRITE_ONCE(state_restored, false);
	pgp_key_consumed = true;

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
	memzero_explicit(pgp_key, sizeof(pgp_key));
	kfree(blocked_ips_v4);
	kfree(blocked_ips_v6);
	printk(KERN_INFO "kblocker: cleanly unloaded\n");
}

module_init(kblocker_init);
module_exit(kblocker_exit);