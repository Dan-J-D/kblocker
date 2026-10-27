#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <net/ipv6.h>
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

DEFINE_MUTEX(kb_lock);
bool allow_unload;
u8 unload_key[16];
u8 key_hash[32];
u8 pgp_key[16];
bool pgp_key_consumed;
bool state_restored;
bool enabled;
bool pgp_active;
atomic_t ref_taken = ATOMIC_INIT(0);

struct kobject *kblocker_kobj;

char *kb_hosts_file = "/etc/hosts";
char *kb_state_file = "/var/lib/kblocker/state";
char *kb_modconf_file = "/etc/modules-load.d/kblocker.conf";

#ifdef KBLOCKER_DEBUG
/* Debug builds only: in a release build these would let root point the
 * state file elsewhere via modprobe.d and skip restore after a reboot. */
module_param_named(hosts_file, kb_hosts_file, charp, 0444);
module_param_named(state_file, kb_state_file, charp, 0444);
module_param_named(modconf_file, kb_modconf_file, charp, 0444);
MODULE_PARM_DESC(hosts_file, "Hosts file to manage (debug builds only)");
MODULE_PARM_DESC(state_file, "Session state file (debug builds only)");
MODULE_PARM_DESC(modconf_file, "modules-load.d entry to protect (debug builds only)");
#endif

/* Copy the domain list; returns the number of entries copied */
int snapshot_domains(char (*dst)[MAX_DOMAIN_LEN])
{
	int n;

	spin_lock_bh(&ip_list_lock);
	n = blocked_domain_count;
	memcpy(dst, blocked_domains, n * MAX_DOMAIN_LEN);
	spin_unlock_bh(&ip_list_lock);
	return n;
}

static ssize_t status_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	return sysfs_emit(buf, "enabled: %d\nblocked_ips_v4: %d\n"
			  "blocked_ips_v6: %d\nblocked_domains: %d\nblock_count: %d\n"
			  "remaining: %llu\n"
			  "allow_unload: %d\nprotected_files: %d\n"
			  "state_restored: %d\n"
			  "pgp_active: %d\n",
			  READ_ONCE(enabled), READ_ONCE(blocked_count_v4),
			  READ_ONCE(blocked_count_v6),
			  READ_ONCE(blocked_domain_count),
			  READ_ONCE(blocked_count_v4) + READ_ONCE(blocked_count_v6),
			  remaining_seconds(), READ_ONCE(allow_unload),
			  protection_count(), READ_ONCE(state_restored),
			  READ_ONCE(pgp_active));
}

static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	return sysfs_emit(buf, "%d %llu\n", READ_ONCE(enabled), remaining_seconds());
}

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	u64 val;
	int ret = 0;

	if (kstrtou64(buf, 0, &val))
		return -EINVAL;
	if (val > MAX_SESSION_SECONDS)
		return -ERANGE;

	mutex_lock(&kb_lock);
	if (val == 0) {
		if (pgp_active) {
			/* A pre-armed PGP session cannot be disabled through
			 * this file; disable/unblock with the key instead. */
			if (enabled) {
				ret = -EPERM;
			} else {
				clear_hosts_from_kernel();
				printk(KERN_INFO "kblocker: cleaned hosts (pgp_active, already disabled)\n");
			}
		} else {
			disable_blocking();
		}
	} else {
		/* If pgp_active was pre-armed (written to 1 before this
		 * store), the key goes to a one-shot buffer and pgp_active
		 * becomes read-only. Otherwise the key stays readable from
		 * /sys/kernel/kblocker/key and pgp_active cannot be set
		 * until the session ends. */
		ret = enable_blocking(val);
	}
	kb_unlock();

	return ret ? ret : count;
}

static ssize_t remaining_show(struct kobject *kobj, struct kobj_attribute *attr,
			      char *buf)
{
	return sysfs_emit(buf, "%llu\n", remaining_seconds());
}

static ssize_t blocked_ips_show(struct kobject *kobj, struct kobj_attribute *attr,
				char *buf)
{
	int i, len = 0;

	spin_lock_bh(&ip_list_lock);
	for (i = 0; i < blocked_count_v4; i++)
		len += sysfs_emit_at(buf, len, "%pI4\n", &blocked_ips_v4[i]);
	for (i = 0; i < blocked_count_v6; i++)
		len += sysfs_emit_at(buf, len, "%pI6\n", &blocked_ips_v6[i]);
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
	ssize_t ret = count;

	tmp_v4 = kmalloc_array(MAX_IPS_V4, sizeof(__be32), GFP_KERNEL);
	tmp_v6 = kmalloc_array(MAX_IPS_V6, sizeof(struct in6_addr), GFP_KERNEL);
	copy = kmemdup_nul(buf, count, GFP_KERNEL);
	if (!tmp_v4 || !tmp_v6 || !copy) {
		ret = -ENOMEM;
		goto out;
	}
	orig_copy = copy;

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
	copy = orig_copy;

	mutex_lock(&kb_lock);
	if (enabled) {
		ret = -EPERM;
	} else {
		spin_lock_bh(&ip_list_lock);
		memcpy(blocked_ips_v4, tmp_v4, n4 * sizeof(__be32));
		memcpy(blocked_ips_v6, tmp_v6, n6 * sizeof(struct in6_addr));
		WRITE_ONCE(blocked_count_v4, n4);
		WRITE_ONCE(blocked_count_v6, n6);
		spin_unlock_bh(&ip_list_lock);
	}
	kb_unlock();
out:
	kfree(tmp_v4);
	kfree(tmp_v6);
	kfree(copy);
	return ret;
}

static ssize_t blocked_domains_show(struct kobject *kobj, struct kobj_attribute *attr,
				    char *buf)
{
	int i, len = 0;

	spin_lock_bh(&ip_list_lock);
	for (i = 0; i < blocked_domain_count; i++)
		len += sysfs_emit_at(buf, len, "%s\n", blocked_domains[i]);
	spin_unlock_bh(&ip_list_lock);
	return len;
}

static ssize_t blocked_domains_store(struct kobject *kobj, struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	char (*tmp)[MAX_DOMAIN_LEN];
	char *copy, *orig, *token, *d;
	int nd = 0;
	ssize_t ret = count;

	tmp = kmalloc_array(MAX_DOMAINS, MAX_DOMAIN_LEN, GFP_KERNEL);
	copy = kmemdup_nul(buf, count, GFP_KERNEL);
	if (!tmp || !copy) {
		ret = -ENOMEM;
		goto out;
	}
	orig = copy;

	/* Validate everything before touching the live list */
	while ((token = strsep(&copy, "\n"))) {
		if (strim(token)[0] == '\0' || strim(token)[0] == '#')
			continue;
		d = kb_normalize_domain(token);
		if (!d || nd >= MAX_DOMAINS) {
			ret = -EINVAL;
			break;
		}
		strscpy(tmp[nd++], d, MAX_DOMAIN_LEN);
	}
	copy = orig;
	if (ret < 0)
		goto out;

	mutex_lock(&kb_lock);
	if (enabled) {
		ret = -EPERM;
	} else {
		spin_lock_bh(&ip_list_lock);
		memcpy(blocked_domains, tmp, nd * MAX_DOMAIN_LEN);
		WRITE_ONCE(blocked_domain_count, nd);
		spin_unlock_bh(&ip_list_lock);
	}
	kb_unlock();
out:
	kfree(tmp);
	kfree(copy);
	return ret;
}

static ssize_t block_count_show(struct kobject *kobj, struct kobj_attribute *attr,
				char *buf)
{
	int n4, n6;

	spin_lock_bh(&ip_list_lock);
	n4 = blocked_count_v4;
	n6 = blocked_count_v6;
	spin_unlock_bh(&ip_list_lock);

	return sysfs_emit(buf, "%d\n", n4 + n6);
}

static struct kobj_attribute status_attr = __ATTR_RO(status);
static struct kobj_attribute enabled_attr = __ATTR_RW(enabled);
static struct kobj_attribute remaining_attr = __ATTR_RO(remaining);
static struct kobj_attribute blocked_ips_attr = __ATTR_RW(blocked_ips);
static struct kobj_attribute blocked_domains_attr = __ATTR_RW(blocked_domains);
static struct kobj_attribute block_count_attr = __ATTR_RO(block_count);
static struct kobj_attribute unblock_attr = __ATTR_WO(unblock);
static struct kobj_attribute key_attr = __ATTR(key, 0400, unload_key_show, NULL);
static struct kobj_attribute pgp_active_attr = __ATTR_RW(pgp_active);
static struct kobj_attribute disable_attr = __ATTR_WO(disable);

#ifdef KBLOCKER_DEBUG
/*
 * Simulate a reboot (kb_debug_reboot), so a fuzzer that rewrites the state
 * file can reach recovery without reloading the module. Never built into
 * release modules: it ends sessions without the key and lets anyone who
 * can write the state file start a locked one.
 */
static ssize_t debug_restore_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	mutex_lock(&kb_lock);
	kb_debug_reboot();
	kb_unlock();
	return count;
}
static struct kobj_attribute debug_restore_attr = __ATTR_WO(debug_restore);
#endif

static struct attribute *attrs[] = {
	&status_attr.attr,
	&enabled_attr.attr,
	&remaining_attr.attr,
	&blocked_ips_attr.attr,
	&blocked_domains_attr.attr,
	&block_count_attr.attr,
	&unblock_attr.attr,
	&key_attr.attr,
	&pgp_active_attr.attr,
	&disable_attr.attr,
#ifdef KBLOCKER_DEBUG
	&debug_restore_attr.attr,
#endif
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static int __init kblocker_init(void)
{
	int ret;

	pgp_key_consumed = true;
	session_init();
	protection_init();

	blocked_ips_v4 = kmalloc_array(MAX_IPS_V4, sizeof(__be32), GFP_KERNEL);
	blocked_ips_v6 = kmalloc_array(MAX_IPS_V6, sizeof(struct in6_addr), GFP_KERNEL);
	if (!blocked_ips_v4 || !blocked_ips_v6) {
		ret = -ENOMEM;
		goto err_free;
	}

	ret = kblocker_register_netfilter();
	if (ret)
		goto err_free;

	mutex_lock(&kb_lock);
	try_restore_state_from_disk();
	if (!state_restored)
		generate_unload_key();
	kb_unlock();

	/* sysfs last, so nothing can race with the restore above */
	kblocker_kobj = kobject_create_and_add("kblocker", kernel_kobj);
	if (!kblocker_kobj) {
		ret = -ENOMEM;
		goto err_session;
	}
	ret = sysfs_create_group(kblocker_kobj, &attr_group);
	if (ret) {
		kobject_put(kblocker_kobj);
		goto err_session;
	}

	printk(KERN_INFO "kblocker: loaded (%s)\n",
	       READ_ONCE(enabled) ? "session restored" : "disabled by default");
	return 0;

err_session:
	mutex_lock(&kb_lock);
	disable_blocking();
	kb_unlock();
	session_exit();
	kblocker_cleanup_netfilter();
err_free:
	kfree(blocked_ips_v4);
	kfree(blocked_ips_v6);
	return ret;
}

static void __exit kblocker_exit(void)
{
	if (READ_ONCE(enabled) && !READ_ONCE(allow_unload)) {
		panic("kblocker: FORCED UNLOAD DETECTED while enabled. System halted.");
	}

	if (kblocker_kobj) {
		sysfs_remove_group(kblocker_kobj, &attr_group);
		kobject_put(kblocker_kobj);
	}

	session_exit();
	protection_disable();
	kblocker_cleanup_netfilter();

	memzero_explicit(unload_key, sizeof(unload_key));
	memzero_explicit(key_hash, sizeof(key_hash));
	memzero_explicit(pgp_key, sizeof(pgp_key));
	kfree(blocked_ips_v4);
	kfree(blocked_ips_v6);
	printk(KERN_INFO "kblocker: cleanly unloaded\n");
}

module_init(kblocker_init);
module_exit(kblocker_exit);
