#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <crypto/sha2.h>
#include "kblocker.h"

bool ct_memcmp_eq(const u8 *a, const u8 *b, size_t size)
{
	u8 diff = 0;
	size_t i;
	for (i = 0; i < size; i++)
		diff |= READ_ONCE(a[i]) ^ READ_ONCE(b[i]);
	return diff == 0;
}

#ifdef KBLOCKER_DEBUG
/*
 * Keys are 00 01 02 ... 0f, so a fuzzer, which cannot carry what it reads
 * from the key attribute into a later write, can still present the right
 * key and reach the authorized disable and unload paths.
 */
static bool fixed_key;
module_param(fixed_key, bool, 0444);
MODULE_PARM_DESC(fixed_key, "Use a constant key (debug builds only)");
#endif

/* Caller holds kb_lock (or is module init) */
void generate_unload_key(void)
{
#ifdef KBLOCKER_DEBUG
	if (fixed_key) {
		int i;

		for (i = 0; i < sizeof(unload_key); i++)
			unload_key[i] = i;
	} else
#endif
		get_random_bytes(unload_key, sizeof(unload_key));
	sha256(unload_key, sizeof(unload_key), key_hash);
}

/*
 * Parse a 32-hex-digit key from a sysfs write and compare its SHA-256
 * against key_hash. Returns 0 on match, -EINVAL on malformed input,
 * -EPERM on mismatch. Caller holds kb_lock.
 */
static int check_key(const char *buf, size_t count)
{
	u8 parsed[16], input_hash[32];
	bool match;

	if (count && buf[count - 1] == '\n')
		count--;
	if (count != 32 || kb_hex_decode(buf, parsed, 16))
		return -EINVAL;

	sha256(parsed, sizeof(parsed), input_hash);
	match = ct_memcmp_eq(input_hash, key_hash, sizeof(input_hash));
	memzero_explicit(parsed, sizeof(parsed));
	memzero_explicit(input_hash, sizeof(input_hash));
	return match ? 0 : -EPERM;
}

ssize_t unblock_store(struct kobject *kobj, struct kobj_attribute *attr,
		      const char *buf, size_t count)
{
	int ret;

	mutex_lock(&kb_lock);
	ret = check_key(buf, count);
	if (ret) {
		kb_unlock();
		if (ret == -EPERM)
			printk(KERN_WARNING "kblocker: invalid unload key attempt\n");
		return ret;
	}

	disable_blocking();
	WRITE_ONCE(allow_unload, true);
	memzero_explicit(unload_key, sizeof(unload_key));
	memzero_explicit(key_hash, sizeof(key_hash));
	kb_unlock();

	printk(KERN_INFO "kblocker: unload authorized, auto-disabled\n");
	return count;
}

ssize_t disable_store(struct kobject *kobj, struct kobj_attribute *attr,
		      const char *buf, size_t count)
{
	int ret;

	mutex_lock(&kb_lock);
	if (!pgp_active) {
		disable_blocking();
		kb_unlock();
		return count;
	}

	ret = check_key(buf, count);
	if (ret) {
		kb_unlock();
		if (ret == -EPERM)
			printk(KERN_WARNING "kblocker: invalid disable key attempt\n");
		return ret;
	}

	disable_blocking();
	generate_unload_key();
	kb_unlock();

	printk(KERN_INFO "kblocker: authorized disable, new key generated\n");
	return count;
}

ssize_t unload_key_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	ssize_t len = 0;
	int i;

	mutex_lock(&kb_lock);
	if (state_restored) {
		len = sysfs_emit(buf, "restored\n");
	} else if (pgp_active) {
		/* One-shot PGP key buffer: show key once, then zero it */
		if (!pgp_key_consumed) {
			for (i = 0; i < 16; i++)
				len += sysfs_emit_at(buf, len, "%02x", pgp_key[i]);
			len += sysfs_emit_at(buf, len, "\n");
			memzero_explicit(pgp_key, sizeof(pgp_key));
			pgp_key_consumed = true;
		} else {
			len = sysfs_emit(buf, "encrypted\n");
		}
	} else {
		for (i = 0; i < 16; i++)
			len += sysfs_emit_at(buf, len, "%02x", unload_key[i]);
		len += sysfs_emit_at(buf, len, "\n");
	}
	kb_unlock();
	return len;
}

ssize_t pgp_active_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(pgp_active));
}

ssize_t pgp_active_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	bool val;

	if (kstrtobool(buf, &val))
		return -EINVAL;

	mutex_lock(&kb_lock);
	if (enabled) {
		/* Once enabled, pgp_active is kernel-managed — read-only */
		kb_unlock();
		printk(KERN_WARNING "kblocker: pgp_active is read-only while enabled\n");
		return -EPERM;
	}

	if (val && !pgp_active) {
		WRITE_ONCE(pgp_active, true);
		memzero_explicit(unload_key, sizeof(unload_key));
		memzero_explicit(pgp_key, sizeof(pgp_key));
		pgp_key_consumed = true;
		WRITE_ONCE(state_restored, false);
		printk(KERN_INFO "kblocker: PGP mode pre-armed (set before enable)\n");
	} else if (!val && pgp_active) {
		WRITE_ONCE(pgp_active, false);
		memzero_explicit(pgp_key, sizeof(pgp_key));
		pgp_key_consumed = true;
		printk(KERN_INFO "kblocker: PGP mode pre-arm cancelled\n");
	}
	kb_unlock();

	return count;
}
