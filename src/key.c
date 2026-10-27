#include <linux/kernel.h>
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

static int hex_val(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

int hex_decode(const char *s, u8 *out, int count)
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

/* Caller holds kb_lock (or is module init) */
void generate_unload_key(void)
{
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
	if (count != 32 || hex_decode(buf, parsed, 16))
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
		mutex_unlock(&kb_lock);
		if (ret == -EPERM)
			printk(KERN_WARNING "kblocker: invalid unload key attempt\n");
		return ret;
	}

	disable_blocking();
	WRITE_ONCE(allow_unload, true);
	memzero_explicit(unload_key, sizeof(unload_key));
	memzero_explicit(key_hash, sizeof(key_hash));
	mutex_unlock(&kb_lock);

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
		mutex_unlock(&kb_lock);
		return count;
	}

	ret = check_key(buf, count);
	if (ret) {
		mutex_unlock(&kb_lock);
		if (ret == -EPERM)
			printk(KERN_WARNING "kblocker: invalid disable key attempt\n");
		return ret;
	}

	disable_blocking();
	generate_unload_key();
	mutex_unlock(&kb_lock);

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
	mutex_unlock(&kb_lock);
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
		mutex_unlock(&kb_lock);
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
	mutex_unlock(&kb_lock);

	return count;
}
