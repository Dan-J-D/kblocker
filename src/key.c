#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include "kblocker.h"

bool ct_memcmp_eq(const u8 *a, const u8 *b, size_t size)
{
	u8 diff = 0;
	size_t i;
	for (i = 0; i < size; i++)
		diff |= READ_ONCE(a[i]) ^ READ_ONCE(b[i]);
	return diff == 0;
}

int hex_val(char c)
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

void generate_unload_key(void)
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

ssize_t unblock_store(struct kobject *kobj, struct kobj_attribute *attr,
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

ssize_t disable_store(struct kobject *kobj, struct kobj_attribute *attr,
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

ssize_t unload_key_show(struct kobject *kobj, struct kobj_attribute *attr,
			       char *buf)
{
	if (READ_ONCE(state_restored))
		return sprintf(buf, "restored\n");

	if (READ_ONCE(pgp_active)) {
		/* One-shot PGP key buffer: show key once, then zero it */
		if (!READ_ONCE(pgp_key_consumed)) {
			char *p = buf;
			int i;
			for (i = 0; i < 16; i++)
				p += sprintf(p, "%02x", pgp_key[i]);
			p += sprintf(p, "\n");
			memzero_explicit(pgp_key, sizeof(pgp_key));
			WRITE_ONCE(pgp_key_consumed, true);
			return p - buf;
		}
		return sprintf(buf, "encrypted\n");
	}

	char *p = buf;
	int i;
	for (i = 0; i < 16; i++)
		p += sprintf(p, "%02x", unload_key[i]);
	p += sprintf(p, "\n");
	return p - buf;
}

ssize_t pgp_active_show(struct kobject *kobj, struct kobj_attribute *attr,
			       char *buf)
{
	return sprintf(buf, "%d\n", READ_ONCE(pgp_active));
}

ssize_t pgp_active_store(struct kobject *kobj, struct kobj_attribute *attr,
			        const char *buf, size_t count)
{
	unsigned long val;
	char *end;

	val = simple_strtoul(buf, &end, 0);
	if (end == buf)
		return -EINVAL;

	if (READ_ONCE(enabled)) {
		/* Once enabled, pgp_active is kernel-managed — read-only */
		printk(KERN_WARNING "kblocker: pgp_active is read-only while enabled\n");
		return -EPERM;
	}

	if (val) {
		if (!READ_ONCE(pgp_active)) {
			WRITE_ONCE(pgp_active, true);
			memzero_explicit(unload_key, sizeof(unload_key));
			memzero_explicit(pgp_key, sizeof(pgp_key));
			WRITE_ONCE(pgp_key_consumed, true);
			WRITE_ONCE(state_restored, false);
			printk(KERN_INFO "kblocker: PGP mode pre-armed (set before enable)\n");
		}
	} else {
		if (READ_ONCE(pgp_active)) {
			WRITE_ONCE(pgp_active, false);
			memzero_explicit(pgp_key, sizeof(pgp_key));
			WRITE_ONCE(pgp_key_consumed, true);
			printk(KERN_INFO "kblocker: PGP mode pre-arm cancelled\n");
		}
	}

	return count;
}