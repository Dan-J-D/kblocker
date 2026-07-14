#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/timer.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>
#include <linux/random.h>
#include <linux/inet.h>
#include "kblocker.h"

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
	expiry_seconds = 0;
	WRITE_ONCE(state_restored, false);
	WRITE_ONCE(pgp_active, false);
	memzero_explicit(pgp_key, sizeof(pgp_key));
	pgp_key_consumed = true;
	if (atomic_xchg(&ref_taken, 0))
		module_put(THIS_MODULE);
	do_disable_cleanup();
}

void do_disable_work(struct work_struct *work)
{
	do_disable_cleanup();
}

void disable_blocking(void)
{
	do_disable();
}

void enable_timer_cb(struct timer_list *t)
{
	if (!READ_ONCE(enabled))
		return;

	if (ktime_get_real_seconds() >= expiry_seconds) {
		WRITE_ONCE(enabled, false);
		expiry_seconds = 0;
		WRITE_ONCE(state_restored, false);
		WRITE_ONCE(pgp_active, false);
		memzero_explicit(pgp_key, sizeof(pgp_key));
		pgp_key_consumed = true;
		if (atomic_xchg(&ref_taken, 0))
			module_put(THIS_MODULE);
		printk(KERN_INFO "kblocker: timer-expired, disabling\n");
		schedule_work(&kb_disable_work);
		return;
	}

	mod_timer(&enable_timer, jiffies + HZ);
}

void enable_blocking(unsigned int seconds)
{
	generate_unload_key();
	/* PGP pre-arm: if pgp_active was set to 1 before enable,
	 * copy key to one-shot buffer, immediately zero unload_key,
	 * and lock pgp_active. */
	if (READ_ONCE(pgp_active)) {
		memcpy(pgp_key, unload_key, 16);
		pgp_key_consumed = false;
		memzero_explicit(unload_key, sizeof(unload_key));
	} else {
		memzero_explicit(pgp_key, sizeof(pgp_key));
		pgp_key_consumed = true;
	}
	WRITE_ONCE(enabled, true);
	expiry_seconds = ktime_get_real_seconds() + seconds;
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

u64 remaining_seconds(void)
{
	u64 exp;

	if (!READ_ONCE(enabled))
		return 0;

	exp = READ_ONCE(expiry_seconds);
	if (!exp || ktime_get_real_seconds() >= exp)
		return 0;

	return exp - ktime_get_real_seconds();
}

void do_restore(const u8 *hash, u64 expiry_ts)
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

	WRITE_ONCE(enabled, true);
	if (!atomic_xchg(&ref_taken, 1))
		__module_get(THIS_MODULE);
	mod_timer(&enable_timer, jiffies + HZ);
	WRITE_ONCE(enable_timer_active, true);
	update_hosts_file();

	printk(KERN_INFO "kblocker: state restored, %llu seconds remaining\n", delta);
}

void try_restore_state_from_disk(void)
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