#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/fileattr.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/timer.h>
#include <linux/timekeeping.h>
#include <linux/workqueue.h>
#include <linux/random.h>
#include <linux/inet.h>
#include <net/ipv6.h>
#include "kblocker.h"

/*
 * The running session is timed with the boottime clock, which root
 * cannot set. The wall clock is never consulted while a session runs.
 * Across reboots only the remaining duration is persisted, so time
 * spent powered off does not count and clock changes cannot shorten
 * a session.
 */
static u64 expiry_boot;
static unsigned int save_ticks;
static struct timer_list enable_timer;
static struct work_struct kb_expire_work;

/* Held open from session start; the file is append-only while protected */
static struct file *state_filp;

/* Head of the state file holding key/domains/IPs, and tail holding the
 * most recent remaining: line */
#define STATE_HEAD_MAX (256 * 1024)
#define STATE_TAIL_MAX 128

static u64 now_boot(void)
{
	return ktime_get_boottime_seconds();
}

u64 remaining_seconds(void)
{
	u64 exp, now;

	if (!READ_ONCE(enabled))
		return 0;

	exp = READ_ONCE(expiry_boot);
	now = now_boot();
	return exp > now ? exp - now : 0;
}

/* Clear on-disk immutable/append-only flags (e.g. a chattr +i set by an
 * older kblockerctl), so the file can be rewritten or truncated. */
static void clear_ondisk_flags(const struct path *p)
{
	kb_fileattr_t fa;
	int err;

	if (vfs_fileattr_get(p->dentry, &fa))
		return;
	if (!(fa.flags & (FS_IMMUTABLE_FL | FS_APPEND_FL)))
		return;

	fileattr_fill_flags(&fa, fa.flags & ~(FS_IMMUTABLE_FL | FS_APPEND_FL));
	err = vfs_fileattr_set(mnt_idmap(p->mnt), p->dentry, &fa);
	if (err)
		printk(KERN_WARNING "kblocker: clearing flags on %s failed: %d\n",
		       STATE_FILE, err);
}

static void state_file_close(void)
{
	if (state_filp) {
		filp_close(state_filp, NULL);
		state_filp = NULL;
	}
}

/* Truncate the persisted session so a reboot does not restore it.
 * Caller holds kb_lock and file protection is already off. */
void state_file_clear(void)
{
	struct path p;
	int err;

	state_file_close();

	if (kern_path(STATE_FILE, LOOKUP_FOLLOW, &p))
		return;
	clear_ondisk_flags(&p);
	err = vfs_truncate(&p, 0);
	if (err)
		printk(KERN_ERR "kblocker: truncating %s failed: %d\n",
		       STATE_FILE, err);
	path_put(&p);
}

static int state_file_write_session(u64 seconds)
{
	char (*doms)[MAX_DOMAIN_LEN];
	__be32 *v4;
	struct in6_addr *v6;
	size_t size, len;
	char *buf;
	struct file *f;
	struct path p;
	loff_t pos = 0;
	ssize_t written;
	int nd, n4, n6, i, ret = -ENOMEM;

	state_file_close();

	doms = kmalloc_array(MAX_DOMAINS, MAX_DOMAIN_LEN, GFP_KERNEL);
	v4 = kmalloc_array(MAX_IPS_V4, sizeof(*v4), GFP_KERNEL);
	v6 = kmalloc_array(MAX_IPS_V6, sizeof(*v6), GFP_KERNEL);
	size = 256 + MAX_DOMAINS * (MAX_DOMAIN_LEN + 1) +
	       MAX_IPS_V4 * 16 + MAX_IPS_V6 * 41;
	buf = kvmalloc(size, GFP_KERNEL);
	if (!doms || !v4 || !v6 || !buf)
		goto out;

	nd = snapshot_domains(doms);
	spin_lock_bh(&ip_list_lock);
	n4 = blocked_count_v4;
	n6 = blocked_count_v6;
	memcpy(v4, blocked_ips_v4, n4 * sizeof(*v4));
	memcpy(v6, blocked_ips_v6, n6 * sizeof(*v6));
	spin_unlock_bh(&ip_list_lock);

	len = scnprintf(buf, size, "remaining:%llu\nkey_hash:%*phN\npgp_active:%d\n",
			seconds, 32, key_hash, pgp_active);
	if (nd) {
		len += scnprintf(buf + len, size - len, "domains:");
		for (i = 0; i < nd; i++)
			len += scnprintf(buf + len, size - len, "%s%s",
					 i ? "," : "", doms[i]);
		len += scnprintf(buf + len, size - len, "\n");
	}
	if (n4 || n6) {
		len += scnprintf(buf + len, size - len, "blocked_ips:");
		for (i = 0; i < n4; i++)
			len += scnprintf(buf + len, size - len, "%pI4,", &v4[i]);
		for (i = 0; i < n6; i++)
			len += scnprintf(buf + len, size - len, "%pI6c,", &v6[i]);
		len += scnprintf(buf + len, size - len, "\n");
	}

	if (!kern_path(STATE_FILE, LOOKUP_FOLLOW, &p)) {
		clear_ondisk_flags(&p);
		path_put(&p);
	}

	f = filp_open(STATE_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0600);
	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		printk(KERN_ERR "kblocker: cannot open %s: %d\n", STATE_FILE, ret);
		goto out;
	}

	written = kernel_write(f, buf, len, &pos);
	if (written != len) {
		printk(KERN_ERR "kblocker: writing %s failed: %zd\n",
		       STATE_FILE, written);
		filp_close(f, NULL);
		ret = written < 0 ? written : -EIO;
		goto out;
	}
	vfs_fsync(f, 0);
	state_filp = f;
	ret = 0;
out:
	kvfree(buf);
	kfree(v6);
	kfree(v4);
	kfree(doms);
	return ret;
}

/* Append the current remaining duration. Uses the descriptor opened
 * before protection made the file append-only and unwritable. */
static void state_file_append_remaining(u64 rem)
{
	char line[40];
	loff_t pos = 0;
	int len;

	if (!state_filp)
		return;
	len = scnprintf(line, sizeof(line), "remaining:%llu\n", rem);
	if (kernel_write(state_filp, line, len, &pos) != len)
		printk(KERN_WARNING "kblocker: saving remaining time failed\n");
	else
		vfs_fsync(state_filp, 1);
}

static void stop_session(void)
{
	WRITE_ONCE(enabled, false);
	WRITE_ONCE(expiry_boot, 0);
	WRITE_ONCE(state_restored, false);
	WRITE_ONCE(pgp_active, false);
	memzero_explicit(pgp_key, sizeof(pgp_key));
	pgp_key_consumed = true;
	timer_delete(&enable_timer);
	if (atomic_xchg(&ref_taken, 0))
		module_put(THIS_MODULE);
}

/* Caller holds kb_lock */
void disable_blocking(void)
{
	stop_session();
	protection_disable();
	log_blocklist_on_disable();
	clear_hosts_from_kernel();
	state_file_clear();
	printk(KERN_INFO "kblocker: disabled\n");
}

static void start_session(u64 seconds)
{
	WRITE_ONCE(expiry_boot, now_boot() + seconds);
	WRITE_ONCE(allow_unload, false);
	WRITE_ONCE(enabled, true);
	if (!atomic_xchg(&ref_taken, 1))
		__module_get(THIS_MODULE);

	update_hosts_file();
	/* Only PGP sessions are locked; others can be disabled without a
	 * key anyway, so they are not persisted across reboots. */
	if (pgp_active)
		state_file_write_session(seconds);
	else
		state_file_clear();
	protection_enable();

	save_ticks = 0;
	mod_timer(&enable_timer, jiffies + HZ);
}

/* Caller holds kb_lock */
int enable_blocking(u64 seconds)
{
	if (enabled)
		return -EPERM;
	if (!seconds || seconds > MAX_SESSION_SECONDS)
		return -EINVAL;

	generate_unload_key();
	/* PGP pre-arm: if pgp_active was set to 1 before enable,
	 * copy key to one-shot buffer, immediately zero unload_key,
	 * and lock pgp_active. */
	if (pgp_active) {
		memcpy(pgp_key, unload_key, sizeof(pgp_key));
		pgp_key_consumed = false;
		memzero_explicit(unload_key, sizeof(unload_key));
	} else {
		memzero_explicit(pgp_key, sizeof(pgp_key));
		pgp_key_consumed = true;
	}
	WRITE_ONCE(state_restored, false);
	start_session(seconds);
	printk(KERN_INFO "kblocker: enabled for %llu seconds\n", seconds);
	return 0;
}

static void kb_expire_work_fn(struct work_struct *work)
{
	u64 rem;

	mutex_lock(&kb_lock);
	if (!enabled)
		goto out;

	rem = remaining_seconds();
	if (!rem) {
		printk(KERN_INFO "kblocker: timer-expired, disabling\n");
		disable_blocking();
		goto out;
	}

	if (++save_ticks >= STATE_SAVE_INTERVAL_S) {
		save_ticks = 0;
		state_file_append_remaining(rem);
	}
	mod_timer(&enable_timer, jiffies + HZ);
out:
	mutex_unlock(&kb_lock);
}

static void enable_timer_cb(struct timer_list *t)
{
	schedule_work(&kb_expire_work);
}

void session_init(void)
{
	INIT_WORK(&kb_expire_work, kb_expire_work_fn);
	timer_setup(&enable_timer, enable_timer_cb, 0);
}

void session_exit(void)
{
	timer_delete_sync(&enable_timer);
	cancel_work_sync(&kb_expire_work);
	timer_delete_sync(&enable_timer);

	mutex_lock(&kb_lock);
	state_file_clear();
	mutex_unlock(&kb_lock);
}

static ssize_t read_at(struct file *f, char *buf, size_t len, loff_t pos)
{
	ssize_t ret = kernel_read(f, buf, len, &pos);

	if (ret < 0)
		return ret;
	buf[ret] = '\0';
	return ret;
}

/* Value of the last complete "remaining:N\n" line in @s, or 0 */
static u64 last_remaining(const char *s)
{
	const char *p = s, *hit;
	u64 val = 0, v;
	char *end;

	while ((hit = strstr(p, "remaining:"))) {
		p = hit + 10;
		if (hit != s && hit[-1] != '\n')
			continue;
		v = simple_strtoull(p, &end, 10);
		if (end != p && *end == '\n')
			val = v;
	}
	return val;
}

static void restore_domains(char *buf)
{
	char *p, *end, *copy, *orig, *token;
	int nd = 0;

	p = strstr(buf, "domains:");
	if (!p)
		return;
	p += 8;
	end = strchr(p, '\n');
	if (!end || end == p)
		return;
	copy = kmemdup_nul(p, end - p, GFP_KERNEL);
	if (!copy)
		return;
	orig = copy;

	spin_lock_bh(&ip_list_lock);
	while ((token = strsep(&copy, ",")) && nd < MAX_DOMAINS) {
		int dlen = strlen(token);
		if (dlen > 0 && dlen < MAX_DOMAIN_LEN) {
			memcpy(blocked_domains[nd], token, dlen + 1);
			nd++;
		}
	}
	WRITE_ONCE(blocked_domain_count, nd);
	spin_unlock_bh(&ip_list_lock);
	kfree(orig);
}

static void restore_ips(char *buf)
{
	char *p, *end, *copy, *orig, *token;
	__be32 *tmp_v4;
	struct in6_addr *tmp_v6;
	int n4 = 0, n6 = 0;

	p = strstr(buf, "blocked_ips:");
	if (!p)
		return;
	p += 12;
	end = strchr(p, '\n');
	if (!end || end == p)
		return;
	copy = kmemdup_nul(p, end - p, GFP_KERNEL);
	tmp_v4 = kmalloc_array(MAX_IPS_V4, sizeof(__be32), GFP_KERNEL);
	tmp_v6 = kmalloc_array(MAX_IPS_V6, sizeof(struct in6_addr), GFP_KERNEL);
	if (!copy || !tmp_v4 || !tmp_v6)
		goto out;
	orig = copy;

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
	copy = orig;
out:
	kfree(tmp_v4);
	kfree(tmp_v6);
	kfree(copy);
}

/*
 * Called once from module init, under kb_lock. This is the only way a
 * session can be restored; there is no sysfs interface for it.
 */
void try_restore_state_from_disk(void)
{
	struct file *file;
	char *head = NULL, *tail = NULL, *p, *end;
	loff_t size;
	u8 hash[32];
	u64 rem = 0;

	if (enabled || state_restored)
		return;

	file = filp_open(STATE_FILE, O_RDONLY, 0);
	if (IS_ERR(file))
		return;

	size = i_size_read(file_inode(file));
	if (size <= 0)
		goto out;
	head = kvmalloc(STATE_HEAD_MAX + 1, GFP_KERNEL);
	tail = kmalloc(STATE_TAIL_MAX + 1, GFP_KERNEL);
	if (!head || !tail)
		goto out;
	if (read_at(file, head, min_t(loff_t, size, STATE_HEAD_MAX), 0) <= 0)
		goto out;
	if (read_at(file, tail, min_t(loff_t, size, STATE_TAIL_MAX),
		    max_t(loff_t, size - STATE_TAIL_MAX, 0)) < 0)
		goto out;

	restore_domains(head);
	restore_ips(head);

	p = strstr(head, "key_hash:");
	if (!p)
		goto out;
	p += 9;
	end = strchr(p, '\n');
	if (!end || end - p != 64 || hex_decode(p, hash, 32))
		goto out;

	rem = last_remaining(tail);
	if (!rem)
		rem = last_remaining(head);
	if (!rem) {
		/* Legacy file written by older kblockerctl: wall-clock deadline */
		p = strstr(head, "expiry:");
		if (p) {
			u64 expiry = simple_strtoull(p + 7, &end, 10);
			time64_t now = ktime_get_real_seconds();
			if (end != p + 7 && expiry > now)
				rem = expiry - now;
		}
	}
	if (!rem) {
		printk(KERN_INFO "kblocker: restore skipped (already expired)\n");
		goto out;
	}
	rem = min_t(u64, rem, MAX_SESSION_SECONDS);

	filp_close(file, NULL);
	file = NULL;

	memcpy(key_hash, hash, sizeof(key_hash));
	memzero_explicit(unload_key, sizeof(unload_key));
	memzero_explicit(pgp_key, sizeof(pgp_key));
	pgp_key_consumed = true;
	/* Only PGP sessions are ever persisted and the raw key is gone, so a
	 * restored session is always PGP-locked, whatever the file says. */
	WRITE_ONCE(pgp_active, true);
	WRITE_ONCE(state_restored, true);
	start_session(rem);
	printk(KERN_INFO "kblocker: state restored, %llu seconds remaining\n", rem);
out:
	memzero_explicit(hash, sizeof(hash));
	kfree(tail);
	kvfree(head);
	if (file)
		filp_close(file, NULL);
}
