#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/fileattr.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/timer.h>
#include <linux/utsname.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/rcupdate.h>
#include "kblocker.h"

/*
 * While a session is enabled, each protected path gets its inode flagged
 * (S_IMMUTABLE, or S_APPEND for the state file the kernel keeps appending
 * to) and its inode_operations swapped for a copy whose permission,
 * setattr and fileattr_set refuse changes. The flags stop unlink, rename,
 * link and writes; the hooks stop the flags from being cleared (chattr)
 * and stop writes through an append-only open.
 *
 * Every inode we have hooked keeps a slot here, holding a reference,
 * until protection is turned off. Hooks are only removed in
 * protection_disable(), which waits for in-flight hook calls before the
 * replacement tables are freed.
 */
#define MAX_INSTALLS 32

struct kb_target {
	char path[256];
	unsigned int flag;
};

struct kb_install {
	struct inode *inode;	/* published last; NULL means free */
	const struct inode_operations *orig_i_op;
	struct inode_operations *custom_i_op;
	unsigned int flag;
	bool we_set_flag;
};

static struct kb_target targets[MAX_PROTECTED_PATHS];
static int num_targets;
static struct kb_install installs[MAX_INSTALLS];
static DEFINE_MUTEX(protect_lock);
static bool protect_active;
static atomic_t hook_inflight = ATOMIC_INIT(0);
static struct timer_list protect_timer;
static struct work_struct protect_work;

/* Read a whole file; returns a NUL-terminated buffer (kvfree it) or an
 * ERR_PTR. A short read is an error so callers never act on partial data. */
char *kb_read_file(struct file *f, loff_t *out_len)
{
	loff_t size = i_size_read(file_inode(f));
	loff_t pos = 0;
	ssize_t ret;
	char *buf;

	if (size < 0 || size > HOSTS_MAX_SIZE)
		return ERR_PTR(-EFBIG);

	buf = kvmalloc(size + 1, GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	ret = size ? kernel_read(f, buf, size, &pos) : 0;
	if (ret != size) {
		kvfree(buf);
		return ERR_PTR(ret < 0 ? ret : -EIO);
	}
	buf[ret] = '\0';
	*out_len = ret;
	return buf;
}

/* Length of @buf with the kblocker block and trailing newlines removed */
static loff_t hosts_base_len(const char *buf, loff_t len)
{
	const char *p = strstr(buf, HOSTS_MARKER);

	if (p)
		len = p - buf;
	while (len > 0 && buf[len - 1] == '\n')
		len--;
	return len;
}

/*
 * Replace everything from @base onwards with @tail. Bytes before @base
 * are the user's own entries and are never rewritten, so a failed write
 * cannot destroy them.
 */
static int hosts_write_tail(struct file *file, loff_t base,
			    const char *tail, size_t tlen)
{
	loff_t pos = base;
	ssize_t written;
	int ret;

	written = kernel_write(file, tail, tlen, &pos);
	if (written != tlen) {
		printk(KERN_ERR "kblocker: /etc/hosts write failed (ret=%zd)\n",
		       written);
		return written < 0 ? written : -EIO;
	}
	ret = vfs_truncate(&file->f_path, base + tlen);
	if (ret)
		printk(KERN_ERR "kblocker: /etc/hosts truncate failed (ret=%d)\n",
		       ret);
	return ret;
}

/* Remove the kblocker block. Called while file protection is off. */
void clear_hosts_from_kernel(void)
{
	struct file *file;
	char *buf;
	loff_t len, base;

	file = filp_open("/etc/hosts", O_RDWR, 0);
	if (IS_ERR(file))
		return;

	buf = kb_read_file(file, &len);
	if (IS_ERR(buf)) {
		printk(KERN_ERR "kblocker: reading /etc/hosts failed: %ld\n",
		       PTR_ERR(buf));
		goto out;
	}

	if (strstr(buf, HOSTS_MARKER)) {
		base = hosts_base_len(buf, len);
		if (!hosts_write_tail(file, base, "\n", 1))
			printk(KERN_DEBUG "kblocker: cleared hosts file entries\n");
	}
	kvfree(buf);
out:
	filp_close(file, NULL);
}

/* Write the kblocker block. Called while file protection is off. */
int update_hosts_file(void)
{
	char (*doms)[MAX_DOMAIN_LEN];
	struct file *file;
	char *buf = NULL, *tail = NULL;
	loff_t len, base;
	size_t tsize, tlen;
	int i, nd, ret;

	doms = kmalloc_array(MAX_DOMAINS, MAX_DOMAIN_LEN, GFP_KERNEL);
	if (!doms)
		return -ENOMEM;

	/* Format from a private copy so concurrent domain updates cannot
	 * change lengths between sizing and writing. */
	nd = snapshot_domains(doms);
	if (!nd) {
		kfree(doms);
		clear_hosts_from_kernel();
		return 0;
	}

	file = filp_open("/etc/hosts", O_RDWR, 0);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		printk(KERN_ERR "kblocker: filp_open /etc/hosts failed: %d\n", ret);
		goto out_free;
	}

	buf = kb_read_file(file, &len);
	if (IS_ERR(buf)) {
		ret = PTR_ERR(buf);
		buf = NULL;
		printk(KERN_ERR "kblocker: not updating /etc/hosts, read failed: %d\n",
		       ret);
		goto out_close;
	}
	base = hosts_base_len(buf, len);

	tsize = sizeof(HOSTS_MARKER) + 4;
	for (i = 0; i < nd; i++)
		tsize += 4 * strlen(doms[i]) + 48;
	tail = kmalloc(tsize, GFP_KERNEL);
	if (!tail) {
		ret = -ENOMEM;
		goto out_close;
	}

	tlen = scnprintf(tail, tsize, "\n\n%s\n", HOSTS_MARKER);
	for (i = 0; i < nd; i++)
		tlen += scnprintf(tail + tlen, tsize - tlen,
				  "0.0.0.0 %s\n:: %s\n0.0.0.0 www.%s\n:: www.%s\n",
				  doms[i], doms[i], doms[i], doms[i]);
	tlen += scnprintf(tail + tlen, tsize - tlen, "\n");

	ret = hosts_write_tail(file, base, tail, tlen);
	if (!ret)
		printk(KERN_DEBUG "kblocker: updated hosts file with %d domains\n", nd);

out_close:
	filp_close(file, NULL);
out_free:
	kfree(tail);
	kvfree(buf);
	kfree(doms);
	return ret;
}

static struct kb_install *find_install(const struct inode *inode)
{
	int i;

	for (i = 0; i < MAX_INSTALLS; i++)
		if (smp_load_acquire(&installs[i].inode) == inode)
			return &installs[i];
	return NULL;
}

static int kb_permission(struct mnt_idmap *idmap, struct inode *inode, int mask)
{
	struct kb_install *ins;
	int ret;

	atomic_inc(&hook_inflight);
	ins = find_install(inode);
	if (ins && READ_ONCE(protect_active) && (mask & (MAY_WRITE | MAY_APPEND)))
		ret = -EPERM;
	else if (ins && ins->orig_i_op->permission)
		ret = ins->orig_i_op->permission(idmap, inode, mask);
	else
		ret = generic_permission(idmap, inode, mask);
	atomic_dec(&hook_inflight);
	return ret;
}

static int kb_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
		      struct iattr *attr)
{
	struct kb_install *ins;
	int ret;

	atomic_inc(&hook_inflight);
	ins = find_install(d_inode(dentry));
	if (!ins)
		ret = -EBUSY;	/* raced with protection_disable() */
	else if (READ_ONCE(protect_active))
		ret = -EPERM;
	else if (ins->orig_i_op->setattr)
		ret = ins->orig_i_op->setattr(idmap, dentry, attr);
	else
		ret = simple_setattr(idmap, dentry, attr);
	atomic_dec(&hook_inflight);
	return ret;
}

static int kb_fileattr_set(struct mnt_idmap *idmap, struct dentry *dentry,
			   kb_fileattr_t *fa)
{
	struct kb_install *ins;
	int ret;

	atomic_inc(&hook_inflight);
	ins = find_install(d_inode(dentry));
	if (!ins)
		ret = -EBUSY;
	else if (READ_ONCE(protect_active))
		ret = -EPERM;
	else
		ret = ins->orig_i_op->fileattr_set(idmap, dentry, fa);
	atomic_dec(&hook_inflight);
	return ret;
}

static void point_iop(struct inode *inode, const struct inode_operations *op)
{
	WRITE_ONCE(*(const struct inode_operations **)&inode->i_op, op);
	/* Without this, inodes whose fs has no ->permission keep taking the
	 * cached generic_permission fast path and never call our hook. */
	spin_lock(&inode->i_lock);
	inode->i_opflags &= ~IOP_FASTPERM;
#ifdef IOP_FASTPERM_MAY_EXEC
	inode->i_opflags &= ~IOP_FASTPERM_MAY_EXEC;
#endif
	spin_unlock(&inode->i_lock);
}

/* Caller holds protect_lock */
static void protect_inode(struct inode *inode, unsigned int flag,
			  const char *path)
{
	struct kb_install *ins = find_install(inode);
	struct inode_operations *custom;
	int i;

	inode_lock(inode);
	if (ins) {
		if (inode->i_op != ins->custom_i_op)
			point_iop(inode, ins->custom_i_op);
		goto set_flag;
	}

	for (i = 0; i < MAX_INSTALLS && installs[i].inode; i++)
		;
	if (i == MAX_INSTALLS) {
		printk(KERN_WARNING "kblocker: too many inodes, not protecting %s\n",
		       path);
		goto out;
	}

	custom = kmemdup(inode->i_op, sizeof(*custom), GFP_KERNEL);
	if (!custom)
		goto out;
	custom->permission = kb_permission;
	custom->setattr = kb_setattr;
	if (inode->i_op->fileattr_set)
		custom->fileattr_set = kb_fileattr_set;

	ins = &installs[i];
	ins->orig_i_op = inode->i_op;
	ins->custom_i_op = custom;
	ins->flag = flag;
	ins->we_set_flag = false;
	ihold(inode);
	smp_store_release(&ins->inode, inode);
	point_iop(inode, custom);

set_flag:
	if (!(inode->i_flags & ins->flag)) {
		inode_set_flags(inode, ins->flag, ins->flag);
		ins->we_set_flag = true;
	}
out:
	inode_unlock(inode);
}

/* Caller holds protect_lock */
static void protect_targets(void)
{
	struct path kp;
	int i;

	for (i = 0; i < num_targets; i++) {
		if (kern_path(targets[i].path, LOOKUP_FOLLOW, &kp))
			continue;
		if (d_is_reg(kp.dentry))
			protect_inode(d_inode(kp.dentry), targets[i].flag,
				      targets[i].path);
		path_put(&kp);
	}
}

static void do_protect_work(struct work_struct *work)
{
	mutex_lock(&protect_lock);
	if (protect_active) {
		/* Re-resolve: picks up files recreated or bind-mounted over */
		protect_targets();
		mod_timer(&protect_timer,
			  jiffies + msecs_to_jiffies(PROTECT_INTERVAL_MS));
	}
	mutex_unlock(&protect_lock);
}

static void protect_callback(struct timer_list *t)
{
	schedule_work(&protect_work);
}

void protection_enable(void)
{
	mutex_lock(&protect_lock);
	WRITE_ONCE(protect_active, true);
	protect_targets();
	mod_timer(&protect_timer, jiffies + msecs_to_jiffies(PROTECT_INTERVAL_MS));
	mutex_unlock(&protect_lock);
}

void protection_disable(void)
{
	int i;

	mutex_lock(&protect_lock);
	WRITE_ONCE(protect_active, false);
	mutex_unlock(&protect_lock);

	timer_delete_sync(&protect_timer);
	cancel_work_sync(&protect_work);
	timer_delete_sync(&protect_timer);

	mutex_lock(&protect_lock);
	for (i = 0; i < MAX_INSTALLS; i++) {
		struct kb_install *ins = &installs[i];
		struct inode *inode = ins->inode;

		if (!inode)
			continue;
		inode_lock(inode);
		if (ins->we_set_flag)
			inode_set_flags(inode, 0, ins->flag);
		if (inode->i_op == ins->custom_i_op)
			point_iop(inode, ins->orig_i_op);
		inode_unlock(inode);
	}

	/* Wait out path walks that loaded a custom table before we restored
	 * the original, and hook calls already running. */
	synchronize_rcu();
	while (atomic_read(&hook_inflight))
		msleep(1);
	synchronize_rcu();

	for (i = 0; i < MAX_INSTALLS; i++) {
		struct kb_install *ins = &installs[i];
		struct inode *inode = ins->inode;

		if (!inode)
			continue;
		WRITE_ONCE(ins->inode, NULL);
		kfree(ins->custom_i_op);
		ins->custom_i_op = NULL;
		ins->orig_i_op = NULL;
		iput(inode);
	}
	mutex_unlock(&protect_lock);
}

int protection_count(void)
{
	int i, n = 0;

	for (i = 0; i < MAX_INSTALLS; i++)
		if (READ_ONCE(installs[i].inode))
			n++;
	return n;
}

static void add_target(const char *path, unsigned int flag)
{
	if (num_targets >= MAX_PROTECTED_PATHS)
		return;
	strscpy(targets[num_targets].path, path, sizeof(targets[0].path));
	targets[num_targets].flag = flag;
	num_targets++;
}

void protection_init(void)
{
	char ko_path[256];

	INIT_WORK(&protect_work, do_protect_work);
	timer_setup(&protect_timer, protect_callback, 0);

	snprintf(ko_path, sizeof(ko_path),
		 "/lib/modules/%s/extra/kblocker.ko", utsname()->release);
	add_target(ko_path, S_IMMUTABLE);
	snprintf(ko_path, sizeof(ko_path),
		 "/lib/modules/%s/updates/dkms/kblocker.ko", utsname()->release);
	add_target(ko_path, S_IMMUTABLE);
	add_target("/etc/modules-load.d/kblocker.conf", S_IMMUTABLE);
	add_target("/etc/hosts", S_IMMUTABLE);
	/* Append-only: the kernel keeps appending remaining-time records */
	add_target(STATE_FILE, S_APPEND);
}
