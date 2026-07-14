#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/timer.h>
#include <linux/utsname.h>
#include <linux/workqueue.h>
#include <linux/version.h>
#include "kblocker.h"

static char ko_path[256];

static int hosts_clear_immutable(void)
{
	int i, was_set = 0;

	for (i = 0; i < num_protected_files; i++) {
		if (!protected_files[i].exists || !protected_files[i].inode)
			continue;
		inode_lock(protected_files[i].inode);
		if (protected_files[i].inode->i_flags & S_IMMUTABLE) {
			was_set = 1;
			inode_set_flags(protected_files[i].inode, 0, S_IMMUTABLE);
		}
		inode_unlock(protected_files[i].inode);
	}
	return was_set;
}

char *hosts_read_all(struct file *f, loff_t *out_len)
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

void clear_hosts_from_kernel(void)
{
	struct file *file;
	struct inode *inode;
	char *buf, *out, *p;
	loff_t len;
	ssize_t out_len, written;
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
		printk(KERN_DEBUG "kblocker: clear_hosts: marker not found\n");
		kfree(buf);
		filp_close(file, NULL);
		WRITE_ONCE(kblocker_bypass_protection, false);
		return;
	}

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
	written = kernel_write(file, out, out_len, &pos);
	if (written != out_len) {
		printk(KERN_DEBUG "kblocker: clear_hosts write failed (ret=%zd)\n", written);
		kfree(out);
		kfree(buf);
		filp_close(file, NULL);
		WRITE_ONCE(kblocker_bypass_protection, false);
		return;
	}

	inode = file_inode(file);
	if (inode) {
		int trunc_ret;
		inode_lock(inode);
		if (inode->i_flags & S_IMMUTABLE)
			inode_set_flags(inode, 0, S_IMMUTABLE);
		inode_unlock(inode);
		trunc_ret = vfs_truncate(&file->f_path, out_len);
		if (trunc_ret)
			printk(KERN_DEBUG "kblocker: clear_hosts truncate failed (ret=%d)\n", trunc_ret);
	}

	kfree(out);
	kfree(buf);
	filp_close(file, NULL);

	printk(KERN_DEBUG "kblocker: cleared hosts file entries\n");
	WRITE_ONCE(kblocker_bypass_protection, false);
}

int update_hosts_file(void)
{
	struct file *file;
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

	/* Truncate via the open file's own path (not kern_path, which may
	 * resolve to a different inode on overlay filesystems)
	 */
	{
		struct inode *in = file_inode(file);
		if (in) {
			inode_lock(in);
			if (in->i_flags & S_IMMUTABLE)
				inode_set_flags(in, 0, S_IMMUTABLE);
			inode_unlock(in);
			vfs_truncate(&file->f_path, pos);
			inode_lock(in);
			inode_set_flags(in, S_IMMUTABLE, S_IMMUTABLE);
			inode_unlock(in);
		}
	}

	kfree(out);
	filp_close(file, NULL);

	printk(KERN_DEBUG "kblocker: updated hosts file with %d domains\n", ndom);
	WRITE_ONCE(kblocker_bypass_protection, false);
	return 0;
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

	if (READ_ONCE(kblocker_bypass_protection))
		return 0;

	if ((mask & MAY_WRITE)) {
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
		/* Re-check bypass inside the lock: update_hosts_file may have set it
		 * while we were waiting for the lock on another CPU.
		 */
		if (READ_ONCE(kblocker_bypass_protection)) {
			inode_unlock(inode);
			goto put;
		}
		inode_set_flags(inode, S_IMMUTABLE, S_IMMUTABLE);
		printk(KERN_WARNING "kblocker: re-applied immutable flag on %s\n",
		       path);
	}
	inode_unlock(inode);

put:
	path_put(&kp);
}

void do_protect_work(struct work_struct *work)
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

void protect_callback(struct timer_list *t)
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

int setup_file_protection(void)
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

void cleanup_file_protection(void)
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