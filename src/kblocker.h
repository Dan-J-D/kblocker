#ifndef _KBLOCKER_H
#define _KBLOCKER_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/netfilter.h>
#include <linux/workqueue.h>

#define MAX_IPS_V4 4096
#define MAX_IPS_V6 1024
#define PROTECT_INTERVAL_MS 1000
#define MAX_PROTECTED_PATHS 8
#define MAX_DOMAINS 64
#define MAX_DOMAIN_LEN 256
#define STATE_FILE "/var/lib/kblocker/state"
#define HOSTS_MARKER "# kblocker managed entries - do not edit manually"
#define HOSTS_MAX_SIZE (1024 * 1024)

extern __be32 *blocked_ips_v4;
extern int blocked_count_v4;
extern struct in6_addr *blocked_ips_v6;
extern int blocked_count_v6;
extern char blocked_domains[MAX_DOMAINS][MAX_DOMAIN_LEN];
extern int blocked_domain_count;
extern bool allow_unload;
extern u8 unload_key[16];
extern u8 key_hash[32];
extern bool state_restored;
extern bool pgp_active;
extern bool enabled;
extern u64 expiry_seconds;
extern bool enable_timer_active;
extern bool timer_active;
extern bool kblocker_bypass_protection;
extern bool ipv4_registered;
extern bool forward_registered;
extern struct nf_hook_ops nfho_out;
extern struct nf_hook_ops nfho_forward;
extern struct kobject *kblocker_kobj;
extern struct timer_list enable_timer;
extern struct timer_list protect_timer;
extern struct work_struct kb_disable_work;
extern struct work_struct kb_protect_work;

extern u8 pgp_key[16];
extern bool pgp_key_consumed;
extern atomic_t ref_taken;
extern spinlock_t ip_list_lock;

struct protected_file {
	char path[256];
	bool exists;
	struct inode *inode;
	const struct inode_operations *orig_i_op;
	struct inode_operations *custom_i_op;
};

extern struct protected_file protected_files[MAX_PROTECTED_PATHS];
extern int num_protected_files;

bool ct_memcmp_eq(const u8 *a, const u8 *b, size_t size);
unsigned int kblocker_hook(void *priv, struct sk_buff *skb,
			   const struct nf_hook_state *state);
unsigned int kblocker_hook_v4(void *priv, struct sk_buff *skb,
			      const struct nf_hook_state *state);
unsigned int kblocker_hook_v6(void *priv, struct sk_buff *skb,
			      const struct nf_hook_state *state);

void enable_blocking(unsigned int seconds);
void disable_blocking(void);
void do_disable_work(struct work_struct *work);
void generate_unload_key(void);
void clear_hosts_from_kernel(void);
int update_hosts_file(void);
void log_blocklist_on_disable(void);

int hex_val(char c);
int hex_decode(const char *s, u8 *out, int count);
u64 remaining_seconds(void);
void do_restore(const u8 *hash, u64 expiry_ts);
void try_restore_state_from_disk(void);

char *hosts_read_all(struct file *f, loff_t *out_len);
int setup_file_protection(void);
void cleanup_file_protection(void);

void enable_timer_cb(struct timer_list *t);
void do_disable_work(struct work_struct *work);
void do_protect_work(struct work_struct *work);
void protect_callback(struct timer_list *t);

void kblocker_cleanup_netfilter(void);

ssize_t unblock_store(struct kobject *kobj, struct kobj_attribute *attr,
		      const char *buf, size_t count);
ssize_t unload_key_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
ssize_t pgp_active_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
ssize_t pgp_active_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count);
ssize_t disable_store(struct kobject *kobj, struct kobj_attribute *attr,
		      const char *buf, size_t count);

#endif