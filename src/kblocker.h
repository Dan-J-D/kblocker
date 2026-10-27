#ifndef _KBLOCKER_H
#define _KBLOCKER_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/netfilter.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include "parse.h"

/* struct mnt_idmap in inode_operations, fileattr_set, sha256() library */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
#error "kblocker requires Linux 6.3 or newer"
#endif

#define MAX_IPS_V4 4096
#define MAX_IPS_V6 1024
#define PROTECT_INTERVAL_MS 1000
#define MAX_PROTECTED_PATHS 8
#define MAX_DOMAINS 64
#ifdef KBLOCKER_DEBUG
/* Short sessions under a fuzzer still reach the periodic save */
#define STATE_SAVE_INTERVAL_S 2
#else
#define STATE_SAVE_INTERVAL_S 60
#endif
#define HOSTS_MAX_SIZE (1024 * 1024)
/* Upper bound for a session; keeps arithmetic far from overflow */
#define MAX_SESSION_SECONDS (10ULL * 365 * 24 * 3600)

extern __be32 *blocked_ips_v4;
extern int blocked_count_v4;
extern struct in6_addr *blocked_ips_v6;
extern int blocked_count_v6;
extern char blocked_domains[MAX_DOMAINS][MAX_DOMAIN_LEN];
extern int blocked_domain_count;
extern spinlock_t ip_list_lock;

/*
 * Session state. Writers hold kb_lock; the netfilter hooks and the
 * show handlers read individual fields with READ_ONCE.
 */
extern struct mutex kb_lock;
extern bool allow_unload;
extern u8 unload_key[16];
extern u8 key_hash[32];
extern u8 pgp_key[16];
extern bool pgp_key_consumed;
extern bool state_restored;
extern bool pgp_active;
extern bool enabled;
extern atomic_t ref_taken;

extern struct kobject *kblocker_kobj;

/* Protected file paths. Fixed in release builds; debug builds (make
 * KBLOCKER_DEBUG=1) take them as module parameters so fuzzers can point
 * them at files visible inside their sandboxes. */
extern char *kb_hosts_file;
extern char *kb_state_file;
extern char *kb_modconf_file;

/* Release kb_lock; debug builds first check the session invariants */
void kb_unlock(void);

/* key.c */
bool ct_memcmp_eq(const u8 *a, const u8 *b, size_t size);
void generate_unload_key(void);
ssize_t unblock_store(struct kobject *kobj, struct kobj_attribute *attr,
		      const char *buf, size_t count);
ssize_t unload_key_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
ssize_t pgp_active_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
ssize_t pgp_active_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count);
ssize_t disable_store(struct kobject *kobj, struct kobj_attribute *attr,
		      const char *buf, size_t count);

/* state.c — callers hold kb_lock unless noted */
void session_init(void);
void session_exit(void);
int enable_blocking(u64 seconds);
void disable_blocking(void);
u64 remaining_seconds(void);
void try_restore_state_from_disk(void);
#ifdef KBLOCKER_DEBUG
void kb_debug_reboot(void);
#endif
void state_file_clear(void);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
struct file_kattr;
typedef struct file_kattr kb_fileattr_t;
#else
struct fileattr;
typedef struct fileattr kb_fileattr_t;
#endif

/* main.c */
int snapshot_domains(char (*dst)[MAX_DOMAIN_LEN]);

/* file_protection.c */
char *kb_read_file(struct file *f, loff_t *out_len);
int update_hosts_file(void);
void clear_hosts_from_kernel(void);
void protection_init(void);
void protection_enable(void);
void protection_disable(void);
int protection_count(void);

/* netfilter.c */
int kblocker_register_netfilter(void);
void kblocker_cleanup_netfilter(void);
void log_blocklist_on_disable(void);

#endif
