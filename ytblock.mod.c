#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x22755710, "filp_open" },
	{ 0x534ed5f3, "__msecs_to_jiffies" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0x40a621c5, "snprintf" },
	{ 0x49733ad6, "queue_work_on" },
	{ 0x6a16bd2c, "inode_set_flags" },
	{ 0x329fc928, "in6_pton" },
	{ 0xa53f4e29, "memcpy" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x6464d17c, "kernel_kobj" },
	{ 0x2352b148, "timer_delete_sync" },
	{ 0xc6a17655, "__module_get" },
	{ 0x3a260aac, "vfs_truncate" },
	{ 0xce01efee, "path_put" },
	{ 0xd272d446, "__fentry__" },
	{ 0xd0632e1b, "crypto_destroy_tfm" },
	{ 0xe8213e80, "_printk" },
	{ 0x329fc928, "in4_pton" },
	{ 0x5629a063, "strncasecmp" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x2520ea93, "refcount_warn_saturate" },
	{ 0xde338d9a, "_raw_spin_unlock_bh" },
	{ 0xd710adbf, "__kmalloc_large_noprof" },
	{ 0x9479a1e8, "strnlen" },
	{ 0xc6a17655, "module_put" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0xd70733be, "sized_strscpy" },
	{ 0x5c605c30, "nf_unregister_net_hook" },
	{ 0x02fbf427, "nf_register_net_hook" },
	{ 0xa59da3c0, "down_write" },
	{ 0xb1172073, "init_net" },
	{ 0xa59da3c0, "up_write" },
	{ 0x366ddfcc, "memchr" },
	{ 0x32feeafc, "mod_timer" },
	{ 0x5a1b475b, "sk_free" },
	{ 0x17545440, "strstr" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xd94efd11, "const_current_task" },
	{ 0x20550fb7, "crypto_shash_digest" },
	{ 0x75738bed, "panic" },
	{ 0xc6badcf4, "sysfs_create_group" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0x9332f4c1, "kern_path" },
	{ 0xa96ed8ce, "kernel_read" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x386e4ba3, "kmemdup_noprof" },
	{ 0x98115f5f, "__pskb_pull_tail" },
	{ 0xed8368be, "kobject_create_and_add" },
	{ 0x058c185a, "jiffies" },
	{ 0x3cf61928, "sysfs_remove_group" },
	{ 0x7a6661ca, "ktime_get_real_seconds" },
	{ 0xdd6830c7, "sprintf" },
	{ 0xa5c7582d, "strsep" },
	{ 0x13e72361, "filp_close" },
	{ 0xecd17989, "__kmalloc_cache_noprof" },
	{ 0x2d88a3ab, "cancel_work_sync" },
	{ 0x0a589842, "simple_strtoul" },
	{ 0xde338d9a, "_raw_spin_lock_bh" },
	{ 0x02f9bbf0, "timer_init_key" },
	{ 0xac62cf98, "tcp_done" },
	{ 0x224a53e7, "get_random_bytes" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0x43a349ca, "strlen" },
	{ 0x39286c61, "tcp_prot" },
	{ 0x0e435208, "crypto_alloc_shash" },
	{ 0x08bfc903, "kmalloc_caches" },
	{ 0xf6ed07f0, "kernel_write" },
	{ 0xaef1f20d, "system_wq" },
	{ 0x98b39dbb, "kobject_put" },
	{ 0xc669898f, "simple_strtoull" },
	{ 0x814e12e5, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0x22755710,
	0x534ed5f3,
	0xd710adbf,
	0x40a621c5,
	0x49733ad6,
	0x6a16bd2c,
	0x329fc928,
	0xa53f4e29,
	0xcb8b6ec6,
	0x6464d17c,
	0x2352b148,
	0xc6a17655,
	0x3a260aac,
	0xce01efee,
	0xd272d446,
	0xd0632e1b,
	0xe8213e80,
	0x329fc928,
	0x5629a063,
	0xbd03ed67,
	0xd272d446,
	0x2520ea93,
	0xde338d9a,
	0xd710adbf,
	0x9479a1e8,
	0xc6a17655,
	0x90a48d82,
	0xd70733be,
	0x5c605c30,
	0x02fbf427,
	0xa59da3c0,
	0xb1172073,
	0xa59da3c0,
	0x366ddfcc,
	0x32feeafc,
	0x5a1b475b,
	0x17545440,
	0xbd03ed67,
	0xd94efd11,
	0x20550fb7,
	0x75738bed,
	0xc6badcf4,
	0xe54e0a6b,
	0x9332f4c1,
	0xa96ed8ce,
	0xd272d446,
	0x386e4ba3,
	0x98115f5f,
	0xed8368be,
	0x058c185a,
	0x3cf61928,
	0x7a6661ca,
	0xdd6830c7,
	0xa5c7582d,
	0x13e72361,
	0xecd17989,
	0x2d88a3ab,
	0x0a589842,
	0xde338d9a,
	0x02f9bbf0,
	0xac62cf98,
	0x224a53e7,
	0xe4de56b4,
	0x43a349ca,
	0x39286c61,
	0x0e435208,
	0x08bfc903,
	0xf6ed07f0,
	0xaef1f20d,
	0x98b39dbb,
	0xc669898f,
	0x814e12e5,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"filp_open\0"
	"__msecs_to_jiffies\0"
	"__kmalloc_noprof\0"
	"snprintf\0"
	"queue_work_on\0"
	"inode_set_flags\0"
	"in6_pton\0"
	"memcpy\0"
	"kfree\0"
	"kernel_kobj\0"
	"timer_delete_sync\0"
	"__module_get\0"
	"vfs_truncate\0"
	"path_put\0"
	"__fentry__\0"
	"crypto_destroy_tfm\0"
	"_printk\0"
	"in4_pton\0"
	"strncasecmp\0"
	"__ref_stack_chk_guard\0"
	"__stack_chk_fail\0"
	"refcount_warn_saturate\0"
	"_raw_spin_unlock_bh\0"
	"__kmalloc_large_noprof\0"
	"strnlen\0"
	"module_put\0"
	"__ubsan_handle_out_of_bounds\0"
	"sized_strscpy\0"
	"nf_unregister_net_hook\0"
	"nf_register_net_hook\0"
	"down_write\0"
	"init_net\0"
	"up_write\0"
	"memchr\0"
	"mod_timer\0"
	"sk_free\0"
	"strstr\0"
	"random_kmalloc_seed\0"
	"const_current_task\0"
	"crypto_shash_digest\0"
	"panic\0"
	"sysfs_create_group\0"
	"__fortify_panic\0"
	"kern_path\0"
	"kernel_read\0"
	"__x86_return_thunk\0"
	"kmemdup_noprof\0"
	"__pskb_pull_tail\0"
	"kobject_create_and_add\0"
	"jiffies\0"
	"sysfs_remove_group\0"
	"ktime_get_real_seconds\0"
	"sprintf\0"
	"strsep\0"
	"filp_close\0"
	"__kmalloc_cache_noprof\0"
	"cancel_work_sync\0"
	"simple_strtoul\0"
	"_raw_spin_lock_bh\0"
	"timer_init_key\0"
	"tcp_done\0"
	"get_random_bytes\0"
	"__ubsan_handle_load_invalid_value\0"
	"strlen\0"
	"tcp_prot\0"
	"crypto_alloc_shash\0"
	"kmalloc_caches\0"
	"kernel_write\0"
	"system_wq\0"
	"kobject_put\0"
	"simple_strtoull\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "12A1C95EB87CAE3687FC722");
