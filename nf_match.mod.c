#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x14522340, "module_layout" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0xfa2e111f, "slab_buffer_size" },
	{ 0xd691cba2, "malloc_sizes" },
	{ 0x105e2727, "__tracepoint_kmalloc" },
	{ 0x7edc1537, "device_destroy" },
	{ 0xfa0d49c7, "__register_chrdev" },
	{ 0xca975b7a, "nf_register_hook" },
	{ 0x8ce3169d, "netlink_kernel_create" },
	{ 0xde0bdcff, "memset" },
	{ 0xe4c1df3e, "_read_lock_bh" },
	{ 0xf85ccdae, "kmem_cache_alloc_notrace" },
	{ 0xea147363, "printk" },
	{ 0xd4defbf4, "netlink_kernel_release" },
	{ 0xb4390f9a, "mcount" },
	{ 0x2d2cf7d, "device_create" },
	{ 0x27418d14, "netlink_unicast" },
	{ 0x1c740bd6, "init_net" },
	{ 0x25421969, "__alloc_skb" },
	{ 0x3d75cbcf, "kfree_skb" },
	{ 0x49da9a9a, "_read_unlock_bh" },
	{ 0x50787d0f, "netlink_ack" },
	{ 0x7e5a6ea3, "nf_unregister_hook" },
	{ 0x3aa1dbcf, "_spin_unlock_bh" },
	{ 0x37a0cba, "kfree" },
	{ 0xe06bb002, "class_destroy" },
	{ 0x93cbd1ec, "_spin_lock_bh" },
	{ 0x207b7e2c, "skb_put" },
	{ 0xa2654165, "__class_create" },
	{ 0x3302b500, "copy_from_user" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "62B15FB7A718CD14589C438");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 3,
};
