#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
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

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x92997ed8, "_printk" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x4dfa8d4b, "mutex_lock" },
	{ 0x3213f038, "mutex_unlock" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0xbcf67ef9, "cdev_init" },
	{ 0xacc93d51, "cdev_add" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0xec37920b, "__class_create" },
	{ 0x9c88a22f, "cdev_del" },
	{ 0xece70a6c, "device_create" },
	{ 0x3edbf426, "class_destroy" },
	{ 0x89e354cb, "kmalloc_caches" },
	{ 0xd752212e, "kmalloc_trace" },
	{ 0xe61f2f6, "device_destroy" },
	{ 0xcefb0c9f, "__mutex_init" },
	{ 0x37a0cba, "kfree" },
	{ 0x53e23810, "current_task" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xf5b00aab, "boot_cpu_data" },
	{ 0x17de3d5, "nr_cpu_ids" },
	{ 0x9e683f75, "__cpu_possible_mask" },
	{ 0xc60d0620, "__num_online_cpus" },
	{ 0x21ea5251, "__bitmap_weight" },
	{ 0x40c7247c, "si_meminfo" },
	{ 0x8d522714, "__rcu_read_lock" },
	{ 0x68ddb0dc, "init_task" },
	{ 0x2469810f, "__rcu_read_unlock" },
	{ 0xc4f0da12, "ktime_get_with_offset" },
	{ 0x65929cae, "ns_to_timespec64" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x4963cf87, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "90949DDD6CF77794E18B80F");
