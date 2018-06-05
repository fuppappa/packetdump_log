#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xb6fd8534, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xbdc6b187, __VMLINUX_SYMBOL_STR(cpu_tss) },
	{ 0x754d539c, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0xe1a164ff, __VMLINUX_SYMBOL_STR(filp_close) },
	{ 0xeae3dfd6, __VMLINUX_SYMBOL_STR(__const_udelay) },
	{ 0x4f553a6c, __VMLINUX_SYMBOL_STR(nf_register_hook) },
	{ 0x5c0442fd, __VMLINUX_SYMBOL_STR(acpi_gbl_FADT) },
	{ 0xa35eebf2, __VMLINUX_SYMBOL_STR(kern_path) },
	{ 0x1916e38c, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irqrestore) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x9e64fbfe, __VMLINUX_SYMBOL_STR(rtc_cmos_read) },
	{ 0xb6936ffe, __VMLINUX_SYMBOL_STR(_bcd2bin) },
	{ 0x3f20ca97, __VMLINUX_SYMBOL_STR(rtc_lock) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x680ec266, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irqsave) },
	{ 0xf1436e42, __VMLINUX_SYMBOL_STR(nf_unregister_hook) },
	{ 0x4f827917, __VMLINUX_SYMBOL_STR(vfs_write) },
	{ 0xec17ff3d, __VMLINUX_SYMBOL_STR(filp_open) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "0C41C18A9D4DBDC2A0DF88F");
