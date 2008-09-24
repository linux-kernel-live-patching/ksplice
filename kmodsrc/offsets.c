#include <linux/kernel.h>
#include <linux/version.h>

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
/* 98de032b681d8a7532d44dfc66aa5c0c1c755a9d was after 2.6.21 */
#define paravirt_patch_site paravirt_patch
#endif /* LINUX_VERSION_CODE */
#endif /* CONFIG_PARAVIRT */

#include <asm/uaccess.h>
#include "offsets.h"

const struct ksplice_config config
    __attribute__((section(".ksplice_config"))) = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
/* eb8f689046b857874e964463619f09df06d59fad was after 2.6.24 */
/* Introduction of .cpuinit, .devinit, .meminit sections */
#ifndef CONFIG_HOTPLUG
	.ignore_devinit = 1,
#endif /* !CONFIG_HOTPLUG */
#ifndef CONFIG_HOTPLUG_CPU
	.ignore_cpuinit = 1,
#endif /* !CONFIG_HOTPLUG_CPU */
#ifndef CONFIG_MEMORY_HOTPLUG
	.ignore_meminit = 1,
#endif /* !CONFIG_MEMORY_HOTPLUG */
#endif /* LINUX_VERSION_CODE */
};

const struct table_section table_sections[]
    __attribute__((section(".ksplice_table_sections"))) = {
#ifdef CONFIG_X86
	{
		.sect = ".altinstructions",
		.entry_size = sizeof(struct alt_instr),
		.entry_align = __alignof__(struct alt_instr),
		.addr_offset = offsetof(struct alt_instr, instr),
		.other_sect = ".altinstr_replacement",
		.other_offset = offsetof(struct alt_instr, replacement),
	},
#endif /* CONFIG_X86 */
#if defined CONFIG_GENERIC_BUG && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
	{
		.sect = "__bug_table",
		.entry_size = sizeof(struct bug_entry),
		.entry_align = __alignof__(struct bug_entry),
		.addr_offset = offsetof(struct bug_entry, bug_addr),
	},
#else /* !CONFIG_GENERIC_BUG || LINUX_VERSION_CODE < */
/* 91768d6c2bad0d2766a166f13f2f57e197de3458 was after 2.6.19 */
#endif /* CONFIG_GENERIC_BUG && LINUX_VERSION_CODE */
	{
		.sect = "__ex_table",
		.entry_size = sizeof(struct exception_table_entry),
		.entry_align = __alignof__(struct exception_table_entry),
		.addr_offset = offsetof(struct exception_table_entry, insn),
		.other_sect = ".fixup",
		.other_offset = offsetof(struct exception_table_entry, fixup),
	},
#ifdef CONFIG_PARAVIRT
	{
		.sect = ".parainstructions",
		.entry_size = sizeof(struct paravirt_patch_site),
		.entry_align = __alignof__(struct paravirt_patch_site),
		.addr_offset = offsetof(struct paravirt_patch_site, instr),
	},
#endif /* CONFIG_PARAVIRT */
	{
		.sect = ".smp_locks",
		.entry_size = sizeof(u8 *),
		.entry_align = __alignof__(u8 *),
		.addr_offset = 0,
	},
};
