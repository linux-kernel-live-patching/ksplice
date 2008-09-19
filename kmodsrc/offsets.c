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

const struct table_section table_sections[]
    __attribute__((section(".ksplice_table_sections"))) = {
#ifdef CONFIG_X86
	{
		.sect = ".altinstructions",
		.entry_size = sizeof(struct alt_instr),
		.entry_align = __alignof__(struct alt_instr),
		.addr_offset = offsetof(struct alt_instr, instr),
	},
#endif /* CONFIG_X86 */
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
