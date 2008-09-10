struct ksplice_symbol {
	const char *name;
	const char *label;
	unsigned long nr_candidates;
	const unsigned long *candidates;
};

struct ksplice_reloc {
	unsigned long blank_addr;
	long blank_offset;
	const struct ksplice_symbol *symbol;
	int pcrel;
	long addend;
	int size;
	long dst_mask;
	unsigned int rightshift;
	int signed_addend;
};

struct ksplice_size {
	const struct ksplice_symbol *symbol;
	unsigned long size;
	unsigned long thismod_addr;
	unsigned int flags;
};
#define KSPLICE_SIZE_TEXT 0x00000001
#define KSPLICE_SIZE_RODATA 0x00000002
#define KSPLICE_SIZE_DATA 0x00000004

#define MAX_TRAMPOLINE_SIZE 5

struct ksplice_patch {
	const char *label;
	unsigned long oldaddr;
	unsigned long repladdr;
	char saved[MAX_TRAMPOLINE_SIZE];
	char trampoline[MAX_TRAMPOLINE_SIZE];
	unsigned int size;
};

struct ksplice_export {
	const char *name;
	const char *saved_name;
	const char *new_name;
	struct kernel_symbol *sym;
};

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/version.h>

#if defined(CONFIG_PARAVIRT) && defined(CONFIG_X86_64) &&	\
    LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25) &&		\
    LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
/* Linux 2.6.25 and 2.6.26 apply paravirt replacements to the core
 * kernel but not modules on x86-64.  If we are patching the core
 * kernel, we need to apply the same replacements to our update
 * modules in order for run-pre matching to succeed.
 */
#define KSPLICE_NEED_PARAINSTRUCTIONS 1
#endif /* KSPLICE_NEED_PARAINSTRUCTIONS */

#undef _STR
#define _STR(x) #x
#undef STR
#define STR(x) _STR(x)
#define _PASTE(x, y) x##y
#define PASTE(x, y) _PASTE(x, y)
#define KSPLICE_UNIQ(s) PASTE(s##_, KSPLICE_MID)
#define KSPLICE_KID_UNIQ(s) PASTE(s##_, KSPLICE_KID)
#ifdef KSPLICE_STANDALONE
#define init_ksplice_module KSPLICE_KID_UNIQ(init_ksplice_module)
#define cleanup_ksplice_module KSPLICE_KID_UNIQ(cleanup_ksplice_module)
#endif

struct ksplice_module_list_entry {
	struct module *target;
	struct module *primary;
	struct list_head list;
};

/* List of all ksplice modules and the module they patch */
extern struct list_head ksplice_module_list;

struct ksplice_pack {
	const char *name;
	const char *kid;
	struct update *update;
	const char *target_name;
	struct module *target;
	unsigned long map_printk;
	struct module *primary;
	struct ksplice_module_list_entry module_list_entry;
	const struct ksplice_reloc *primary_relocs, *primary_relocs_end;
	const struct ksplice_size *primary_sizes, *primary_sizes_end;
	const struct ksplice_reloc *helper_relocs, *helper_relocs_end;
	const struct ksplice_size *helper_sizes, *helper_sizes_end;
	struct ksplice_patch *patches, *patches_end;
	struct ksplice_export *exports, *exports_end;
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	struct paravirt_patch_site
	    *primary_parainstructions, *primary_parainstructions_end,
	    *helper_parainstructions, *helper_parainstructions_end;
#endif /* KSPLICE_NEED_PARAINSTRUCTIONS */
	struct list_head reloc_addrmaps;
	struct list_head reloc_namevals;
	struct list_head safety_records;
	struct list_head list;
};

int init_ksplice_module(struct ksplice_pack *pack);
void cleanup_ksplice_module(struct ksplice_pack *pack);

#endif /* __KERNEL__ */
