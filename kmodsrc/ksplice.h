struct ksplice_reloc {
	const char *sym_name;
	unsigned long blank_addr;
	long blank_offset;
	unsigned long num_sym_addrs;
	const unsigned long *sym_addrs;
	int pcrel;
	long addend;
	int size;
	long dst_mask;
	unsigned int rightshift;
};

struct ksplice_size {
	const char *name;
	unsigned long size;
	unsigned long thismod_addr;
	unsigned long num_sym_addrs;
	const unsigned long *sym_addrs;
};

struct ksplice_patch {
	const char *oldstr;
	unsigned long oldaddr;
	unsigned long repladdr;
	char saved[5];
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

struct module_pack {
	const char *name;
	const char *kid;
	struct update_bundle *bundle;
	const char *target_name;
	struct module *target;
	unsigned long map_printk;
	struct module *primary;
	const struct ksplice_reloc *primary_relocs, *primary_relocs_end;
	const struct ksplice_size *primary_sizes, *primary_sizes_end;
	const struct ksplice_reloc *helper_relocs, *helper_relocs_end;
	const struct ksplice_size *helper_sizes, *helper_sizes_end;
	struct ksplice_patch *patches, *patches_end;
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

int init_ksplice_module(struct module_pack *pack);
void cleanup_ksplice_module(struct module_pack *pack);

#endif /* __KERNEL__ */
