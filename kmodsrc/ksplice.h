#include <linux/types.h>

/**
 * struct ksplice_symbol - Ksplice's analogue of an ELF symbol
 * @name:	The ELF name of the symbol
 * @label:	A unique Ksplice name for the symbol
 **/
struct ksplice_symbol {
	const char *name;
	const char *label;
/* private: */
	struct list_head *vals;
	unsigned long value;
};

/**
 * struct ksplice_reloc - Ksplice's analogue of an ELF relocation
 * @blank_addr:		The address of the relocation's storage unit
 * @symbol:		The ksplice_symbol associated with this relocation
 * @howto:		The information regarding the relocation type
 * @addend:		The ELF addend of the relocation
 **/
struct ksplice_reloc {
	unsigned long blank_addr;
	struct ksplice_symbol *symbol;
	const struct ksplice_reloc_howto *howto;
	long insn_addend;
	long target_addend;
};

enum ksplice_reloc_howto_type {
	KSPLICE_HOWTO_RELOC,
	KSPLICE_HOWTO_RELOC_PATCH,
	KSPLICE_HOWTO_DATE,
	KSPLICE_HOWTO_TIME,
	KSPLICE_HOWTO_BUG,
	KSPLICE_HOWTO_EXTABLE,
};

/**
 * struct ksplice_reloc_howto - Ksplice's relocation type information
 * @pcrel:		Is the relocation PC relative?
 * @size:		The size, in bytes, of the item to be relocated
 * @dst_mask:		Bitmask for which parts of the instruction or data are
 * 			replaced with the relocated value
 * 			(based on dst_mask from GNU BFD's reloc_howto_struct)
 * @rightshift:		The value the final relocation is shifted right by;
 * 			used to drop unwanted data from the relocation
 * 			(based on rightshift from GNU BFD's reloc_howto_struct)
 * @signed_addend:	Should the addend be interpreted as a signed value?
 **/
struct ksplice_reloc_howto {
	enum ksplice_reloc_howto_type type;
	int pcrel;
	int size;
	long dst_mask;
	unsigned int rightshift;
	int signed_addend;
};

#if BITS_PER_LONG == 32
#define KSPLICE_CANARY 0x77777777UL
#elif BITS_PER_LONG == 64
#define KSPLICE_CANARY 0x7777777777777777UL
#endif /* BITS_PER_LONG */

/**
 * struct ksplice_section - Ksplice's analogue of an ELF section
 * @symbol:		The ksplice_symbol associated with this section
 * @size:		The length, in bytes, of this section
 * @address:		The address of the section
 * @flags:		Specifies whether this section contains text, read-only
 * 			data, or data
 **/
struct ksplice_section {
	struct ksplice_symbol *symbol;
	unsigned long address;
	unsigned long size;
	unsigned int flags;
	const unsigned char **match_map;
};
#define KSPLICE_SECTION_TEXT 0x00000001
#define KSPLICE_SECTION_RODATA 0x00000002
#define KSPLICE_SECTION_DATA 0x00000004
#define KSPLICE_SECTION_STRING 0x00000008
#define KSPLICE_SECTION_MATCHED 0x10000000

#define MAX_TRAMPOLINE_SIZE 5

enum ksplice_patch_type {
	KSPLICE_PATCH_TEXT,
	KSPLICE_PATCH_BUGLINE,
	KSPLICE_PATCH_DATA,
	KSPLICE_PATCH_EXPORT,
};

/**
 * struct ksplice_patch - A replacement that Ksplice should perform
 * @oldaddr:		The address of the obsolete function or structure
 * @repladdr:		The address of the replacement function
 * @type:		The type of the ksplice patch
 * @size:		The size of the patch
 * @contents:		The bytes to be installed at oldaddr
 * @vaddr		The address of the page mapping used to write at oldaddr
 * @saved:		The bytes originally at oldaddr which were
 * 			overwritten by the patch
 **/
struct ksplice_patch {
	unsigned long oldaddr;
	unsigned long repladdr;
	enum ksplice_patch_type type;
	unsigned int size;
	void *contents;
/* private: */
	void *vaddr;
	void *saved;
};

#ifdef KSPLICE_STANDALONE
struct ksplice_system_map {
	const char *label;
	unsigned long nr_candidates;
	const unsigned long *candidates;
};
#endif /* KSPLICE_STANDALONE */

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/stringify.h>
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

#define _PASTE(x, y) x##y
#define PASTE(x, y) _PASTE(x, y)
#define KSPLICE_UNIQ(s) PASTE(s##_, KSPLICE_MID)
#define KSPLICE_KID_UNIQ(s) PASTE(s##_, KSPLICE_KID)
#ifdef KSPLICE_STANDALONE
#define init_ksplice_pack KSPLICE_KID_UNIQ(init_ksplice_pack)
#define cleanup_ksplice_pack KSPLICE_KID_UNIQ(cleanup_ksplice_pack)
#endif

/**
 * struct ksplice_module_list_entry - A record of a Ksplice pack's target
 * @target:	A module that is patched
 * @primary:	A Ksplice module that patches target
 **/
struct ksplice_module_list_entry {
	struct module *target;
	struct module *primary;
/* private: */
	struct list_head list;
};

/* List of all ksplice modules and the module they patch */
extern struct list_head ksplice_module_list;

/**
 * struct ksplice_pack - Data for one module modified by a Ksplice update
 * @name:			The name of the primary module for the pack
 * @kid:			The Ksplice unique identifier for the pack
 * @target_name:		The name of the module modified by the pack
 * @primary:			The primary module associated with the pack
 * @primary_relocs:		The relocations for the primary module
 * @primary_relocs_end:		The end pointer for primary_relocs
 * @primary_sections:		The sections in the primary module
 * @primary_sections_end:	The end pointer for primary_sections array
 * @helper_relocs:		The relocations for the helper module
 * @helper_relocs_end:		The end pointer for helper_relocs array
 * @helper_sections:		The sections in the helper module
 * @helper_sections_end:	The end pointer for helper_sections array
 * @patches:			The function replacements in the pack
 * @patches_end:		The end pointer for patches array
 * @update:			The atomic update the pack is part of
 * @target:			The module modified by the pack
 * @labelvals:			The mapping between Ksplice symbol labels and
 *				their values
 * @safety_records:		The ranges of addresses that must not be on a
 *				kernel stack for the patch to apply safely
 **/
struct ksplice_pack {
	const char *name;
	const char *kid;
	const char *target_name;
#ifdef KSPLICE_STANDALONE
	unsigned long map_printk;
#endif /* KSPLICE_STANDALONE */
	struct module *primary;
	struct ksplice_reloc *primary_relocs, *primary_relocs_end;
	const struct ksplice_section *primary_sections, *primary_sections_end;
	struct ksplice_symbol *primary_symbols, *primary_symbols_end;
	struct ksplice_reloc *helper_relocs, *helper_relocs_end;
	struct ksplice_section *helper_sections, *helper_sections_end;
	struct ksplice_symbol *helper_symbols, *helper_symbols_end;
	struct ksplice_patch *patches, *patches_end;
	const typeof(int (*)(void)) *pre_apply, *pre_apply_end, *check_apply,
	    *check_apply_end;
	const typeof(void (*)(void)) *apply, *apply_end, *post_apply,
	    *post_apply_end, *fail_apply, *fail_apply_end;
	const typeof(int (*)(void)) *pre_reverse, *pre_reverse_end,
	    *check_reverse, *check_reverse_end;
	const typeof(void (*)(void)) *reverse, *reverse_end, *post_reverse,
	    *post_reverse_end, *fail_reverse, *fail_reverse_end;
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	struct paravirt_patch_site
	    *primary_parainstructions, *primary_parainstructions_end,
	    *helper_parainstructions, *helper_parainstructions_end;
#endif /* KSPLICE_NEED_PARAINSTRUCTIONS */
#ifdef KSPLICE_STANDALONE
	struct ksplice_system_map
	    *primary_system_map, *primary_system_map_end,
	    *helper_system_map, *helper_system_map_end;
#endif /* KSPLICE_STANDALONE */
/* private: */
	struct ksplice_module_list_entry module_list_entry;
	struct update *update;
	struct module *target;
	struct list_head temp_labelvals;
	struct list_head safety_records;
	struct list_head list;
};


/**
 * init_ksplice_pack() - Initializes a pack
 * @pack:	The pack to be initialized.  All of the public fields of the
 * 		pack and its associated data structures should be populated
 * 		before this function is called.  The values of the private
 * 		fields will be ignored.
 **/
int init_ksplice_pack(struct ksplice_pack *pack);

/**
 * cleanup_ksplice_pack() - Cleans up a pack
 * @pack:	The pack to be cleaned up
 */
void cleanup_ksplice_pack(struct ksplice_pack *pack);

#endif /* __KERNEL__ */
