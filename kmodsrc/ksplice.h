struct ksplice_reloc {
	char *sym_name;
	unsigned long blank_addr;
	long blank_offset;
	unsigned long num_sym_addrs;
	unsigned long *sym_addrs;
	int pcrel;
	long addend;
	int size;
	long dst_mask;
	unsigned int rightshift;
};

struct ksplice_size {
	char *name;
	unsigned long size;
	unsigned long thismod_addr;
	unsigned long num_sym_addrs;
	unsigned long *sym_addrs;
};

struct ksplice_patch {
	char *oldstr;
	unsigned long oldaddr;
	unsigned long repladdr;
	char saved[5];
};

#ifdef __KERNEL__
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif /* CONFIG_DEBUG_FS */
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/version.h>

#if BITS_PER_LONG == 32
#define ADDR "08lx"
#elif BITS_PER_LONG == 64
#define ADDR "016lx"
#endif /* BITS_PER_LONG */

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

enum ksplice_stage_enum {
	PREPARING, APPLIED, REVERSED
};

enum ksplice_abort_cause_enum {
	NONE, NO_MATCH, BAD_SYSTEM_MAP, CODE_BUSY, MODULE_BUSY, UNEXPECTED,
	FAILED_TO_FIND, ALREADY_REVERSED
};

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
	struct list_head *reloc_addrmaps;
	struct list_head *reloc_namevals;
	struct list_head *safety_records;
	struct list_head list;
};

struct update_bundle {
	const char *kid;
	const char *name;
	struct kobject kobj;
	enum ksplice_stage_enum stage;
	enum ksplice_abort_cause_enum abort_cause;
	int debug;
#ifdef CONFIG_DEBUG_FS
	struct debugfs_blob_wrapper debug_blob;
	struct dentry *debugfs_dentry;
#endif /* CONFIG_DEBUG_FS */
	struct list_head packs;
	struct list_head list;
};

#if defined(CONFIG_DEBUG_FS) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
/* Old kernels don't have debugfs_create_blob */
struct debugfs_blob_wrapper {
	void *data;
	unsigned long size;
};
#endif /* CONFIG_DEBUG_FS && LINUX_VERSION_CODE */

struct reloc_nameval {
	struct list_head list;
	char *name;
	unsigned long val;
	enum { NOVAL, TEMP, VAL } status;
};

struct reloc_addrmap {
	struct list_head list;
	unsigned long addr;
	struct reloc_nameval *nameval;
	int pcrel;
	long addend;
	int size;
	long dst_mask;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
static inline int virtual_address_mapped(unsigned long addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);
	return pte == NULL ? 0 : pte_present(*pte);
}
#else /* LINUX_VERSION_CODE < */
/* f0646e43acb18f0e00b00085dc88bc3f403e7930 was after 2.6.24 */
static inline int virtual_address_mapped(unsigned long addr)
{
	pgd_t *pgd = pgd_offset_k(addr);
#ifdef pud_page
	pud_t *pud;
#endif /* pud_page */
	pmd_t *pmd;
	pte_t *pte;

	if (!pgd_present(*pgd))
		return 0;

#ifdef pud_page
	pud = pud_offset(pgd, addr);
	if (!pud_present(*pud))
		return 0;

	pmd = pmd_offset(pud, addr);
#else /* pud_page */
	pmd = pmd_offset(pgd, addr);
#endif /* pud_page */

	if (!pmd_present(*pmd))
		return 0;

	if (pmd_large(*pmd))
		return 1;

	pte = pte_offset_kernel(pmd, addr);
	if (!pte_present(*pte))
		return 0;

	return 1;
}
#endif /* LINUX_VERSION_CODE */

struct reloc_nameval *find_nameval(struct module_pack *pack, char *name,
				   int create);
struct reloc_addrmap *find_addrmap(struct module_pack *pack,
				   unsigned long addr);
int handle_myst_reloc(struct module_pack *pack, unsigned long pre_addr,
		      unsigned long run_addr, int rerun);

struct safety_record {
	struct list_head list;
	unsigned long addr;
	unsigned int size;
	int care;
};

struct candidate_val {
	struct list_head list;
	unsigned long val;
};

#define singular(list) (!list_empty(list) && (list)->next->next == (list))

#ifdef CONFIG_DEBUG_FS
extern int init_debug_buf(struct update_bundle *bundle);
extern void clear_debug_buf(struct update_bundle *bundle);
extern int __ksdebug(struct update_bundle *bundle, const char *fmt, ...);
#define _ksdebug(bundle, level, fmt, ...)			\
	do {							\
		if ((bundle)->debug >= (level))			\
			__ksdebug(bundle, fmt, ## __VA_ARGS__);	\
	} while (0)
#else /* !CONFIG_DEBUG_FS */
#define _ksdebug(bundle, level, fmt, ...)		\
	do {						\
		if ((bundle)->debug >= (level))		\
			printk(fmt, ## __VA_ARGS__);	\
	} while (0)
static inline int init_debug_buf(struct update_bundle *bundle)
{
	return 0;
}
static inline void clear_debug_buf(struct update_bundle *bundle)
{
	return;
}
#endif /* CONFIG_DEBUG_FS */
#define ksdebug(pack, level, fmt, ...) \
	do { _ksdebug((pack)->bundle, level, fmt, ## __VA_ARGS__); } while (0)
#define failed_to_find(pack, sym_name) \
	ksdebug(pack, 0, KERN_ERR "ksplice: Failed to find symbol %s at " \
		"%s:%d\n", sym_name, __FILE__, __LINE__)

static inline void print_abort(struct module_pack *pack, const char *str)
{
	ksdebug(pack, 0, KERN_ERR "ksplice: Aborted. (%s)\n", str);
}

int init_ksplice_module(struct module_pack *pack);
void cleanup_ksplice_module(struct module_pack *pack);

#endif /* __KERNEL__ */
