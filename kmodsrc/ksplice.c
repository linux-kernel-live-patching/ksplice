/*  Copyright (C) 2007-2009  Ksplice, Inc.
 *  Authors: Jeff Arnold, Anders Kaseorg, Tim Abbott
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, version 2.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
 *  02110-1301, USA.
 */

#include <linux/module.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#include <linux/bug.h>
#else /* LINUX_VERSION_CODE */
/* 7664c5a1da4711bb6383117f51b94c8dc8f3f1cd was after 2.6.19 */
#endif /* LINUX_VERSION_CODE */
#include <linux/ctype.h>
#if defined CONFIG_DEBUG_FS || LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#include <linux/debugfs.h>
#else /* CONFIG_DEBUG_FS */
/* a7a76cefc4b12bb6508afa4c77f11c2752cc365d was after 2.6.11 */
#endif /* CONFIG_DEBUG_FS */
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kobject.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#include <linux/sort.h>
#else /* LINUX_VERSION_CODE < */
/* 8c63b6d337534a6b5fb111dc27d0850f535118c0 was after 2.6.11 */
#endif /* LINUX_VERSION_CODE */
#include <linux/stop_machine.h>
#include <linux/sysfs.h>
#include <linux/time.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#include <linux/uaccess.h>
#else /* LINUX_VERSION_CODE < */
/* linux/uaccess.h doesn't exist in kernels before 2.6.18 */
#include <asm/uaccess.h>
#endif /* LINUX_VERSION_CODE */
#include <linux/vmalloc.h>
#ifdef KSPLICE_STANDALONE
#include "ksplice.h"
#else /* !KSPLICE_STANDALONE */
#include <linux/ksplice.h>
#endif /* KSPLICE_STANDALONE */
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
#include <asm/alternative.h>
#endif /* KSPLICE_NEED_PARAINSTRUCTIONS */

#if defined(KSPLICE_STANDALONE) && \
    !defined(CONFIG_KSPLICE) && !defined(CONFIG_KSPLICE_MODULE)
#define KSPLICE_NO_KERNEL_SUPPORT 1
#endif /* KSPLICE_STANDALONE && !CONFIG_KSPLICE && !CONFIG_KSPLICE_MODULE */

enum stage {
	STAGE_PREPARING,	/* the update is not yet applied */
	STAGE_APPLIED,		/* the update is applied */
	STAGE_REVERSED,		/* the update has been applied and reversed */
};

/* parameter to modify run-pre matching */
enum run_pre_mode {
	RUN_PRE_INITIAL,	/* dry run (only change temp_labelvals) */
	RUN_PRE_DEBUG,		/* dry run with byte-by-byte debugging */
	RUN_PRE_FINAL,		/* finalizes the matching */
#ifdef KSPLICE_STANDALONE
	RUN_PRE_SILENT,
#endif /* KSPLICE_STANDALONE */
};

enum { NOVAL, TEMP, VAL };

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
/* 5d7b32de9935c65ca8285ac6ec2382afdbb5d479 was after 2.6.8 */
#define __bitwise__
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
/* af4ca457eaf2d6682059c18463eb106e2ce58198 was after 2.6.14 */
#define __bitwise__ __bitwise
#endif

typedef int __bitwise__ abort_t;

#define OK ((__force abort_t) 0)
#define NO_MATCH ((__force abort_t) 1)
#define CODE_BUSY ((__force abort_t) 2)
#define MODULE_BUSY ((__force abort_t) 3)
#define OUT_OF_MEMORY ((__force abort_t) 4)
#define FAILED_TO_FIND ((__force abort_t) 5)
#define ALREADY_REVERSED ((__force abort_t) 6)
#define MISSING_EXPORT ((__force abort_t) 7)
#define UNEXPECTED_RUNNING_TASK ((__force abort_t) 8)
#define UNEXPECTED ((__force abort_t) 9)
#define TARGET_NOT_LOADED ((__force abort_t) 10)
#define CALL_FAILED ((__force abort_t) 11)
#define COLD_UPDATE_LOADED ((__force abort_t) 12)
#ifdef KSPLICE_STANDALONE
#define BAD_SYSTEM_MAP ((__force abort_t) 13)
#endif /* KSPLICE_STANDALONE */

struct update {
	const char *kid;
	const char *name;
	struct kobject kobj;
	enum stage stage;
	abort_t abort_cause;
	int debug;
#ifdef CONFIG_DEBUG_FS
	struct debugfs_blob_wrapper debug_blob;
	struct dentry *debugfs_dentry;
#else /* !CONFIG_DEBUG_FS */
	bool debug_continue_line;
#endif /* CONFIG_DEBUG_FS */
	bool partial;		/* is it OK if some target mods aren't loaded */
	struct list_head packs;	/* packs for loaded target mods */
	struct list_head unused_packs;	/* packs for non-loaded target mods */
	struct list_head conflicts;
	struct list_head list;
	struct list_head ksplice_module_list;
};

/* a process conflicting with an update */
struct conflict {
	const char *process_name;
	pid_t pid;
	struct list_head stack;
	struct list_head list;
};

/* an address on the stack of a conflict */
struct conflict_addr {
	unsigned long addr;	/* the address on the stack */
	bool has_conflict;	/* does this address in particular conflict? */
	const char *label;	/* the label of the conflicting safety_record */
	struct list_head list;
};

#if defined(CONFIG_DEBUG_FS) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
/* Old kernels don't have debugfs_create_blob */
struct debugfs_blob_wrapper {
	void *data;
	unsigned long size;
};
#endif /* CONFIG_DEBUG_FS && LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/* 930631edd4b1fe2781d9fe90edbe35d89dfc94cc was after 2.6.18 */
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

struct labelval {
	struct list_head list;
	struct ksplice_symbol *symbol;
	struct list_head *saved_vals;
};

/* region to be checked for conflicts in the stack check */
struct safety_record {
	struct list_head list;
	const char *label;
	unsigned long addr;	/* the address to be checked for conflicts
				 * (e.g. an obsolete function's starting addr)
				 */
	unsigned long size;	/* the size of the region to be checked */
};

/* possible value for a symbol */
struct candidate_val {
	struct list_head list;
	unsigned long val;
};

/* private struct used by init_symbol_array */
struct ksplice_lookup {
/* input */
	struct ksplice_pack *pack;
	struct ksplice_symbol **arr;
	size_t size;
/* output */
	abort_t ret;
};

#ifdef KSPLICE_NO_KERNEL_SUPPORT
struct symsearch {
	const struct kernel_symbol *start, *stop;
	const unsigned long *crcs;
	enum {
		NOT_GPL_ONLY,
		GPL_ONLY,
		WILL_BE_GPL_ONLY,
	} licence;
	bool unused;
};
#endif /* KSPLICE_NO_KERNEL_SUPPORT */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
/* c33fa9f5609e918824446ef9a75319d4a802f1f4 was after 2.6.25 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
/* 2fff0a48416af891dce38fd425246e337831e0bb was after 2.6.19 */
static bool virtual_address_mapped(unsigned long addr)
{
	char retval;
	return probe_kernel_address(addr, retval) != -EFAULT;
}
#else /* LINUX_VERSION_CODE < */
static bool virtual_address_mapped(unsigned long addr);
#endif /* LINUX_VERSION_CODE */

static long probe_kernel_read(void *dst, void *src, size_t size)
{
	if (size == 0)
		return 0;
	if (!virtual_address_mapped((unsigned long)src) ||
	    !virtual_address_mapped((unsigned long)src + size - 1))
		return -EFAULT;

	memcpy(dst, src, size);
	return 0;
}
#endif /* LINUX_VERSION_CODE */

static LIST_HEAD(updates);
#ifdef KSPLICE_STANDALONE
#if defined(CONFIG_KSPLICE) || defined(CONFIG_KSPLICE_MODULE)
extern struct list_head ksplice_module_list;
#else /* !CONFIG_KSPLICE */
LIST_HEAD(ksplice_module_list);
#endif /* CONFIG_KSPLICE */
#else /* !KSPLICE_STANDALONE */
LIST_HEAD(ksplice_module_list);
EXPORT_SYMBOL_GPL(ksplice_module_list);
static struct kobject *ksplice_kobj;
#endif /* KSPLICE_STANDALONE */

static struct kobj_type update_ktype;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
/* Old kernels do not have kcalloc
 * e629946abd0bb8266e9c3d0fd1bff2ef8dec5443 was after 2.6.8
 */
static void *kcalloc(size_t n, size_t size, typeof(GFP_KERNEL) flags)
{
	char *mem;
	if (n != 0 && size > ULONG_MAX / n)
		return NULL;
	mem = kmalloc(n * size, flags);
	if (mem)
		memset(mem, 0, n * size);
	return mem;
}
#endif /* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
/* 8c63b6d337534a6b5fb111dc27d0850f535118c0 was after 2.6.11 */
static void u32_swap(void *a, void *b, int size)
{
	u32 t = *(u32 *)a;
	*(u32 *)a = *(u32 *)b;
	*(u32 *)b = t;
}

static void generic_swap(void *a, void *b, int size)
{
	char t;

	do {
		t = *(char *)a;
		*(char *)a++ = *(char *)b;
		*(char *)b++ = t;
	} while (--size > 0);
}

/**
 * sort - sort an array of elements
 * @base: pointer to data to sort
 * @num: number of elements
 * @size: size of each element
 * @cmp: pointer to comparison function
 * @swap: pointer to swap function or NULL
 *
 * This function does a heapsort on the given array. You may provide a
 * swap function optimized to your element type.
 *
 * Sorting time is O(n log n) both on average and worst-case. While
 * qsort is about 20% faster on average, it suffers from exploitable
 * O(n*n) worst-case behavior and extra memory requirements that make
 * it less suitable for kernel use.
 */

void sort(void *base, size_t num, size_t size,
	  int (*cmp)(const void *, const void *),
	  void (*swap)(void *, void *, int size))
{
	/* pre-scale counters for performance */
	int i = (num / 2 - 1) * size, n = num * size, c, r;

	if (!swap)
		swap = (size == 4 ? u32_swap : generic_swap);

	/* heapify */
	for (; i >= 0; i -= size) {
		for (r = i; r * 2 + size < n; r = c) {
			c = r * 2 + size;
			if (c < n - size && cmp(base + c, base + c + size) < 0)
				c += size;
			if (cmp(base + r, base + c) >= 0)
				break;
			swap(base + r, base + c, size);
		}
	}

	/* sort */
	for (i = n - size; i > 0; i -= size) {
		swap(base, base + i, size);
		for (r = 0; r * 2 + size < i; r = c) {
			c = r * 2 + size;
			if (c < i - size && cmp(base + c, base + c + size) < 0)
				c += size;
			if (cmp(base + r, base + c) >= 0)
				break;
			swap(base + r, base + c, size);
		}
	}
}
#endif /* LINUX_VERSION_CODE < */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13)
/* Old kernels do not have kstrdup
 * 543537bd922692bc978e2e356fcd8bfc9c2ee7d5 was 2.6.13-rc4
 */
static char *kstrdup(const char *s, typeof(GFP_KERNEL) gfp)
{
	size_t len;
	char *buf;

	if (!s)
		return NULL;

	len = strlen(s) + 1;
	buf = kmalloc(len, gfp);
	if (buf)
		memcpy(buf, s, len);
	return buf;
}
#endif /* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
/* Old kernels use semaphore instead of mutex
 * 97d1f15b7ef52c1e9c28dc48b454024bb53a5fd2 was after 2.6.16
 */
#define mutex semaphore
#define mutex_lock down
#define mutex_unlock up
#endif /* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
/* 11443ec7d9286dd25663516436a14edfb5f43857 was after 2.6.21 */
static char * __attribute_used__
kvasprintf(typeof(GFP_KERNEL) gfp, const char *fmt, va_list ap)
{
	unsigned int len;
	char *p, dummy[1];
	va_list aq;

	va_copy(aq, ap);
	len = vsnprintf(dummy, 0, fmt, aq);
	va_end(aq);

	p = kmalloc(len + 1, gfp);
	if (!p)
		return NULL;

	vsnprintf(p, len + 1, fmt, ap);

	return p;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
/* e905914f96e11862b130dd229f73045dad9a34e8 was after 2.6.17 */
static char * __attribute__((format (printf, 2, 3)))
kasprintf(typeof(GFP_KERNEL) gfp, const char *fmt, ...)
{
	va_list ap;
	char *p;

	va_start(ap, fmt);
	p = kvasprintf(gfp, fmt, ap);
	va_end(ap);

	return p;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
/* 06b2a76d25d3cfbd14680021c1d356c91be6904e was after 2.6.24 */
static int strict_strtoul(const char *cp, unsigned int base, unsigned long *res)
{
	char *tail;
	unsigned long val;
	size_t len;

	*res = 0;
	len = strlen(cp);
	if (len == 0)
		return -EINVAL;

	val = simple_strtoul(cp, &tail, base);
	if ((*tail == '\0') ||
	    ((len == (size_t)(tail - cp) + 1) && (*tail == '\n'))) {
		*res = val;
		return 0;
	}

	return -EINVAL;
}
#endif

#ifndef task_thread_info
#define task_thread_info(task) (task)->thread_info
#endif /* !task_thread_info */

#ifdef KSPLICE_STANDALONE

static bool bootstrapped = false;

#ifdef CONFIG_KALLSYMS
extern unsigned long kallsyms_addresses[], kallsyms_num_syms;
extern u8 kallsyms_names[];
#endif /* CONFIG_KALLSYMS */

/* defined by ksplice-create */
extern const struct ksplice_reloc ksplice_init_relocs[],
    ksplice_init_relocs_end[];

/* Obtained via System.map */
extern struct list_head modules;
extern struct mutex module_mutex;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18) && defined(CONFIG_UNUSED_SYMBOLS)
/* f71d20e961474dde77e6558396efb93d6ac80a4b was after 2.6.17 */
#define KSPLICE_KSYMTAB_UNUSED_SUPPORT 1
#endif /* LINUX_VERSION_CODE */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17)
/* 9f28bb7e1d0188a993403ab39b774785892805e1 was after 2.6.16 */
#define KSPLICE_KSYMTAB_FUTURE_SUPPORT 1
#endif /* LINUX_VERSION_CODE */
extern const struct kernel_symbol __start___ksymtab[];
extern const struct kernel_symbol __stop___ksymtab[];
extern const unsigned long __start___kcrctab[];
extern const struct kernel_symbol __start___ksymtab_gpl[];
extern const struct kernel_symbol __stop___ksymtab_gpl[];
extern const unsigned long __start___kcrctab_gpl[];
#ifdef KSPLICE_KSYMTAB_UNUSED_SUPPORT
extern const struct kernel_symbol __start___ksymtab_unused[];
extern const struct kernel_symbol __stop___ksymtab_unused[];
extern const unsigned long __start___kcrctab_unused[];
extern const struct kernel_symbol __start___ksymtab_unused_gpl[];
extern const struct kernel_symbol __stop___ksymtab_unused_gpl[];
extern const unsigned long __start___kcrctab_unused_gpl[];
#endif /* KSPLICE_KSYMTAB_UNUSED_SUPPORT */
#ifdef KSPLICE_KSYMTAB_FUTURE_SUPPORT
extern const struct kernel_symbol __start___ksymtab_gpl_future[];
extern const struct kernel_symbol __stop___ksymtab_gpl_future[];
extern const unsigned long __start___kcrctab_gpl_future[];
#endif /* KSPLICE_KSYMTAB_FUTURE_SUPPORT */

#endif /* KSPLICE_STANDALONE */

static struct update *init_ksplice_update(const char *kid);
static void cleanup_ksplice_update(struct update *update);
static void maybe_cleanup_ksplice_update(struct update *update);
static void add_to_update(struct ksplice_pack *pack, struct update *update);
static int ksplice_sysfs_init(struct update *update);

/* Preparing the relocations and patches for application */
static abort_t apply_update(struct update *update);
static abort_t prepare_pack(struct ksplice_pack *pack);
static abort_t finalize_pack(struct ksplice_pack *pack);
static abort_t finalize_patches(struct ksplice_pack *pack);
static abort_t add_dependency_on_address(struct ksplice_pack *pack,
					 unsigned long addr);
static abort_t map_trampoline_pages(struct update *update);
static void unmap_trampoline_pages(struct update *update);
static void *map_writable(void *addr, size_t len);
static abort_t apply_relocs(struct ksplice_pack *pack,
			    const struct ksplice_reloc *relocs,
			    const struct ksplice_reloc *relocs_end);
static abort_t apply_reloc(struct ksplice_pack *pack,
			   const struct ksplice_reloc *r);
static abort_t apply_howto_reloc(struct ksplice_pack *pack,
				 const struct ksplice_reloc *r);
static abort_t apply_howto_date(struct ksplice_pack *pack,
				const struct ksplice_reloc *r);
static abort_t read_reloc_value(struct ksplice_pack *pack,
				const struct ksplice_reloc *r,
				unsigned long addr, unsigned long *valp);
static abort_t write_reloc_value(struct ksplice_pack *pack,
				 const struct ksplice_reloc *r,
				 unsigned long addr, unsigned long sym_addr);
static abort_t create_module_list_entry(struct ksplice_pack *pack,
					bool to_be_applied);
static void cleanup_module_list_entries(struct update *update);
static void __attribute__((noreturn)) ksplice_deleted(void);

/* run-pre matching */
static abort_t match_pack_sections(struct ksplice_pack *pack,
				   bool consider_data_sections);
static abort_t find_section(struct ksplice_pack *pack,
			    struct ksplice_section *sect);
static abort_t try_addr(struct ksplice_pack *pack,
			struct ksplice_section *sect,
			unsigned long run_addr,
			struct list_head *safety_records,
			enum run_pre_mode mode);
static abort_t run_pre_cmp(struct ksplice_pack *pack,
			   const struct ksplice_section *sect,
			   unsigned long run_addr,
			   struct list_head *safety_records,
			   enum run_pre_mode mode);
#ifndef CONFIG_FUNCTION_DATA_SECTIONS
/* defined in arch/ARCH/kernel/ksplice-arch.c */
static abort_t arch_run_pre_cmp(struct ksplice_pack *pack,
				struct ksplice_section *sect,
				unsigned long run_addr,
				struct list_head *safety_records,
				enum run_pre_mode mode);
#endif /* CONFIG_FUNCTION_DATA_SECTIONS */
static void print_bytes(struct ksplice_pack *pack,
			const unsigned char *run, int runc,
			const unsigned char *pre, int prec);
#if defined(KSPLICE_STANDALONE) && !defined(CONFIG_KALLSYMS)
static abort_t brute_search(struct ksplice_pack *pack,
			    struct ksplice_section *sect,
			    const void *start, unsigned long len,
			    struct list_head *vals);
static abort_t brute_search_all(struct ksplice_pack *pack,
				struct ksplice_section *sect,
				struct list_head *vals);
#endif /* KSPLICE_STANDALONE && !CONFIG_KALLSYMS */
static const struct ksplice_reloc *
init_reloc_search(struct ksplice_pack *pack,
		  const struct ksplice_section *sect);
static const struct ksplice_reloc *find_reloc(const struct ksplice_reloc *start,
					      const struct ksplice_reloc *end,
					      unsigned long address,
					      unsigned long size);
static abort_t lookup_reloc(struct ksplice_pack *pack,
			    const struct ksplice_reloc **fingerp,
			    unsigned long addr,
			    const struct ksplice_reloc **relocp);
static abort_t handle_reloc(struct ksplice_pack *pack,
			    const struct ksplice_section *sect,
			    const struct ksplice_reloc *r,
			    unsigned long run_addr, enum run_pre_mode mode);
static abort_t handle_howto_date(struct ksplice_pack *pack,
				 const struct ksplice_section *sect,
				 const struct ksplice_reloc *r,
				 unsigned long run_addr,
				 enum run_pre_mode mode);
static abort_t handle_howto_reloc(struct ksplice_pack *pack,
				  const struct ksplice_section *sect,
				  const struct ksplice_reloc *r,
				  unsigned long run_addr,
				  enum run_pre_mode mode);
static struct ksplice_section *symbol_section(struct ksplice_pack *pack,
					      const struct ksplice_symbol *sym);
static int compare_section_labels(const void *va, const void *vb);
static int symbol_section_bsearch_compare(const void *a, const void *b);
static const struct ksplice_reloc *patch_reloc(struct ksplice_pack *pack,
					       const struct ksplice_patch *p);

/* Computing possible addresses for symbols */
static abort_t lookup_symbol(struct ksplice_pack *pack,
			     const struct ksplice_symbol *ksym,
			     struct list_head *vals);
static void cleanup_symbol_arrays(struct ksplice_pack *pack);
static abort_t init_symbol_arrays(struct ksplice_pack *pack);
static abort_t init_symbol_array(struct ksplice_pack *pack,
				 struct ksplice_symbol *start,
				 struct ksplice_symbol *end);
static abort_t uniquify_symbols(struct ksplice_pack *pack);
static abort_t add_matching_values(struct ksplice_lookup *lookup,
				   const char *sym_name, unsigned long sym_val);
static bool add_export_values(const struct symsearch *syms,
			      struct module *owner,
			      unsigned int symnum, void *data);
static int symbolp_bsearch_compare(const void *key, const void *elt);
static int compare_symbolp_names(const void *a, const void *b);
static int compare_symbolp_labels(const void *a, const void *b);
#ifdef CONFIG_KALLSYMS
static int add_kallsyms_values(void *data, const char *name,
			       struct module *owner, unsigned long val);
#endif /* CONFIG_KALLSYMS */
#ifdef KSPLICE_STANDALONE
static abort_t
add_system_map_candidates(struct ksplice_pack *pack,
			  const struct ksplice_system_map *start,
			  const struct ksplice_system_map *end,
			  const char *label, struct list_head *vals);
static int compare_system_map(const void *a, const void *b);
static int system_map_bsearch_compare(const void *key, const void *elt);
#endif /* KSPLICE_STANDALONE */
static abort_t new_export_lookup(struct ksplice_pack *ipack, const char *name,
				 struct list_head *vals);

/* Atomic update trampoline insertion and removal */
static abort_t apply_patches(struct update *update);
static abort_t reverse_patches(struct update *update);
static int __apply_patches(void *update);
static int __reverse_patches(void *update);
static abort_t check_each_task(struct update *update);
static abort_t check_task(struct update *update,
			  const struct task_struct *t, bool rerun);
static abort_t check_stack(struct update *update, struct conflict *conf,
			   const struct thread_info *tinfo,
			   const unsigned long *stack);
static abort_t check_address(struct update *update,
			     struct conflict *conf, unsigned long addr);
static abort_t check_record(struct conflict_addr *ca,
			    const struct safety_record *rec,
			    unsigned long addr);
static bool is_stop_machine(const struct task_struct *t);
static void cleanup_conflicts(struct update *update);
static void print_conflicts(struct update *update);
static void insert_trampoline(struct ksplice_patch *p);
static abort_t verify_trampoline(struct ksplice_pack *pack,
				 const struct ksplice_patch *p);
static void remove_trampoline(const struct ksplice_patch *p);

static abort_t create_labelval(struct ksplice_pack *pack,
			       struct ksplice_symbol *ksym,
			       unsigned long val, int status);
static abort_t create_safety_record(struct ksplice_pack *pack,
				    const struct ksplice_section *sect,
				    struct list_head *record_list,
				    unsigned long run_addr,
				    unsigned long run_size);
static abort_t add_candidate_val(struct ksplice_pack *pack,
				 struct list_head *vals, unsigned long val);
static void release_vals(struct list_head *vals);
static void set_temp_labelvals(struct ksplice_pack *pack, int status_val);

static int contains_canary(struct ksplice_pack *pack, unsigned long blank_addr,
			   const struct ksplice_reloc_howto *howto);
static unsigned long follow_trampolines(struct ksplice_pack *pack,
					unsigned long addr);
static bool patches_module(const struct module *a, const struct module *b);
static bool starts_with(const char *str, const char *prefix);
static bool singular(struct list_head *list);
static void *bsearch(const void *key, const void *base, size_t n,
		     size_t size, int (*cmp)(const void *key, const void *elt));
static int compare_relocs(const void *a, const void *b);
static int reloc_bsearch_compare(const void *key, const void *elt);

/* Debugging */
static abort_t init_debug_buf(struct update *update);
static void clear_debug_buf(struct update *update);
static int __attribute__((format(printf, 2, 3)))
_ksdebug(struct update *update, const char *fmt, ...);
#define ksdebug(pack, fmt, ...) \
	_ksdebug(pack->update, fmt, ## __VA_ARGS__)

#ifdef KSPLICE_NO_KERNEL_SUPPORT
/* Functions defined here that will be exported in later kernels */
#ifdef CONFIG_KALLSYMS
static int kallsyms_on_each_symbol(int (*fn)(void *, const char *,
					     struct module *, unsigned long),
				   void *data);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
static unsigned int kallsyms_expand_symbol(unsigned int off, char *result);
#endif /* LINUX_VERSION_CODE */
static int module_kallsyms_on_each_symbol(int (*fn)(void *, const char *,
						    struct module *,
						    unsigned long),
					  void *data);
#endif /* CONFIG_KALLSYMS */
static struct module *find_module(const char *name);
static int use_module(struct module *a, struct module *b);
static const struct kernel_symbol *find_symbol(const char *name,
					       struct module **owner,
					       const unsigned long **crc,
					       bool gplok, bool warn);
static bool each_symbol(bool (*fn)(const struct symsearch *arr,
				   struct module *owner,
				   unsigned int symnum, void *data),
			void *data);
static struct module *__module_address(unsigned long addr);
#endif /* KSPLICE_NO_KERNEL_SUPPORT */

/* Architecture-specific functions defined in arch/ARCH/kernel/ksplice-arch.c */

/* Prepare a trampoline for the given patch */
static abort_t prepare_trampoline(struct ksplice_pack *pack,
				  struct ksplice_patch *p);
/* What address does the trampoline at addr jump to? */
static abort_t trampoline_target(struct ksplice_pack *pack, unsigned long addr,
				 unsigned long *new_addr);
/* Hook to handle pc-relative jumps inserted by parainstructions */
static abort_t handle_paravirt(struct ksplice_pack *pack, unsigned long pre,
			       unsigned long run, int *matched);
/* Called for relocations of type KSPLICE_HOWTO_BUG */
static abort_t handle_bug(struct ksplice_pack *pack,
			  const struct ksplice_reloc *r,
			  unsigned long run_addr);
/* Called for relocations of type KSPLICE_HOWTO_EXTABLE */
static abort_t handle_extable(struct ksplice_pack *pack,
			      const struct ksplice_reloc *r,
			      unsigned long run_addr);
/* Is address p on the stack of the given thread? */
static bool valid_stack_ptr(const struct thread_info *tinfo, const void *p);

#ifndef KSPLICE_STANDALONE
#include "ksplice-arch.c"
#elif defined CONFIG_X86
#include "x86/ksplice-arch.c"
#elif defined CONFIG_ARM
#include "arm/ksplice-arch.c"
#endif /* KSPLICE_STANDALONE */

#define clear_list(head, type, member)				\
	do {							\
		struct list_head *_pos, *_n;			\
		list_for_each_safe(_pos, _n, head) {		\
			list_del(_pos);				\
			kfree(list_entry(_pos, type, member));	\
		}						\
	} while (0)

/**
 * init_ksplice_pack() - Initializes a ksplice pack
 * @pack:	The pack to be initialized.  All of the public fields of the
 * 		pack and its associated data structures should be populated
 * 		before this function is called.  The values of the private
 * 		fields will be ignored.
 **/
int init_ksplice_pack(struct ksplice_pack *pack)
{
	struct update *update;
	struct ksplice_patch *p;
	struct ksplice_section *s;
	int ret = 0;

#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return -1;
#endif /* KSPLICE_STANDALONE */

	INIT_LIST_HEAD(&pack->temp_labelvals);
	INIT_LIST_HEAD(&pack->safety_records);

	sort(pack->helper_relocs,
	     pack->helper_relocs_end - pack->helper_relocs,
	     sizeof(*pack->helper_relocs), compare_relocs, NULL);
	sort(pack->primary_relocs,
	     pack->primary_relocs_end - pack->primary_relocs,
	     sizeof(*pack->primary_relocs), compare_relocs, NULL);
	sort(pack->helper_sections,
	     pack->helper_sections_end - pack->helper_sections,
	     sizeof(*pack->helper_sections), compare_section_labels, NULL);
#ifdef KSPLICE_STANDALONE
	sort(pack->primary_system_map,
	     pack->primary_system_map_end - pack->primary_system_map,
	     sizeof(*pack->primary_system_map), compare_system_map, NULL);
	sort(pack->helper_system_map,
	     pack->helper_system_map_end - pack->helper_system_map,
	     sizeof(*pack->helper_system_map), compare_system_map, NULL);
#endif /* KSPLICE_STANDALONE */

	for (p = pack->patches; p < pack->patches_end; p++)
		p->vaddr = NULL;
	for (s = pack->helper_sections; s < pack->helper_sections_end; s++)
		s->match_map = NULL;
	for (p = pack->patches; p < pack->patches_end; p++) {
		const struct ksplice_reloc *r = patch_reloc(pack, p);
		if (r == NULL)
			return -ENOENT;
		if (p->type == KSPLICE_PATCH_DATA) {
			s = symbol_section(pack, r->symbol);
			if (s == NULL)
				return -ENOENT;
			/* Ksplice creates KSPLICE_PATCH_DATA patches in order
			 * to modify rodata sections that have been explicitly
			 * marked for patching using the ksplice-patch.h macro
			 * ksplice_assume_rodata.  Here we modify the section
			 * flags appropriately.
			 */
			if (s->flags & KSPLICE_SECTION_DATA)
				s->flags = (s->flags & ~KSPLICE_SECTION_DATA) |
				    KSPLICE_SECTION_RODATA;
		}
	}

	mutex_lock(&module_mutex);
	list_for_each_entry(update, &updates, list) {
		if (strcmp(pack->kid, update->kid) == 0) {
			if (update->stage != STAGE_PREPARING) {
				ret = -EPERM;
				goto out;
			}
			add_to_update(pack, update);
			ret = 0;
			goto out;
		}
	}
	update = init_ksplice_update(pack->kid);
	if (update == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	ret = ksplice_sysfs_init(update);
	if (ret != 0) {
		cleanup_ksplice_update(update);
		goto out;
	}
	add_to_update(pack, update);
out:
	mutex_unlock(&module_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(init_ksplice_pack);

/**
 * cleanup_ksplice_pack() - Cleans up a pack
 * @pack:	The pack to be cleaned up
 */
void cleanup_ksplice_pack(struct ksplice_pack *pack)
{
	if (pack->update == NULL)
		return;

	mutex_lock(&module_mutex);
	if (pack->update->stage == STAGE_APPLIED) {
		/* If the pack wasn't actually applied (because we
		 * only applied this update to loaded modules and this
		 * target was not loaded), then unregister the pack
		 * from the list of unused packs.
		 */
		struct ksplice_pack *p;
		bool found = false;

		list_for_each_entry(p, &pack->update->unused_packs, list) {
			if (p == pack)
				found = true;
		}
		if (found)
			list_del(&pack->list);
		mutex_unlock(&module_mutex);
		return;
	}
	list_del(&pack->list);
	if (pack->update->stage == STAGE_PREPARING)
		maybe_cleanup_ksplice_update(pack->update);
	pack->update = NULL;
	mutex_unlock(&module_mutex);
}
EXPORT_SYMBOL_GPL(cleanup_ksplice_pack);

static struct update *init_ksplice_update(const char *kid)
{
	struct update *update;
	update = kcalloc(1, sizeof(struct update), GFP_KERNEL);
	if (update == NULL)
		return NULL;
	update->name = kasprintf(GFP_KERNEL, "ksplice_%s", kid);
	if (update->name == NULL) {
		kfree(update);
		return NULL;
	}
	update->kid = kstrdup(kid, GFP_KERNEL);
	if (update->kid == NULL) {
		kfree(update->name);
		kfree(update);
		return NULL;
	}
	if (try_module_get(THIS_MODULE) != 1) {
		kfree(update->kid);
		kfree(update->name);
		kfree(update);
		return NULL;
	}
	INIT_LIST_HEAD(&update->packs);
	INIT_LIST_HEAD(&update->unused_packs);
	INIT_LIST_HEAD(&update->ksplice_module_list);
	if (init_debug_buf(update) != OK) {
		module_put(THIS_MODULE);
		kfree(update->kid);
		kfree(update->name);
		kfree(update);
		return NULL;
	}
	list_add(&update->list, &updates);
	update->stage = STAGE_PREPARING;
	update->abort_cause = OK;
	update->partial = 0;
	INIT_LIST_HEAD(&update->conflicts);
	return update;
}

static void cleanup_ksplice_update(struct update *update)
{
	list_del(&update->list);
	cleanup_conflicts(update);
	clear_debug_buf(update);
	cleanup_module_list_entries(update);
	kfree(update->kid);
	kfree(update->name);
	kfree(update);
	module_put(THIS_MODULE);
}

/* Clean up the update if it no longer has any packs */
static void maybe_cleanup_ksplice_update(struct update *update)
{
	if (list_empty(&update->packs) && list_empty(&update->unused_packs))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
		kobject_put(&update->kobj);
#else /* LINUX_VERSION_CODE < */
/* 6d06adfaf82d154023141ddc0c9de18b6a49090b was after 2.6.24 */
		kobject_unregister(&update->kobj);
#endif /* LINUX_VERSION_CODE */
}

static void add_to_update(struct ksplice_pack *pack, struct update *update)
{
	pack->update = update;
	list_add(&pack->list, &update->unused_packs);
}

static int ksplice_sysfs_init(struct update *update)
{
	int ret = 0;
	memset(&update->kobj, 0, sizeof(update->kobj));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#ifndef KSPLICE_STANDALONE
	ret = kobject_init_and_add(&update->kobj, &update_ktype,
				   ksplice_kobj, "%s", update->kid);
#else /* KSPLICE_STANDALONE */
/* 6d06adfaf82d154023141ddc0c9de18b6a49090b was after 2.6.24 */
	ret = kobject_init_and_add(&update->kobj, &update_ktype,
				   &THIS_MODULE->mkobj.kobj, "ksplice");
#endif /* KSPLICE_STANDALONE */
#else /* LINUX_VERSION_CODE < */
	ret = kobject_set_name(&update->kobj, "%s", "ksplice");
	if (ret != 0)
		return ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
	update->kobj.parent = &THIS_MODULE->mkobj.kobj;
#else /* LINUX_VERSION_CODE < */
/* b86ab02803095190d6b72bcc18dcf620bf378df9 was after 2.6.10 */
	update->kobj.parent = &THIS_MODULE->mkobj->kobj;
#endif /* LINUX_VERSION_CODE */
	update->kobj.ktype = &update_ktype;
	ret = kobject_register(&update->kobj);
#endif /* LINUX_VERSION_CODE */
	if (ret != 0)
		return ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
	kobject_uevent(&update->kobj, KOBJ_ADD);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
/* 312c004d36ce6c739512bac83b452f4c20ab1f62 was after 2.6.14 */
/* 12025235884570ba7f02a6f427f973ac6be7ec54 was after 2.6.9 */
	kobject_uevent(&update->kobj, KOBJ_ADD, NULL);
#endif /* LINUX_VERSION_CODE */
	return 0;
}

static abort_t apply_update(struct update *update)
{
	struct ksplice_pack *pack, *n;
	abort_t ret;
	int retval;

	list_for_each_entry(pack, &update->packs, list) {
		ret = create_module_list_entry(pack, true);
		if (ret != OK)
			goto out;
	}

	list_for_each_entry_safe(pack, n, &update->unused_packs, list) {
		if (strcmp(pack->target_name, "vmlinux") == 0) {
			pack->target = NULL;
		} else if (pack->target == NULL) {
			pack->target = find_module(pack->target_name);
			if (pack->target == NULL ||
			    !module_is_live(pack->target)) {
				if (!update->partial) {
					ret = TARGET_NOT_LOADED;
					goto out;
				}
				ret = create_module_list_entry(pack, false);
				if (ret != OK)
					goto out;
				continue;
			}
			retval = use_module(pack->primary, pack->target);
			if (retval != 1) {
				ret = UNEXPECTED;
				goto out;
			}
		}
		ret = create_module_list_entry(pack, true);
		if (ret != OK)
			goto out;
		list_del(&pack->list);
		list_add_tail(&pack->list, &update->packs);

#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
		if (pack->target == NULL) {
			apply_paravirt(pack->primary_parainstructions,
				       pack->primary_parainstructions_end);
			apply_paravirt(pack->helper_parainstructions,
				       pack->helper_parainstructions_end);
		}
#endif /* KSPLICE_NEED_PARAINSTRUCTIONS */
	}

	list_for_each_entry(pack, &update->packs, list) {
		const struct ksplice_section *sect;
		for (sect = pack->primary_sections;
		     sect < pack->primary_sections_end; sect++) {
			struct safety_record *rec = kmalloc(sizeof(*rec),
							    GFP_KERNEL);
			if (rec == NULL) {
				ret = OUT_OF_MEMORY;
				goto out;
			}
			rec->addr = sect->address;
			rec->size = sect->size;
			rec->label = sect->symbol->label;
			list_add(&rec->list, &pack->safety_records);
		}
	}

	list_for_each_entry(pack, &update->packs, list) {
		ret = init_symbol_arrays(pack);
		if (ret != OK) {
			cleanup_symbol_arrays(pack);
			goto out;
		}
		ret = prepare_pack(pack);
		cleanup_symbol_arrays(pack);
		if (ret != OK)
			goto out;
	}
	ret = apply_patches(update);
out:
	list_for_each_entry(pack, &update->packs, list) {
		struct ksplice_section *s;
		if (update->stage == STAGE_PREPARING)
			clear_list(&pack->safety_records, struct safety_record,
				   list);
		for (s = pack->helper_sections; s < pack->helper_sections_end;
		     s++) {
			if (s->match_map != NULL) {
				vfree(s->match_map);
				s->match_map = NULL;
			}
		}
	}
	if (update->stage == STAGE_PREPARING)
		cleanup_module_list_entries(update);
	return ret;
}

static int compare_symbolp_names(const void *a, const void *b)
{
	const struct ksplice_symbol *const *sympa = a, *const *sympb = b;
	if ((*sympa)->name == NULL && (*sympb)->name == NULL)
		return 0;
	if ((*sympa)->name == NULL)
		return -1;
	if ((*sympb)->name == NULL)
		return 1;
	return strcmp((*sympa)->name, (*sympb)->name);
}

static int compare_symbolp_labels(const void *a, const void *b)
{
	const struct ksplice_symbol *const *sympa = a, *const *sympb = b;
	return strcmp((*sympa)->label, (*sympb)->label);
}

static int symbolp_bsearch_compare(const void *key, const void *elt)
{
	const char *name = key;
	const struct ksplice_symbol *const *symp = elt;
	const struct ksplice_symbol *sym = *symp;
	if (sym->name == NULL)
		return 1;
	return strcmp(name, sym->name);
}

static abort_t add_matching_values(struct ksplice_lookup *lookup,
				   const char *sym_name, unsigned long sym_val)
{
	struct ksplice_symbol **symp;
	abort_t ret;

	symp = bsearch(sym_name, lookup->arr, lookup->size,
		       sizeof(*lookup->arr), symbolp_bsearch_compare);
	if (symp == NULL)
		return OK;

	while (symp > lookup->arr &&
	       symbolp_bsearch_compare(sym_name, symp - 1) == 0)
		symp--;

	for (; symp < lookup->arr + lookup->size; symp++) {
		struct ksplice_symbol *sym = *symp;
		if (sym->name == NULL || strcmp(sym_name, sym->name) != 0)
			break;
		ret = add_candidate_val(lookup->pack, sym->vals, sym_val);
		if (ret != OK)
			return ret;
	}
	return OK;
}

#ifdef CONFIG_KALLSYMS
static int add_kallsyms_values(void *data, const char *name,
			       struct module *owner, unsigned long val)
{
	struct ksplice_lookup *lookup = data;
	if (owner == lookup->pack->primary ||
	    !patches_module(owner, lookup->pack->target))
		return (__force int)OK;
	return (__force int)add_matching_values(lookup, name, val);
}
#endif /* CONFIG_KALLSYMS */

static bool add_export_values(const struct symsearch *syms,
			      struct module *owner,
			      unsigned int symnum, void *data)
{
	struct ksplice_lookup *lookup = data;
	abort_t ret;

	ret = add_matching_values(lookup, syms->start[symnum].name,
				  syms->start[symnum].value);
	if (ret != OK) {
		lookup->ret = ret;
		return true;
	}
	return false;
}

static void cleanup_symbol_arrays(struct ksplice_pack *pack)
{
	struct ksplice_symbol *sym;
	for (sym = pack->primary_symbols; sym < pack->primary_symbols_end;
	     sym++) {
		if (sym->vals != NULL) {
			clear_list(sym->vals, struct candidate_val, list);
			kfree(sym->vals);
			sym->vals = NULL;
		}
	}
	for (sym = pack->helper_symbols; sym < pack->helper_symbols_end; sym++) {
		if (sym->vals != NULL) {
			clear_list(sym->vals, struct candidate_val, list);
			kfree(sym->vals);
			sym->vals = NULL;
		}
	}
}

/*
 * The primary and helper modules each have their own independent
 * ksplice_symbol structures.  uniquify_symbols unifies these separate
 * pieces of kernel symbol information by replacing all references to
 * the helper copy of symbols with references to the primary copy.
 */
static abort_t uniquify_symbols(struct ksplice_pack *pack)
{
	struct ksplice_reloc *r;
	struct ksplice_section *s;
	struct ksplice_symbol *sym, **sym_arr, **symp;
	size_t size = pack->primary_symbols_end - pack->primary_symbols;

	if (size == 0)
		return OK;

	sym_arr = vmalloc(sizeof(*sym_arr) * size);
	if (sym_arr == NULL)
		return OUT_OF_MEMORY;

	for (symp = sym_arr, sym = pack->primary_symbols;
	     symp < sym_arr + size && sym < pack->primary_symbols_end;
	     sym++, symp++)
		*symp = sym;

	sort(sym_arr, size, sizeof(*sym_arr), compare_symbolp_labels, NULL);

	for (r = pack->helper_relocs; r < pack->helper_relocs_end; r++) {
		symp = bsearch(&r->symbol, sym_arr, size, sizeof(*sym_arr),
			       compare_symbolp_labels);
		if (symp != NULL) {
			if ((*symp)->name == NULL)
				(*symp)->name = r->symbol->name;
			r->symbol = *symp;
		}
	}

	for (s = pack->helper_sections; s < pack->helper_sections_end; s++) {
		symp = bsearch(&s->symbol, sym_arr, size, sizeof(*sym_arr),
			       compare_symbolp_labels);
		if (symp != NULL) {
			if ((*symp)->name == NULL)
				(*symp)->name = s->symbol->name;
			s->symbol = *symp;
		}
	}

	vfree(sym_arr);
	return OK;
}

/*
 * Initialize the ksplice_symbol structures in the given array using
 * the kallsyms and exported symbol tables.
 */
static abort_t init_symbol_array(struct ksplice_pack *pack,
				 struct ksplice_symbol *start,
				 struct ksplice_symbol *end)
{
	struct ksplice_symbol *sym, **sym_arr, **symp;
	struct ksplice_lookup lookup;
	size_t size = end - start;
	abort_t ret;

	if (size == 0)
		return OK;

	for (sym = start; sym < end; sym++) {
		if (starts_with(sym->label, "__ksymtab")) {
			const struct kernel_symbol *ksym;
			const char *colon = strchr(sym->label, ':');
			const char *name = colon + 1;
			if (colon == NULL)
				continue;
			ksym = find_symbol(name, NULL, NULL, true, false);
			if (ksym == NULL) {
				ksdebug(pack, "Could not find kernel_symbol "
					"structure for %s\n", name);
				continue;
			}
			sym->value = (unsigned long)ksym;
			sym->vals = NULL;
			continue;
		}

		sym->vals = kmalloc(sizeof(*sym->vals), GFP_KERNEL);
		if (sym->vals == NULL)
			return OUT_OF_MEMORY;
		INIT_LIST_HEAD(sym->vals);
		sym->value = 0;
	}

	sym_arr = vmalloc(sizeof(*sym_arr) * size);
	if (sym_arr == NULL)
		return OUT_OF_MEMORY;

	for (symp = sym_arr, sym = start; symp < sym_arr + size && sym < end;
	     sym++, symp++)
		*symp = sym;

	sort(sym_arr, size, sizeof(*sym_arr), compare_symbolp_names, NULL);

	lookup.pack = pack;
	lookup.arr = sym_arr;
	lookup.size = size;
	lookup.ret = OK;

	each_symbol(add_export_values, &lookup);
	ret = lookup.ret;
#ifdef CONFIG_KALLSYMS
	if (ret == OK)
		ret = (__force abort_t)
		    kallsyms_on_each_symbol(add_kallsyms_values, &lookup);
#endif /* CONFIG_KALLSYMS */
	vfree(sym_arr);
	return ret;
}

/* Prepare the pack's ksplice_symbol structures for run-pre matching */
static abort_t init_symbol_arrays(struct ksplice_pack *pack)
{
	abort_t ret;

	ret = uniquify_symbols(pack);
	if (ret != OK)
		return ret;

	ret = init_symbol_array(pack, pack->helper_symbols,
				pack->helper_symbols_end);
	if (ret != OK)
		return ret;

	ret = init_symbol_array(pack, pack->primary_symbols,
				pack->primary_symbols_end);
	if (ret != OK)
		return ret;

	return OK;
}

static abort_t prepare_pack(struct ksplice_pack *pack)
{
	abort_t ret;

	ksdebug(pack, "Preparing and checking %s\n", pack->name);
	ret = match_pack_sections(pack, false);
	if (ret == NO_MATCH) {
		/* It is possible that by using relocations from .data sections
		 * we can successfully run-pre match the rest of the sections.
		 * To avoid using any symbols obtained from .data sections
		 * (which may be unreliable) in the post code, we first prepare
		 * the post code and then try to run-pre match the remaining
		 * sections with the help of .data sections.
		 */
		ksdebug(pack, "Continuing without some sections; we might "
			"find them later.\n");
		ret = finalize_pack(pack);
		if (ret != OK) {
			ksdebug(pack, "Aborted.  Unable to continue without "
				"the unmatched sections.\n");
			return ret;
		}

		ksdebug(pack, "run-pre: Considering .data sections to find the "
			"unmatched sections\n");
		ret = match_pack_sections(pack, true);
		if (ret != OK)
			return ret;

		ksdebug(pack, "run-pre: Found all previously unmatched "
			"sections\n");
		return OK;
	} else if (ret != OK) {
		return ret;
	}

	return finalize_pack(pack);
}

/*
 * Finish preparing the pack for insertion into the kernel.
 * Afterwards, the replacement code should be ready to run and the
 * ksplice_patches should all be ready for trampoline insertion.
 */
static abort_t finalize_pack(struct ksplice_pack *pack)
{
	abort_t ret;
	ret = apply_relocs(pack, pack->primary_relocs,
			   pack->primary_relocs_end);
	if (ret != OK)
		return ret;

	ret = finalize_patches(pack);
	if (ret != OK)
		return ret;

	return OK;
}

static abort_t finalize_patches(struct ksplice_pack *pack)
{
	struct ksplice_patch *p;
	struct safety_record *rec;
	abort_t ret;

	for (p = pack->patches; p < pack->patches_end; p++) {
		bool found = false;
		list_for_each_entry(rec, &pack->safety_records, list) {
			if (rec->addr <= p->oldaddr &&
			    p->oldaddr < rec->addr + rec->size) {
				found = true;
				break;
			}
		}
		if (!found && p->type != KSPLICE_PATCH_EXPORT) {
			const struct ksplice_reloc *r = patch_reloc(pack, p);
			if (r == NULL) {
				ksdebug(pack, "A patch with no ksplice_reloc at"
					" its oldaddr has no safety record\n");
				return NO_MATCH;
			}
			ksdebug(pack, "No safety record for patch with oldaddr "
				"%s+%lx\n", r->symbol->label, r->target_addend);
			return NO_MATCH;
		}

		if (p->type == KSPLICE_PATCH_TEXT) {
			ret = prepare_trampoline(pack, p);
			if (ret != OK)
				return ret;
		}

		if (found && rec->addr + rec->size < p->oldaddr + p->size) {
			ksdebug(pack, "Safety record %s is too short for "
				"patch\n", rec->label);
			return UNEXPECTED;
		}

		if (p->type == KSPLICE_PATCH_TEXT) {
			if (p->repladdr == 0)
				p->repladdr = (unsigned long)ksplice_deleted;
		}
	}
	return OK;
}

static abort_t map_trampoline_pages(struct update *update)
{
	struct ksplice_pack *pack;
	list_for_each_entry(pack, &update->packs, list) {
		struct ksplice_patch *p;
		for (p = pack->patches; p < pack->patches_end; p++) {
			p->vaddr = map_writable((void *)p->oldaddr, p->size);
			if (p->vaddr == NULL) {
				ksdebug(pack, "Unable to map oldaddr read/write"
					"\n");
				unmap_trampoline_pages(update);
				return UNEXPECTED;
			}
		}
	}
	return OK;
}

static void unmap_trampoline_pages(struct update *update)
{
	struct ksplice_pack *pack;
	list_for_each_entry(pack, &update->packs, list) {
		struct ksplice_patch *p;
		for (p = pack->patches; p < pack->patches_end; p++) {
			vunmap((void *)((unsigned long)p->vaddr & PAGE_MASK));
			p->vaddr = NULL;
		}
	}
}

/*
 * map_writable creates a shadow page mapping of the range
 * [addr, addr + len) so that we can write to code mapped read-only.
 *
 * It is similar to a generalized version of x86's text_poke.  But
 * because one cannot use vmalloc/vfree() inside stop_machine, we use
 * map_writable to map the pages before stop_machine, then use the
 * mapping inside stop_machine, and unmap the pages afterwards.
 */
static void *map_writable(void *addr, size_t len)
{
	void *vaddr;
	int nr_pages = DIV_ROUND_UP(offset_in_page(addr) + len, PAGE_SIZE);
	struct page **pages = kmalloc(nr_pages * sizeof(*pages), GFP_KERNEL);
	void *page_addr = (void *)((unsigned long)addr & PAGE_MASK);
	int i;

	if (pages == NULL)
		return NULL;

	for (i = 0; i < nr_pages; i++) {
		if (__module_address((unsigned long)page_addr) == NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22) || !defined(CONFIG_X86_64)
			pages[i] = virt_to_page(page_addr);
#else /* LINUX_VERSION_CODE < && CONFIG_X86_64 */
/* e3ebadd95cb621e2c7436f3d3646447ac9d5c16d was after 2.6.21 */
			pages[i] =
			    pfn_to_page(__pa_symbol(page_addr) >> PAGE_SHIFT);
#endif /* LINUX_VERSION_CODE || !CONFIG_X86_64 */
			WARN_ON(!PageReserved(pages[i]));
		} else {
			pages[i] = vmalloc_to_page(addr);
		}
		if (pages[i] == NULL) {
			kfree(pages);
			return NULL;
		}
		page_addr += PAGE_SIZE;
	}
	vaddr = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
	kfree(pages);
	if (vaddr == NULL)
		return NULL;
	return vaddr + offset_in_page(addr);
}

/*
 * Ksplice adds a dependency on any symbol address used to resolve relocations
 * in the primary module.
 *
 * Be careful to follow_trampolines so that we always depend on the
 * latest version of the target function, since that's the code that
 * will run if we call addr.
 */
static abort_t add_dependency_on_address(struct ksplice_pack *pack,
					 unsigned long addr)
{
	struct ksplice_pack *p;
	struct module *m =
	    __module_text_address(follow_trampolines(pack, addr));
	if (m == NULL)
		return OK;
	list_for_each_entry(p, &pack->update->packs, list) {
		if (m == p->primary)
			return OK;
	}
	if (use_module(pack->primary, m) != 1)
		return MODULE_BUSY;
	return OK;
}

static abort_t apply_relocs(struct ksplice_pack *pack,
			    const struct ksplice_reloc *relocs,
			    const struct ksplice_reloc *relocs_end)
{
	const struct ksplice_reloc *r;
	for (r = relocs; r < relocs_end; r++) {
		abort_t ret = apply_reloc(pack, r);
		if (ret != OK)
			return ret;
	}
	return OK;
}

static abort_t apply_reloc(struct ksplice_pack *pack,
			   const struct ksplice_reloc *r)
{
	switch (r->howto->type) {
	case KSPLICE_HOWTO_RELOC:
	case KSPLICE_HOWTO_RELOC_PATCH:
		return apply_howto_reloc(pack, r);
	case KSPLICE_HOWTO_DATE:
	case KSPLICE_HOWTO_TIME:
		return apply_howto_date(pack, r);
	default:
		ksdebug(pack, "Unexpected howto type %d\n", r->howto->type);
		return UNEXPECTED;
	}
}

/*
 * Applies a relocation.  Aborts if the symbol referenced in it has
 * not been uniquely resolved.
 */
static abort_t apply_howto_reloc(struct ksplice_pack *pack,
				 const struct ksplice_reloc *r)
{
	abort_t ret;
	int canary_ret;
	unsigned long sym_addr;
	LIST_HEAD(vals);

	canary_ret = contains_canary(pack, r->blank_addr, r->howto);
	if (canary_ret < 0)
		return UNEXPECTED;
	if (canary_ret == 0) {
		ksdebug(pack, "reloc: skipped %lx to %s+%lx (altinstr)\n",
			r->blank_addr, r->symbol->label, r->target_addend);
		return OK;
	}

#ifdef KSPLICE_STANDALONE
	if (!bootstrapped) {
		ret = add_system_map_candidates(pack,
						pack->primary_system_map,
						pack->primary_system_map_end,
						r->symbol->label, &vals);
		if (ret != OK) {
			release_vals(&vals);
			return ret;
		}
	}
#endif /* KSPLICE_STANDALONE */
	ret = lookup_symbol(pack, r->symbol, &vals);
	if (ret != OK) {
		release_vals(&vals);
		return ret;
	}
	/*
	 * Relocations for the oldaddr fields of patches must have
	 * been resolved via run-pre matching.
	 */
	if (!singular(&vals) || (r->symbol->vals != NULL &&
				 r->howto->type == KSPLICE_HOWTO_RELOC_PATCH)) {
		release_vals(&vals);
		ksdebug(pack, "Failed to find %s for reloc\n",
			r->symbol->label);
		return FAILED_TO_FIND;
	}
	sym_addr = list_entry(vals.next, struct candidate_val, list)->val;
	release_vals(&vals);

	ret = write_reloc_value(pack, r, r->blank_addr,
				r->howto->pcrel ? sym_addr - r->blank_addr :
				sym_addr);
	if (ret != OK)
		return ret;

	ksdebug(pack, "reloc: %lx to %s+%lx (S=%lx ", r->blank_addr,
		r->symbol->label, r->target_addend, sym_addr);
	switch (r->howto->size) {
	case 1:
		ksdebug(pack, "aft=%02x)\n", *(uint8_t *)r->blank_addr);
		break;
	case 2:
		ksdebug(pack, "aft=%04x)\n", *(uint16_t *)r->blank_addr);
		break;
	case 4:
		ksdebug(pack, "aft=%08x)\n", *(uint32_t *)r->blank_addr);
		break;
#if BITS_PER_LONG >= 64
	case 8:
		ksdebug(pack, "aft=%016llx)\n", *(uint64_t *)r->blank_addr);
		break;
#endif /* BITS_PER_LONG */
	default:
		ksdebug(pack, "Aborted.  Invalid relocation size.\n");
		return UNEXPECTED;
	}
#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return OK;
#endif /* KSPLICE_STANDALONE */

	/*
	 * Create labelvals so that we can verify our choices in the
	 * second round of run-pre matching that considers data sections.
	 */
	ret = create_labelval(pack, r->symbol, sym_addr, VAL);
	if (ret != OK)
		return ret;

	return add_dependency_on_address(pack, sym_addr);
}

/*
 * Date relocations are created wherever __DATE__ or __TIME__ is used
 * in the kernel; we resolve them by simply copying in the date/time
 * obtained from run-pre matching the relevant compilation unit.
 */
static abort_t apply_howto_date(struct ksplice_pack *pack,
				const struct ksplice_reloc *r)
{
	if (r->symbol->vals != NULL) {
		ksdebug(pack, "Failed to find %s for date\n", r->symbol->label);
		return FAILED_TO_FIND;
	}
	memcpy((unsigned char *)r->blank_addr,
	       (const unsigned char *)r->symbol->value, r->howto->size);
	return OK;
}

/*
 * Given a relocation and its run address, compute the address of the
 * symbol the relocation referenced, and store it in *valp.
 */
static abort_t read_reloc_value(struct ksplice_pack *pack,
				const struct ksplice_reloc *r,
				unsigned long addr, unsigned long *valp)
{
	unsigned char bytes[sizeof(long)];
	unsigned long val;
	const struct ksplice_reloc_howto *howto = r->howto;

	if (howto->size <= 0 || howto->size > sizeof(long)) {
		ksdebug(pack, "Aborted.  Invalid relocation size.\n");
		return UNEXPECTED;
	}

	if (probe_kernel_read(bytes, (void *)addr, howto->size) == -EFAULT)
		return NO_MATCH;

	switch (howto->size) {
	case 1:
		val = *(uint8_t *)bytes;
		break;
	case 2:
		val = *(uint16_t *)bytes;
		break;
	case 4:
		val = *(uint32_t *)bytes;
		break;
#if BITS_PER_LONG >= 64
	case 8:
		val = *(uint64_t *)bytes;
		break;
#endif /* BITS_PER_LONG */
	default:
		ksdebug(pack, "Aborted.  Invalid relocation size.\n");
		return UNEXPECTED;
	}

	val &= howto->dst_mask;
	if (howto->signed_addend)
		val |= -(val & (howto->dst_mask & ~(howto->dst_mask >> 1)));
	val <<= howto->rightshift;
	val -= r->insn_addend + r->target_addend;
	*valp = val;
	return OK;
}

/*
 * Given a relocation, the address of its storage unit, and the
 * address of the symbol the relocation references, write the
 * relocation's final value into the storage unit.
 */
static abort_t write_reloc_value(struct ksplice_pack *pack,
				 const struct ksplice_reloc *r,
				 unsigned long addr, unsigned long sym_addr)
{
	unsigned long val = sym_addr + r->target_addend + r->insn_addend;
	const struct ksplice_reloc_howto *howto = r->howto;
	val >>= howto->rightshift;
	switch (howto->size) {
	case 1:
		*(uint8_t *)addr = (*(uint8_t *)addr & ~howto->dst_mask) |
		    (val & howto->dst_mask);
		break;
	case 2:
		*(uint16_t *)addr = (*(uint16_t *)addr & ~howto->dst_mask) |
		    (val & howto->dst_mask);
		break;
	case 4:
		*(uint32_t *)addr = (*(uint32_t *)addr & ~howto->dst_mask) |
		    (val & howto->dst_mask);
		break;
#if BITS_PER_LONG >= 64
	case 8:
		*(uint64_t *)addr = (*(uint64_t *)addr & ~howto->dst_mask) |
		    (val & howto->dst_mask);
		break;
#endif /* BITS_PER_LONG */
	default:
		ksdebug(pack, "Aborted.  Invalid relocation size.\n");
		return UNEXPECTED;
	}

	if (read_reloc_value(pack, r, addr, &val) != OK || val != sym_addr) {
		ksdebug(pack, "Aborted.  Relocation overflow.\n");
		return UNEXPECTED;
	}

	return OK;
}

static abort_t create_module_list_entry(struct ksplice_pack *pack,
					bool to_be_applied)
{
	struct ksplice_module_list_entry *entry =
	    kmalloc(sizeof(*entry), GFP_KERNEL);
	if (entry == NULL)
		return OUT_OF_MEMORY;
	entry->primary_name = kstrdup(pack->primary->name, GFP_KERNEL);
	if (entry->primary_name == NULL) {
		kfree(entry);
		return OUT_OF_MEMORY;
	}
	entry->target_name = kstrdup(pack->target_name, GFP_KERNEL);
	if (entry->target_name == NULL) {
		kfree(entry->primary_name);
		kfree(entry);
		return OUT_OF_MEMORY;
	}
	/* The update's kid is guaranteed to outlast the module_list_entry */
	entry->kid = pack->update->kid;
	entry->applied = to_be_applied;
	list_add(&entry->update_list, &pack->update->ksplice_module_list);
	return OK;
}

static void cleanup_module_list_entries(struct update *update)
{
	struct ksplice_module_list_entry *entry;
	list_for_each_entry(entry, &update->ksplice_module_list, update_list) {
		kfree(entry->target_name);
		kfree(entry->primary_name);
	}
	clear_list(&update->ksplice_module_list,
		   struct ksplice_module_list_entry, update_list);
}

/* Replacement address used for functions deleted by the patch */
static void __attribute__((noreturn)) ksplice_deleted(void)
{
	printk(KERN_CRIT "Called a kernel function deleted by Ksplice!\n");
	BUG();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
/* 91768d6c2bad0d2766a166f13f2f57e197de3458 was after 2.6.19 */
	for (;;);
#endif
}

/* Floodfill to run-pre match the sections within a pack. */
static abort_t match_pack_sections(struct ksplice_pack *pack,
				   bool consider_data_sections)
{
	struct ksplice_section *sect;
	abort_t ret;
	int remaining = 0;
	bool progress;

	for (sect = pack->helper_sections; sect < pack->helper_sections_end;
	     sect++) {
		if ((sect->flags & KSPLICE_SECTION_DATA) == 0 &&
		    (sect->flags & KSPLICE_SECTION_STRING) == 0 &&
		    (sect->flags & KSPLICE_SECTION_MATCHED) == 0)
			remaining++;
	}

	while (remaining > 0) {
		progress = false;
		for (sect = pack->helper_sections;
		     sect < pack->helper_sections_end; sect++) {
			if ((sect->flags & KSPLICE_SECTION_MATCHED) != 0)
				continue;
			if ((!consider_data_sections &&
			     (sect->flags & KSPLICE_SECTION_DATA) != 0) ||
			    (sect->flags & KSPLICE_SECTION_STRING) != 0)
				continue;
			ret = find_section(pack, sect);
			if (ret == OK) {
				sect->flags |= KSPLICE_SECTION_MATCHED;
				if ((sect->flags & KSPLICE_SECTION_DATA) == 0)
					remaining--;
				progress = true;
			} else if (ret != NO_MATCH) {
				return ret;
			}
		}

		if (progress)
			continue;

		for (sect = pack->helper_sections;
		     sect < pack->helper_sections_end; sect++) {
			if ((sect->flags & KSPLICE_SECTION_MATCHED) != 0 ||
			    (sect->flags & KSPLICE_SECTION_STRING) != 0)
				continue;
			ksdebug(pack, "run-pre: could not match %s "
				"section %s\n",
				(sect->flags & KSPLICE_SECTION_DATA) != 0 ?
				"data" :
				(sect->flags & KSPLICE_SECTION_RODATA) != 0 ?
				"rodata" : "text", sect->symbol->label);
		}
		ksdebug(pack, "Aborted.  run-pre: could not match some "
			"sections.\n");
		return NO_MATCH;
	}
	return OK;
}

/*
 * Search for the section in the running kernel.  Returns OK if and
 * only if it finds precisely one address in the kernel matching the
 * section.
 */
static abort_t find_section(struct ksplice_pack *pack,
			    struct ksplice_section *sect)
{
	int i;
	abort_t ret;
	unsigned long run_addr;
	LIST_HEAD(vals);
	struct candidate_val *v, *n;

#ifdef KSPLICE_STANDALONE
	ret = add_system_map_candidates(pack, pack->helper_system_map,
					pack->helper_system_map_end,
					sect->symbol->label, &vals);
	if (ret != OK) {
		release_vals(&vals);
		return ret;
	}
#endif /* KSPLICE_STANDALONE */
	ret = lookup_symbol(pack, sect->symbol, &vals);
	if (ret != OK) {
		release_vals(&vals);
		return ret;
	}

	ksdebug(pack, "run-pre: starting sect search for %s\n",
		sect->symbol->label);

	list_for_each_entry_safe(v, n, &vals, list) {
		run_addr = v->val;

		yield();
		ret = try_addr(pack, sect, run_addr, NULL, RUN_PRE_INITIAL);
		if (ret == NO_MATCH) {
			list_del(&v->list);
			kfree(v);
		} else if (ret != OK) {
			release_vals(&vals);
			return ret;
		}
	}

#if defined(KSPLICE_STANDALONE) && !defined(CONFIG_KALLSYMS)
	if (list_empty(&vals) && (sect->flags & KSPLICE_SECTION_DATA) == 0) {
		ret = brute_search_all(pack, sect, &vals);
		if (ret != OK) {
			release_vals(&vals);
			return ret;
		}
		/*
		 * Make sure run-pre matching output is displayed if
		 * brute_search succeeds.
		 */
		if (singular(&vals)) {
			run_addr = list_entry(vals.next, struct candidate_val,
					      list)->val;
			ret = try_addr(pack, sect, run_addr, NULL,
				       RUN_PRE_INITIAL);
			if (ret != OK) {
				ksdebug(pack, "run-pre: Debug run failed for "
					"sect %s:\n", sect->symbol->label);
				release_vals(&vals);
				return ret;
			}
		}
	}
#endif /* KSPLICE_STANDALONE && !CONFIG_KALLSYMS */

	if (singular(&vals)) {
		LIST_HEAD(safety_records);
		run_addr = list_entry(vals.next, struct candidate_val,
				      list)->val;
		ret = try_addr(pack, sect, run_addr, &safety_records,
			       RUN_PRE_FINAL);
		release_vals(&vals);
		if (ret != OK) {
			clear_list(&safety_records, struct safety_record, list);
			ksdebug(pack, "run-pre: Final run failed for sect "
				"%s:\n", sect->symbol->label);
		} else {
			list_splice(&safety_records, &pack->safety_records);
		}
		return ret;
	} else if (!list_empty(&vals)) {
		struct candidate_val *val;
		ksdebug(pack, "run-pre: multiple candidates for sect %s:\n",
			sect->symbol->label);
		i = 0;
		list_for_each_entry(val, &vals, list) {
			i++;
			ksdebug(pack, "%lx\n", val->val);
			if (i > 5) {
				ksdebug(pack, "...\n");
				break;
			}
		}
		release_vals(&vals);
		return NO_MATCH;
	}
	release_vals(&vals);
	return NO_MATCH;
}

/*
 * try_addr is the the interface to run-pre matching.  Its primary
 * purpose is to manage debugging information for run-pre matching;
 * all the hard work is in run_pre_cmp.
 */
static abort_t try_addr(struct ksplice_pack *pack,
			struct ksplice_section *sect,
			unsigned long run_addr,
			struct list_head *safety_records,
			enum run_pre_mode mode)
{
	abort_t ret;
	const struct module *run_module = __module_address(run_addr);

	if (run_module == pack->primary) {
		ksdebug(pack, "run-pre: unexpected address %lx in primary "
			"module %s for sect %s\n", run_addr, run_module->name,
			sect->symbol->label);
		return UNEXPECTED;
	}
	if (!patches_module(run_module, pack->target)) {
		ksdebug(pack, "run-pre: ignoring address %lx in other module "
			"%s for sect %s\n", run_addr, run_module == NULL ?
			"vmlinux" : run_module->name, sect->symbol->label);
		return NO_MATCH;
	}

	ret = create_labelval(pack, sect->symbol, run_addr, TEMP);
	if (ret != OK)
		return ret;

#ifdef CONFIG_FUNCTION_DATA_SECTIONS
	ret = run_pre_cmp(pack, sect, run_addr, safety_records, mode);
#else /* !CONFIG_FUNCTION_DATA_SECTIONS */
	if ((sect->flags & KSPLICE_SECTION_TEXT) != 0)
		ret = arch_run_pre_cmp(pack, sect, run_addr, safety_records,
				       mode);
	else
		ret = run_pre_cmp(pack, sect, run_addr, safety_records, mode);
#endif /* CONFIG_FUNCTION_DATA_SECTIONS */
	if (ret == NO_MATCH && mode != RUN_PRE_FINAL) {
		set_temp_labelvals(pack, NOVAL);
		ksdebug(pack, "run-pre: %s sect %s does not match (r_a=%lx "
			"p_a=%lx s=%lx)\n",
			(sect->flags & KSPLICE_SECTION_RODATA) != 0 ? "rodata" :
			(sect->flags & KSPLICE_SECTION_DATA) != 0 ? "data" :
			"text", sect->symbol->label, run_addr, sect->address,
			sect->size);
		ksdebug(pack, "run-pre: ");
		if (pack->update->debug >= 1) {
#ifdef CONFIG_FUNCTION_DATA_SECTIONS
			ret = run_pre_cmp(pack, sect, run_addr, safety_records,
					  RUN_PRE_DEBUG);
#else /* !CONFIG_FUNCTION_DATA_SECTIONS */
			if ((sect->flags & KSPLICE_SECTION_TEXT) != 0)
				ret = arch_run_pre_cmp(pack, sect, run_addr,
						       safety_records,
						       RUN_PRE_DEBUG);
			else
				ret = run_pre_cmp(pack, sect, run_addr,
						  safety_records,
						  RUN_PRE_DEBUG);
#endif /* CONFIG_FUNCTION_DATA_SECTIONS */
			set_temp_labelvals(pack, NOVAL);
		}
		ksdebug(pack, "\n");
		return ret;
	} else if (ret != OK) {
		set_temp_labelvals(pack, NOVAL);
		return ret;
	}

	if (mode != RUN_PRE_FINAL) {
		set_temp_labelvals(pack, NOVAL);
		ksdebug(pack, "run-pre: candidate for sect %s=%lx\n",
			sect->symbol->label, run_addr);
		return OK;
	}

	set_temp_labelvals(pack, VAL);
	ksdebug(pack, "run-pre: found sect %s=%lx\n", sect->symbol->label,
		run_addr);
	return OK;
}

/*
 * run_pre_cmp is the primary run-pre matching function; it determines
 * whether the given ksplice_section matches the code or data in the
 * running kernel starting at run_addr.
 *
 * If run_pre_mode is RUN_PRE_FINAL, a safety record for the matched
 * section is created.
 *
 * The run_pre_mode is also used to determine what debugging
 * information to display.
 */
static abort_t run_pre_cmp(struct ksplice_pack *pack,
			   const struct ksplice_section *sect,
			   unsigned long run_addr,
			   struct list_head *safety_records,
			   enum run_pre_mode mode)
{
	int matched = 0;
	abort_t ret;
	const struct ksplice_reloc *r, *finger;
	const unsigned char *pre, *run, *pre_start, *run_start;
	unsigned char runval;

	pre_start = (const unsigned char *)sect->address;
	run_start = (const unsigned char *)run_addr;

	finger = init_reloc_search(pack, sect);

	pre = pre_start;
	run = run_start;
	while (pre < pre_start + sect->size) {
		unsigned long offset = pre - pre_start;
		ret = lookup_reloc(pack, &finger, (unsigned long)pre, &r);
		if (ret == OK) {
			ret = handle_reloc(pack, sect, r, (unsigned long)run,
					   mode);
			if (ret != OK) {
				if (mode == RUN_PRE_INITIAL)
					ksdebug(pack, "reloc in sect does not "
						"match after %lx/%lx bytes\n",
						offset, sect->size);
				return ret;
			}
			if (mode == RUN_PRE_DEBUG)
				print_bytes(pack, run, r->howto->size, pre,
					    r->howto->size);
			pre += r->howto->size;
			run += r->howto->size;
			finger++;
			continue;
		} else if (ret != NO_MATCH) {
			return ret;
		}

		if ((sect->flags & KSPLICE_SECTION_TEXT) != 0) {
			ret = handle_paravirt(pack, (unsigned long)pre,
					      (unsigned long)run, &matched);
			if (ret != OK)
				return ret;
			if (matched != 0) {
				if (mode == RUN_PRE_DEBUG)
					print_bytes(pack, run, matched, pre,
						    matched);
				pre += matched;
				run += matched;
				continue;
			}
		}

		if (probe_kernel_read(&runval, (void *)run, 1) == -EFAULT) {
			if (mode == RUN_PRE_INITIAL)
				ksdebug(pack, "sect unmapped after %lx/%lx "
					"bytes\n", offset, sect->size);
			return NO_MATCH;
		}

		if (runval != *pre &&
		    (sect->flags & KSPLICE_SECTION_DATA) == 0) {
			if (mode == RUN_PRE_INITIAL)
				ksdebug(pack, "sect does not match after "
					"%lx/%lx bytes\n", offset, sect->size);
			if (mode == RUN_PRE_DEBUG) {
				print_bytes(pack, run, 1, pre, 1);
				ksdebug(pack, "[p_o=%lx] ! ", offset);
				print_bytes(pack, run + 1, 2, pre + 1, 2);
			}
			return NO_MATCH;
		}
		if (mode == RUN_PRE_DEBUG)
			print_bytes(pack, run, 1, pre, 1);
		pre++;
		run++;
	}
	return create_safety_record(pack, sect, safety_records, run_addr,
				    run - run_start);
}

static void print_bytes(struct ksplice_pack *pack,
			const unsigned char *run, int runc,
			const unsigned char *pre, int prec)
{
	int o;
	int matched = min(runc, prec);
	for (o = 0; o < matched; o++) {
		if (run[o] == pre[o])
			ksdebug(pack, "%02x ", run[o]);
		else
			ksdebug(pack, "%02x/%02x ", run[o], pre[o]);
	}
	for (o = matched; o < runc; o++)
		ksdebug(pack, "%02x/ ", run[o]);
	for (o = matched; o < prec; o++)
		ksdebug(pack, "/%02x ", pre[o]);
}

#if defined(KSPLICE_STANDALONE) && !defined(CONFIG_KALLSYMS)
static abort_t brute_search(struct ksplice_pack *pack,
			    struct ksplice_section *sect,
			    const void *start, unsigned long len,
			    struct list_head *vals)
{
	unsigned long addr;
	char run, pre;
	abort_t ret;

	for (addr = (unsigned long)start; addr < (unsigned long)start + len;
	     addr++) {
		if (addr % 100000 == 0)
			yield();

		if (probe_kernel_read(&run, (void *)addr, 1) == -EFAULT)
			return OK;

		pre = *(const unsigned char *)(sect->address);

		if (run != pre)
			continue;

		ret = try_addr(pack, sect, addr, NULL, RUN_PRE_INITIAL);
		if (ret == OK) {
			ret = add_candidate_val(pack, vals, addr);
			if (ret != OK)
				return ret;
		} else if (ret != NO_MATCH) {
			return ret;
		}
	}

	return OK;
}

static abort_t brute_search_all(struct ksplice_pack *pack,
				struct ksplice_section *sect,
				struct list_head *vals)
{
	struct module *m;
	abort_t ret = OK;
	int saved_debug;

	ksdebug(pack, "brute_search: searching for %s\n", sect->symbol->label);
	saved_debug = pack->update->debug;
	pack->update->debug = 0;

	list_for_each_entry(m, &modules, list) {
		if (!patches_module(m, pack->target) || m == pack->primary)
			continue;
		ret = brute_search(pack, sect, m->module_core, m->core_size,
				   vals);
		if (ret != OK)
			goto out;
		ret = brute_search(pack, sect, m->module_init, m->init_size,
				   vals);
		if (ret != OK)
			goto out;
	}

	ret = brute_search(pack, sect, (const void *)init_mm.start_code,
			   init_mm.end_code - init_mm.start_code, vals);

out:
	pack->update->debug = saved_debug;
	return ret;
}
#endif /* KSPLICE_STANDALONE && !CONFIG_KALLSYMS */

struct range {
	unsigned long address;
	unsigned long size;
};

static int reloc_bsearch_compare(const void *key, const void *elt)
{
	const struct range *range = key;
	const struct ksplice_reloc *r = elt;
	if (range->address + range->size <= r->blank_addr)
		return -1;
	if (range->address > r->blank_addr)
		return 1;
	return 0;
}

static const struct ksplice_reloc *find_reloc(const struct ksplice_reloc *start,
					      const struct ksplice_reloc *end,
					      unsigned long address,
					      unsigned long size)
{
	const struct ksplice_reloc *r;
	struct range range = { address, size };
	r = bsearch((void *)&range, start, end - start, sizeof(*r),
		    reloc_bsearch_compare);
	if (r == NULL)
		return NULL;
	while (r > start && (r - 1)->blank_addr >= address)
		r--;
	return r;
}

static const struct ksplice_reloc *
init_reloc_search(struct ksplice_pack *pack, const struct ksplice_section *sect)
{
	const struct ksplice_reloc *r;
	r = find_reloc(pack->helper_relocs, pack->helper_relocs_end,
		       sect->address, sect->size);
	if (r == NULL)
		return pack->helper_relocs_end;
	return r;
}

/*
 * lookup_reloc implements an amortized O(1) lookup for the next
 * helper relocation.  It must be called with a strictly increasing
 * sequence of addresses.
 *
 * The fingerp is private data for lookup_reloc, and needs to have
 * been initialized as a pointer to the result of find_reloc (or
 * init_reloc_search).
 */
static abort_t lookup_reloc(struct ksplice_pack *pack,
			    const struct ksplice_reloc **fingerp,
			    unsigned long addr,
			    const struct ksplice_reloc **relocp)
{
	const struct ksplice_reloc *r = *fingerp;
	int canary_ret;

	while (r < pack->helper_relocs_end &&
	       addr >= r->blank_addr + r->howto->size &&
	       !(addr == r->blank_addr && r->howto->size == 0))
		r++;
	*fingerp = r;
	if (r == pack->helper_relocs_end)
		return NO_MATCH;
	if (addr < r->blank_addr)
		return NO_MATCH;
	*relocp = r;
	if (r->howto->type != KSPLICE_HOWTO_RELOC)
		return OK;

	canary_ret = contains_canary(pack, r->blank_addr, r->howto);
	if (canary_ret < 0)
		return UNEXPECTED;
	if (canary_ret == 0) {
		ksdebug(pack, "run-pre: reloc skipped at p_a=%lx to %s+%lx "
			"(altinstr)\n", r->blank_addr, r->symbol->label,
			r->target_addend);
		return NO_MATCH;
	}
	if (addr != r->blank_addr) {
		ksdebug(pack, "Invalid nonzero relocation offset\n");
		return UNEXPECTED;
	}
	return OK;
}

static abort_t handle_reloc(struct ksplice_pack *pack,
			    const struct ksplice_section *sect,
			    const struct ksplice_reloc *r,
			    unsigned long run_addr, enum run_pre_mode mode)
{
	switch (r->howto->type) {
	case KSPLICE_HOWTO_RELOC:
		return handle_howto_reloc(pack, sect, r, run_addr, mode);
	case KSPLICE_HOWTO_DATE:
	case KSPLICE_HOWTO_TIME:
		return handle_howto_date(pack, sect, r, run_addr, mode);
	case KSPLICE_HOWTO_BUG:
		return handle_bug(pack, r, run_addr);
	case KSPLICE_HOWTO_EXTABLE:
		return handle_extable(pack, r, run_addr);
	default:
		ksdebug(pack, "Unexpected howto type %d\n", r->howto->type);
		return UNEXPECTED;
	}
}

/*
 * For date/time relocations, we check that the sequence of bytes
 * matches the format of a date or time.
 */
static abort_t handle_howto_date(struct ksplice_pack *pack,
				 const struct ksplice_section *sect,
				 const struct ksplice_reloc *r,
				 unsigned long run_addr, enum run_pre_mode mode)
{
	abort_t ret;
	char *buf = kmalloc(r->howto->size, GFP_KERNEL);

	if (buf == NULL)
		return OUT_OF_MEMORY;
	if (probe_kernel_read(buf, (void *)run_addr, r->howto->size) == -EFAULT) {
		ret = NO_MATCH;
		goto out;
	}

	switch (r->howto->type) {
	case KSPLICE_HOWTO_TIME:
		if (isdigit(buf[0]) && isdigit(buf[1]) && buf[2] == ':' &&
		    isdigit(buf[3]) && isdigit(buf[4]) && buf[5] == ':' &&
		    isdigit(buf[6]) && isdigit(buf[7]))
			ret = OK;
		else
			ret = NO_MATCH;
		break;
	case KSPLICE_HOWTO_DATE:
		if (isalpha(buf[0]) && isalpha(buf[1]) && isalpha(buf[2]) &&
		    buf[3] == ' ' && (buf[4] == ' ' || isdigit(buf[4])) &&
		    isdigit(buf[5]) && buf[6] == ' ' && isdigit(buf[7]) &&
		    isdigit(buf[8]) && isdigit(buf[9]) && isdigit(buf[10]))
			ret = OK;
		else
			ret = NO_MATCH;
		break;
	default:
		ret = UNEXPECTED;
	}
	if (ret == NO_MATCH && mode == RUN_PRE_INITIAL)
		ksdebug(pack, "%s string: \"%.*s\" does not match format\n",
			r->howto->type == KSPLICE_HOWTO_DATE ? "date" : "time",
			r->howto->size, buf);

	if (ret != OK)
		goto out;
	ret = create_labelval(pack, r->symbol, run_addr, TEMP);
out:
	kfree(buf);
	return ret;
}

/*
 * Extract the value of a symbol used in a relocation in the pre code
 * during run-pre matching, giving an error if it conflicts with a
 * previously found value of that symbol
 */
static abort_t handle_howto_reloc(struct ksplice_pack *pack,
				  const struct ksplice_section *sect,
				  const struct ksplice_reloc *r,
				  unsigned long run_addr,
				  enum run_pre_mode mode)
{
	struct ksplice_section *sym_sect = symbol_section(pack, r->symbol);
	unsigned long offset = r->target_addend;
	unsigned long val;
	abort_t ret;

	ret = read_reloc_value(pack, r, run_addr, &val);
	if (ret != OK)
		return ret;
	if (r->howto->pcrel)
		val += run_addr;

#ifdef KSPLICE_STANDALONE
	/* The match_map is only used in KSPLICE_STANDALONE */
	if (sym_sect == NULL || sym_sect->match_map == NULL || offset == 0) {
		;
	} else if (offset < 0 || offset >= sym_sect->size) {
		ksdebug(pack, "Out of range relocation: %s+%lx -> %s+%lx",
			sect->symbol->label, r->blank_addr - sect->address,
			r->symbol->label, offset);
		return NO_MATCH;
	} else if (sect == sym_sect && sect->match_map[offset] == NULL) {
		sym_sect->match_map[offset] =
		    (const unsigned char *)r->symbol->value + offset;
	} else if (sect == sym_sect && (unsigned long)sect->match_map[offset] ==
		   r->symbol->value + offset) {
		;
	} else if (sect == sym_sect) {
		ksdebug(pack, "Relocations to nonmatching locations within "
			"section %s: %lx does not match %lx\n",
			sect->symbol->label, offset,
			(unsigned long)sect->match_map[offset] -
			r->symbol->value);
		return NO_MATCH;
	} else if ((sym_sect->flags & KSPLICE_SECTION_MATCHED) == 0) {
		if (mode == RUN_PRE_INITIAL)
			ksdebug(pack, "Delaying matching of %s due to reloc "
				"from to unmatching section: %s+%lx\n",
				sect->symbol->label, r->symbol->label, offset);
		return NO_MATCH;
	} else if (sym_sect->match_map[offset] == NULL) {
		if (mode == RUN_PRE_INITIAL)
			ksdebug(pack, "Relocation not to instruction boundary: "
				"%s+%lx -> %s+%lx", sect->symbol->label,
				r->blank_addr - sect->address, r->symbol->label,
				offset);
		return NO_MATCH;
	} else if ((unsigned long)sym_sect->match_map[offset] !=
		   r->symbol->value + offset) {
		if (mode == RUN_PRE_INITIAL)
			ksdebug(pack, "Match map shift %s+%lx: %lx != %lx\n",
				r->symbol->label, offset,
				r->symbol->value + offset,
				(unsigned long)sym_sect->match_map[offset]);
		val += r->symbol->value + offset -
		    (unsigned long)sym_sect->match_map[offset];
	}
#endif /* KSPLICE_STANDALONE */

	if (mode == RUN_PRE_INITIAL)
		ksdebug(pack, "run-pre: reloc at r_a=%lx p_a=%lx to %s+%lx: "
			"found %s = %lx\n", run_addr, r->blank_addr,
			r->symbol->label, offset, r->symbol->label, val);

	if (contains_canary(pack, run_addr, r->howto) != 0) {
		ksdebug(pack, "Aborted.  Unexpected canary in run code at %lx"
			"\n", run_addr);
		return UNEXPECTED;
	}

	if ((sect->flags & KSPLICE_SECTION_DATA) != 0 &&
	    sect->symbol == r->symbol)
		return OK;
	ret = create_labelval(pack, r->symbol, val, TEMP);
	if (ret == NO_MATCH && mode == RUN_PRE_INITIAL)
		ksdebug(pack, "run-pre: reloc at r_a=%lx p_a=%lx: labelval %s "
			"= %lx does not match expected %lx\n", run_addr,
			r->blank_addr, r->symbol->label, r->symbol->value, val);

	if (ret != OK)
		return ret;
	if (sym_sect != NULL && (sym_sect->flags & KSPLICE_SECTION_MATCHED) == 0
	    && (sym_sect->flags & KSPLICE_SECTION_STRING) != 0) {
		if (mode == RUN_PRE_INITIAL)
			ksdebug(pack, "Recursively comparing string section "
				"%s\n", sym_sect->symbol->label);
		else if (mode == RUN_PRE_DEBUG)
			ksdebug(pack, "[str start] ");
		ret = run_pre_cmp(pack, sym_sect, val, NULL, mode);
		if (mode == RUN_PRE_DEBUG)
			ksdebug(pack, "[str end] ");
		if (ret == OK && mode == RUN_PRE_INITIAL)
			ksdebug(pack, "Successfully matched string section %s"
				"\n", sym_sect->symbol->label);
		else if (mode == RUN_PRE_INITIAL)
			ksdebug(pack, "Failed to match string section %s\n",
				sym_sect->symbol->label);
	}
	return ret;
}

static int symbol_section_bsearch_compare(const void *a, const void *b)
{
	const struct ksplice_symbol *sym = a;
	const struct ksplice_section *sect = b;
	return strcmp(sym->label, sect->symbol->label);
}

static int compare_section_labels(const void *va, const void *vb)
{
	const struct ksplice_section *a = va, *b = vb;
	return strcmp(a->symbol->label, b->symbol->label);
}

static struct ksplice_section *symbol_section(struct ksplice_pack *pack,
					      const struct ksplice_symbol *sym)
{
	return bsearch(sym, pack->helper_sections, pack->helper_sections_end -
		       pack->helper_sections, sizeof(struct ksplice_section),
		       symbol_section_bsearch_compare);
}

/* Find the relocation for the oldaddr of a ksplice_patch */
static const struct ksplice_reloc *patch_reloc(struct ksplice_pack *pack,
					       const struct ksplice_patch *p)
{
	unsigned long addr = (unsigned long)&p->oldaddr;
	const struct ksplice_reloc *r =
	    find_reloc(pack->primary_relocs, pack->primary_relocs_end, addr,
		       sizeof(addr));
	if (r == NULL || r->blank_addr < addr ||
	    r->blank_addr >= addr + sizeof(addr))
		return NULL;
	return r;
}

/*
 * Populates vals with the possible values for ksym from the various
 * sources Ksplice uses to resolve symbols
 */
static abort_t lookup_symbol(struct ksplice_pack *pack,
			     const struct ksplice_symbol *ksym,
			     struct list_head *vals)
{
	abort_t ret;

#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return OK;
#endif /* KSPLICE_STANDALONE */

	if (ksym->vals == NULL) {
		release_vals(vals);
		ksdebug(pack, "using detected sym %s=%lx\n", ksym->label,
			ksym->value);
		return add_candidate_val(pack, vals, ksym->value);
	}

#ifdef CONFIG_MODULE_UNLOAD
	if (strcmp(ksym->label, "cleanup_module") == 0 && pack->target != NULL
	    && pack->target->exit != NULL) {
		ret = add_candidate_val(pack, vals,
					(unsigned long)pack->target->exit);
		if (ret != OK)
			return ret;
	}
#endif

	if (ksym->name != NULL) {
		struct candidate_val *val;
		list_for_each_entry(val, ksym->vals, list) {
			ret = add_candidate_val(pack, vals, val->val);
			if (ret != OK)
				return ret;
		}

		ret = new_export_lookup(pack, ksym->name, vals);
		if (ret != OK)
			return ret;
	}

	return OK;
}

#ifdef KSPLICE_STANDALONE
static abort_t
add_system_map_candidates(struct ksplice_pack *pack,
			  const struct ksplice_system_map *start,
			  const struct ksplice_system_map *end,
			  const char *label, struct list_head *vals)
{
	abort_t ret;
	long off;
	int i;
	const struct ksplice_system_map *smap;

	/* Some Fedora kernel releases have System.map files whose symbol
	 * addresses disagree with the running kernel by a constant address
	 * offset because of the CONFIG_PHYSICAL_START and CONFIG_PHYSICAL_ALIGN
	 * values used to compile these kernels.  This constant address offset
	 * is always a multiple of 0x100000.
	 *
	 * If we observe an offset that is NOT a multiple of 0x100000, then the
	 * user provided us with an incorrect System.map file, and we should
	 * abort.
	 * If we observe an offset that is a multiple of 0x100000, then we can
	 * adjust the System.map address values accordingly and proceed.
	 */
	off = (unsigned long)printk - pack->map_printk;
	if (off & 0xfffff) {
		ksdebug(pack, "Aborted.  System.map does not match kernel.\n");
		return BAD_SYSTEM_MAP;
	}

	smap = bsearch(label, start, end - start, sizeof(*smap),
		       system_map_bsearch_compare);
	if (smap == NULL)
		return OK;

	for (i = 0; i < smap->nr_candidates; i++) {
		ret = add_candidate_val(pack, vals, smap->candidates[i] + off);
		if (ret != OK)
			return ret;
	}
	return OK;
}

static int system_map_bsearch_compare(const void *key, const void *elt)
{
	const struct ksplice_system_map *map = elt;
	const char *label = key;
	return strcmp(label, map->label);
}
#endif /* !KSPLICE_STANDALONE */

/*
 * An update could one module to export a symbol and at the same time
 * change another module to use that symbol.  This violates the normal
 * situation where the packs can be handled independently.
 *
 * new_export_lookup obtains symbol values from the changes to the
 * exported symbol table made by other packs.
 */
static abort_t new_export_lookup(struct ksplice_pack *ipack, const char *name,
				 struct list_head *vals)
{
	struct ksplice_pack *pack;
	struct ksplice_patch *p;
	list_for_each_entry(pack, &ipack->update->packs, list) {
		for (p = pack->patches; p < pack->patches_end; p++) {
			const struct kernel_symbol *sym;
			const struct ksplice_reloc *r;
			if (p->type != KSPLICE_PATCH_EXPORT ||
			    strcmp(name, *(const char **)p->contents) != 0)
				continue;

			/* Check that the p->oldaddr reloc has been resolved. */
			r = patch_reloc(pack, p);
			if (r == NULL ||
			    contains_canary(pack, r->blank_addr, r->howto) != 0)
				continue;
			sym = (const struct kernel_symbol *)r->symbol->value;

			/*
			 * Check that the sym->value reloc has been resolved,
			 * if there is a Ksplice relocation there.
			 */
			r = find_reloc(pack->primary_relocs,
				       pack->primary_relocs_end,
				       (unsigned long)&sym->value,
				       sizeof(&sym->value));
			if (r != NULL &&
			    r->blank_addr == (unsigned long)&sym->value &&
			    contains_canary(pack, r->blank_addr, r->howto) != 0)
				continue;
			return add_candidate_val(ipack, vals, sym->value);
		}
	}
	return OK;
}

/*
 * When apply_patches is called, the update should be fully prepared.
 * apply_patches will try to actually insert trampolines for the
 * update.
 */
static abort_t apply_patches(struct update *update)
{
	int i;
	abort_t ret;
	struct ksplice_pack *pack;

	ret = map_trampoline_pages(update);
	if (ret != OK)
		return ret;

	list_for_each_entry(pack, &update->packs, list) {
		const typeof(int (*)(void)) *f;
		for (f = pack->pre_apply; f < pack->pre_apply_end; f++) {
			if ((*f)() != 0) {
				ret = CALL_FAILED;
				goto out;
			}
		}
	}

	for (i = 0; i < 5; i++) {
		cleanup_conflicts(update);
#ifdef KSPLICE_STANDALONE
		bust_spinlocks(1);
#endif /* KSPLICE_STANDALONE */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
		ret = (__force abort_t)stop_machine(__apply_patches, update,
						    NULL);
#else /* LINUX_VERSION_CODE < */
/* 9b1a4d38373a5581a4e01032a3ccdd94cd93477b was after 2.6.26 */
		ret = (__force abort_t)stop_machine_run(__apply_patches, update,
							NR_CPUS);
#endif /* LINUX_VERSION_CODE */
#ifdef KSPLICE_STANDALONE
		bust_spinlocks(0);
#endif /* KSPLICE_STANDALONE */
		if (ret != CODE_BUSY)
			break;
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
	}
out:
	unmap_trampoline_pages(update);

	if (ret == CODE_BUSY) {
		print_conflicts(update);
		_ksdebug(update, "Aborted %s.  stack check: to-be-replaced "
			 "code is busy.\n", update->kid);
	} else if (ret == ALREADY_REVERSED) {
		_ksdebug(update, "Aborted %s.  Ksplice update %s is already "
			 "reversed.\n", update->kid, update->kid);
	}

	if (ret != OK) {
		list_for_each_entry(pack, &update->packs, list) {
			const typeof(void (*)(void)) *f;
			for (f = pack->fail_apply; f < pack->fail_apply_end;
			     f++)
				(*f)();
		}

		return ret;
	}

	list_for_each_entry(pack, &update->packs, list) {
		const typeof(void (*)(void)) *f;
		for (f = pack->post_apply; f < pack->post_apply_end; f++)
			(*f)();
	}

	_ksdebug(update, "Atomic patch insertion for %s complete\n",
		 update->kid);
	return OK;
}

static abort_t reverse_patches(struct update *update)
{
	int i;
	abort_t ret;
	struct ksplice_pack *pack;

	clear_debug_buf(update);
	ret = init_debug_buf(update);
	if (ret != OK)
		return ret;

	_ksdebug(update, "Preparing to reverse %s\n", update->kid);

	ret = map_trampoline_pages(update);
	if (ret != OK)
		return ret;

	list_for_each_entry(pack, &update->packs, list) {
		const typeof(int (*)(void)) *f;
		for (f = pack->pre_reverse; f < pack->pre_reverse_end; f++) {
			if ((*f)() != 0) {
				ret = CALL_FAILED;
				goto out;
			}
		}
	}

	for (i = 0; i < 5; i++) {
		cleanup_conflicts(update);
		clear_list(&update->conflicts, struct conflict, list);
#ifdef KSPLICE_STANDALONE
		bust_spinlocks(1);
#endif /* KSPLICE_STANDALONE */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
		ret = (__force abort_t)stop_machine(__reverse_patches, update,
						    NULL);
#else /* LINUX_VERSION_CODE < */
/* 9b1a4d38373a5581a4e01032a3ccdd94cd93477b was after 2.6.26 */
		ret = (__force abort_t)stop_machine_run(__reverse_patches,
							update, NR_CPUS);
#endif /* LINUX_VERSION_CODE */
#ifdef KSPLICE_STANDALONE
		bust_spinlocks(0);
#endif /* KSPLICE_STANDALONE */
		if (ret != CODE_BUSY)
			break;
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
	}
out:
	unmap_trampoline_pages(update);

	if (ret == CODE_BUSY) {
		print_conflicts(update);
		_ksdebug(update, "Aborted %s.  stack check: to-be-reversed "
			 "code is busy.\n", update->kid);
	} else if (ret == MODULE_BUSY) {
		_ksdebug(update, "Update %s is in use by another module\n",
			 update->kid);
	}

	if (ret != OK) {
		list_for_each_entry(pack, &update->packs, list) {
			const typeof(void (*)(void)) *f;
			for (f = pack->fail_reverse; f < pack->fail_reverse_end;
			     f++)
				(*f)();
		}

		return ret;
	}

	list_for_each_entry(pack, &update->packs, list) {
		const typeof(void (*)(void)) *f;
		for (f = pack->post_reverse; f < pack->post_reverse_end; f++)
			(*f)();
	}

	list_for_each_entry(pack, &update->packs, list)
		clear_list(&pack->safety_records, struct safety_record, list);

	_ksdebug(update, "Atomic patch removal for %s complete\n", update->kid);
	return OK;
}

/* Atomically insert the update; run from within stop_machine */
static int __apply_patches(void *updateptr)
{
	struct update *update = updateptr;
	struct ksplice_pack *pack;
	struct ksplice_module_list_entry *entry;
	struct ksplice_patch *p;
	abort_t ret;

	if (update->stage == STAGE_APPLIED)
		return (__force int)OK;

	if (update->stage != STAGE_PREPARING)
		return (__force int)UNEXPECTED;

	ret = check_each_task(update);
	if (ret != OK)
		return (__force int)ret;

	list_for_each_entry(pack, &update->packs, list) {
		if (try_module_get(pack->primary) != 1) {
			struct ksplice_pack *pack1;
			list_for_each_entry(pack1, &update->packs, list) {
				if (pack1 == pack)
					break;
				module_put(pack1->primary);
			}
			module_put(THIS_MODULE);
			return (__force int)UNEXPECTED;
		}
	}

	list_for_each_entry(pack, &update->packs, list) {
		const typeof(int (*)(void)) *f;
		for (f = pack->check_apply; f < pack->check_apply_end; f++)
			if ((*f)() != 0)
				return (__force int)CALL_FAILED;
	}

	/* Commit point: the update application will succeed. */

	update->stage = STAGE_APPLIED;
#ifdef TAINT_KSPLICE
	add_taint(TAINT_KSPLICE);
#endif

	list_for_each_entry(entry, &update->ksplice_module_list, update_list)
		list_add(&entry->list, &ksplice_module_list);

	list_for_each_entry(pack, &update->packs, list) {
		for (p = pack->patches; p < pack->patches_end; p++)
			insert_trampoline(p);
	}

	list_for_each_entry(pack, &update->packs, list) {
		const typeof(void (*)(void)) *f;
		for (f = pack->apply; f < pack->apply_end; f++)
			(*f)();
	}

	return (__force int)OK;
}

/* Atomically remove the update; run from within stop_machine */
static int __reverse_patches(void *updateptr)
{
	struct update *update = updateptr;
	struct ksplice_pack *pack;
	struct ksplice_module_list_entry *entry;
	const struct ksplice_patch *p;
	abort_t ret;

	if (update->stage != STAGE_APPLIED)
		return (__force int)OK;

#ifdef CONFIG_MODULE_UNLOAD
	list_for_each_entry(pack, &update->packs, list) {
		if (module_refcount(pack->primary) != 1)
			return (__force int)MODULE_BUSY;
	}
#endif /* CONFIG_MODULE_UNLOAD */

	list_for_each_entry(entry, &update->ksplice_module_list, update_list) {
		if (!entry->applied && find_module(entry->target_name) != NULL)
			return COLD_UPDATE_LOADED;
	}

	ret = check_each_task(update);
	if (ret != OK)
		return (__force int)ret;

	list_for_each_entry(pack, &update->packs, list) {
		for (p = pack->patches; p < pack->patches_end; p++) {
			ret = verify_trampoline(pack, p);
			if (ret != OK)
				return (__force int)ret;
		}
	}

	list_for_each_entry(pack, &update->packs, list) {
		const typeof(int (*)(void)) *f;
		for (f = pack->check_reverse; f < pack->check_reverse_end; f++)
			if ((*f)() != 0)
				return (__force int)CALL_FAILED;
	}

	/* Commit point: the update reversal will succeed. */

	update->stage = STAGE_REVERSED;

	list_for_each_entry(pack, &update->packs, list)
		module_put(pack->primary);

	list_for_each_entry(entry, &update->ksplice_module_list, update_list)
		list_del(&entry->list);

	list_for_each_entry(pack, &update->packs, list) {
		const typeof(void (*)(void)) *f;
		for (f = pack->reverse; f < pack->reverse_end; f++)
			(*f)();
	}

	list_for_each_entry(pack, &update->packs, list) {
		for (p = pack->patches; p < pack->patches_end; p++)
			remove_trampoline(p);
	}

	return (__force int)OK;
}

/*
 * Check whether any thread's instruction pointer or any address of
 * its stack is contained in one of the safety_records associated with
 * the update.
 *
 * check_each_task must be called from inside stop_machine, because it
 * does not take tasklist_lock (which cannot be held by anyone else
 * during stop_machine).
 */
static abort_t check_each_task(struct update *update)
{
	const struct task_struct *g, *p;
	abort_t status = OK, ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
/* 5d4564e68210e4b1edb3f013bc3e59982bb35737 was after 2.6.10 */
	read_lock(&tasklist_lock);
#endif /* LINUX_VERSION_CODE */
	do_each_thread(g, p) {
		/* do_each_thread is a double loop! */
		ret = check_task(update, p, false);
		if (ret != OK) {
			check_task(update, p, true);
			status = ret;
		}
		if (ret != OK && ret != CODE_BUSY)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
/* 5d4564e68210e4b1edb3f013bc3e59982bb35737 was after 2.6.10 */
			goto out;
#else /* LINUX_VERSION_CODE < */
			return ret;
#endif /* LINUX_VERSION_CODE */
	} while_each_thread(g, p);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
/* 5d4564e68210e4b1edb3f013bc3e59982bb35737 was after 2.6.10 */
out:
	read_unlock(&tasklist_lock);
#endif /* LINUX_VERSION_CODE */
	return status;
}

static abort_t check_task(struct update *update,
			  const struct task_struct *t, bool rerun)
{
	abort_t status, ret;
	struct conflict *conf = NULL;

	if (rerun) {
		conf = kmalloc(sizeof(*conf), GFP_ATOMIC);
		if (conf == NULL)
			return OUT_OF_MEMORY;
		conf->process_name = kstrdup(t->comm, GFP_ATOMIC);
		if (conf->process_name == NULL) {
			kfree(conf);
			return OUT_OF_MEMORY;
		}
		conf->pid = t->pid;
		INIT_LIST_HEAD(&conf->stack);
		list_add(&conf->list, &update->conflicts);
	}

	status = check_address(update, conf, KSPLICE_IP(t));
	if (t == current) {
		ret = check_stack(update, conf, task_thread_info(t),
				  (unsigned long *)__builtin_frame_address(0));
		if (status == OK)
			status = ret;
	} else if (!task_curr(t)) {
		ret = check_stack(update, conf, task_thread_info(t),
				  (unsigned long *)KSPLICE_SP(t));
		if (status == OK)
			status = ret;
	} else if (!is_stop_machine(t)) {
		status = UNEXPECTED_RUNNING_TASK;
	}
	return status;
}

static abort_t check_stack(struct update *update, struct conflict *conf,
			   const struct thread_info *tinfo,
			   const unsigned long *stack)
{
	abort_t status = OK, ret;
	unsigned long addr;

	while (valid_stack_ptr(tinfo, stack)) {
		addr = *stack++;
		ret = check_address(update, conf, addr);
		if (ret != OK)
			status = ret;
	}
	return status;
}

static abort_t check_address(struct update *update,
			     struct conflict *conf, unsigned long addr)
{
	abort_t status = OK, ret;
	const struct safety_record *rec;
	struct ksplice_pack *pack;
	struct conflict_addr *ca = NULL;

	if (conf != NULL) {
		ca = kmalloc(sizeof(*ca), GFP_ATOMIC);
		if (ca == NULL)
			return OUT_OF_MEMORY;
		ca->addr = addr;
		ca->has_conflict = false;
		ca->label = NULL;
		list_add(&ca->list, &conf->stack);
	}

	list_for_each_entry(pack, &update->packs, list) {
		unsigned long tramp_addr = follow_trampolines(pack, addr);
		list_for_each_entry(rec, &pack->safety_records, list) {
			ret = check_record(ca, rec, tramp_addr);
			if (ret != OK)
				status = ret;
		}
	}
	return status;
}

static abort_t check_record(struct conflict_addr *ca,
			    const struct safety_record *rec, unsigned long addr)
{
	if (addr >= rec->addr && addr < rec->addr + rec->size) {
		if (ca != NULL) {
			ca->label = rec->label;
			ca->has_conflict = true;
		}
		return CODE_BUSY;
	}
	return OK;
}

/* Is the task one of the stop_machine tasks? */
static bool is_stop_machine(const struct task_struct *t)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
	const char *kstop_prefix = "kstop/";
#else /* LINUX_VERSION_CODE < */
/* c9583e55fa2b08a230c549bd1e3c0bde6c50d9cc was after 2.6.27 */
	const char *kstop_prefix = "kstop";
#endif /* LINUX_VERSION_CODE */
	const char *num;
	if (!starts_with(t->comm, kstop_prefix))
		return false;
	num = t->comm + strlen(kstop_prefix);
	return num[strspn(num, "0123456789")] == '\0';
#else /* LINUX_VERSION_CODE < */
/* ffdb5976c47609c862917d4c186ecbb5706d2dda was after 2.6.26 */
	return strcmp(t->comm, "kstopmachine") == 0;
#endif /* LINUX_VERSION_CODE */
}

static void cleanup_conflicts(struct update *update)
{
	struct conflict *conf;
	list_for_each_entry(conf, &update->conflicts, list) {
		clear_list(&conf->stack, struct conflict_addr, list);
		kfree(conf->process_name);
	}
	clear_list(&update->conflicts, struct conflict, list);
}

static void print_conflicts(struct update *update)
{
	const struct conflict *conf;
	const struct conflict_addr *ca;
	list_for_each_entry(conf, &update->conflicts, list) {
		_ksdebug(update, "stack check: pid %d (%s):", conf->pid,
			 conf->process_name);
		list_for_each_entry(ca, &conf->stack, list) {
			_ksdebug(update, " %lx", ca->addr);
			if (ca->has_conflict)
				_ksdebug(update, " [<-CONFLICT]");
		}
		_ksdebug(update, "\n");
	}
}

static void insert_trampoline(struct ksplice_patch *p)
{
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	memcpy(p->saved, p->vaddr, p->size);
	memcpy(p->vaddr, p->contents, p->size);
	flush_icache_range(p->oldaddr, p->oldaddr + p->size);
	set_fs(old_fs);
}

static abort_t verify_trampoline(struct ksplice_pack *pack,
				 const struct ksplice_patch *p)
{
	if (memcmp(p->vaddr, p->contents, p->size) != 0) {
		ksdebug(pack, "Aborted.  Trampoline at %lx has been "
			"overwritten.\n", p->oldaddr);
		return CODE_BUSY;
	}
	return OK;
}

static void remove_trampoline(const struct ksplice_patch *p)
{
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	memcpy(p->vaddr, p->saved, p->size);
	flush_icache_range(p->oldaddr, p->oldaddr + p->size);
	set_fs(old_fs);
}

/* Returns NO_MATCH if there's already a labelval with a different value */
static abort_t create_labelval(struct ksplice_pack *pack,
			       struct ksplice_symbol *ksym,
			       unsigned long val, int status)
{
	val = follow_trampolines(pack, val);
	if (ksym->vals == NULL)
		return ksym->value == val ? OK : NO_MATCH;

	ksym->value = val;
	if (status == TEMP) {
		struct labelval *lv = kmalloc(sizeof(*lv), GFP_KERNEL);
		if (lv == NULL)
			return OUT_OF_MEMORY;
		lv->symbol = ksym;
		lv->saved_vals = ksym->vals;
		list_add(&lv->list, &pack->temp_labelvals);
	}
	ksym->vals = NULL;
	return OK;
}

/*
 * Creates a new safety_record for a helper section based on its
 * ksplice_section and run-pre matching information.
 */
static abort_t create_safety_record(struct ksplice_pack *pack,
				    const struct ksplice_section *sect,
				    struct list_head *record_list,
				    unsigned long run_addr,
				    unsigned long run_size)
{
	struct safety_record *rec;
	struct ksplice_patch *p;

	if (record_list == NULL)
		return OK;

	for (p = pack->patches; p < pack->patches_end; p++) {
		const struct ksplice_reloc *r = patch_reloc(pack, p);
		if (strcmp(sect->symbol->label, r->symbol->label) == 0)
			break;
	}
	if (p >= pack->patches_end)
		return OK;

	rec = kmalloc(sizeof(*rec), GFP_KERNEL);
	if (rec == NULL)
		return OUT_OF_MEMORY;
	/*
	 * The helper might be unloaded when checking reversing
	 * patches, so we need to kstrdup the label here.
	 */
	rec->label = kstrdup(sect->symbol->label, GFP_KERNEL);
	if (rec->label == NULL) {
		kfree(rec);
		return OUT_OF_MEMORY;
	}
	rec->addr = run_addr;
	rec->size = run_size;

	list_add(&rec->list, record_list);
	return OK;
}

static abort_t add_candidate_val(struct ksplice_pack *pack,
				 struct list_head *vals, unsigned long val)
{
	struct candidate_val *tmp, *new;

/*
 * Careful: follow trampolines before comparing values so that we do
 * not mistake the obsolete function for another copy of the function.
 */
	val = follow_trampolines(pack, val);

	list_for_each_entry(tmp, vals, list) {
		if (tmp->val == val)
			return OK;
	}
	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (new == NULL)
		return OUT_OF_MEMORY;
	new->val = val;
	list_add(&new->list, vals);
	return OK;
}

static void release_vals(struct list_head *vals)
{
	clear_list(vals, struct candidate_val, list);
}

/*
 * The temp_labelvals list is used to cache those temporary labelvals
 * that have been created to cross-check the symbol values obtained
 * from different relocations within a single section being matched.
 *
 * If status is VAL, commit the temp_labelvals as final values.
 *
 * If status is NOVAL, restore the list of possible values to the
 * ksplice_symbol, so that it no longer has a known value.
 */
static void set_temp_labelvals(struct ksplice_pack *pack, int status)
{
	struct labelval *lv, *n;
	list_for_each_entry_safe(lv, n, &pack->temp_labelvals, list) {
		if (status == NOVAL) {
			lv->symbol->vals = lv->saved_vals;
		} else {
			release_vals(lv->saved_vals);
			kfree(lv->saved_vals);
		}
		list_del(&lv->list);
		kfree(lv);
	}
}

/* Is there a Ksplice canary with given howto at blank_addr? */
static int contains_canary(struct ksplice_pack *pack, unsigned long blank_addr,
			   const struct ksplice_reloc_howto *howto)
{
	switch (howto->size) {
	case 1:
		return (*(uint8_t *)blank_addr & howto->dst_mask) ==
		    (KSPLICE_CANARY & howto->dst_mask);
	case 2:
		return (*(uint16_t *)blank_addr & howto->dst_mask) ==
		    (KSPLICE_CANARY & howto->dst_mask);
	case 4:
		return (*(uint32_t *)blank_addr & howto->dst_mask) ==
		    (KSPLICE_CANARY & howto->dst_mask);
#if BITS_PER_LONG >= 64
	case 8:
		return (*(uint64_t *)blank_addr & howto->dst_mask) ==
		    (KSPLICE_CANARY & howto->dst_mask);
#endif /* BITS_PER_LONG */
	default:
		ksdebug(pack, "Aborted.  Invalid relocation size.\n");
		return -1;
	}
}

/*
 * Compute the address of the code you would actually run if you were
 * to call the function at addr (i.e., follow the sequence of jumps
 * starting at addr)
 */
static unsigned long follow_trampolines(struct ksplice_pack *pack,
					unsigned long addr)
{
	unsigned long new_addr;
	struct module *m;

	while (1) {
#ifdef KSPLICE_STANDALONE
		if (!bootstrapped)
			return addr;
#endif /* KSPLICE_STANDALONE */
		if (!__kernel_text_address(addr) ||
		    trampoline_target(pack, addr, &new_addr) != OK)
			return addr;
		m = __module_text_address(new_addr);
		if (m == NULL || m == pack->target ||
		    !starts_with(m->name, "ksplice"))
			return addr;
		addr = new_addr;
	}
}

/* Does module a patch module b? */
static bool patches_module(const struct module *a, const struct module *b)
{
#ifdef KSPLICE_NO_KERNEL_SUPPORT
	const char *name;
	if (a == b)
		return true;
	if (a == NULL || !starts_with(a->name, "ksplice_"))
		return false;
	name = a->name + strlen("ksplice_");
	name += strcspn(name, "_");
	if (name[0] != '_')
		return false;
	name++;
	return strcmp(name, b == NULL ? "vmlinux" : b->name) == 0;
#else /* !KSPLICE_NO_KERNEL_SUPPORT */
	struct ksplice_module_list_entry *entry;
	if (a == b)
		return true;
	list_for_each_entry(entry, &ksplice_module_list, list) {
		if (strcmp(entry->target_name, b->name) == 0 &&
		    strcmp(entry->primary_name, a->name) == 0)
			return true;
	}
	return false;
#endif /* KSPLICE_NO_KERNEL_SUPPORT */
}

static bool starts_with(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

static bool singular(struct list_head *list)
{
	return !list_empty(list) && list->next->next == list;
}

static void *bsearch(const void *key, const void *base, size_t n,
		     size_t size, int (*cmp)(const void *key, const void *elt))
{
	int start = 0, end = n - 1, mid, result;
	if (n == 0)
		return NULL;
	while (start <= end) {
		mid = (start + end) / 2;
		result = cmp(key, base + mid * size);
		if (result < 0)
			end = mid - 1;
		else if (result > 0)
			start = mid + 1;
		else
			return (void *)base + mid * size;
	}
	return NULL;
}

static int compare_relocs(const void *a, const void *b)
{
	const struct ksplice_reloc *ra = a, *rb = b;
	if (ra->blank_addr > rb->blank_addr)
		return 1;
	else if (ra->blank_addr < rb->blank_addr)
		return -1;
	else
		return ra->howto->size - rb->howto->size;
}

#ifdef KSPLICE_STANDALONE
static int compare_system_map(const void *a, const void *b)
{
	const struct ksplice_system_map *sa = a, *sb = b;
	return strcmp(sa->label, sb->label);
}
#endif /* KSPLICE_STANDALONE */

#ifdef CONFIG_DEBUG_FS
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
/* Old kernels don't have debugfs_create_blob */
static ssize_t read_file_blob(struct file *file, char __user *user_buf,
			      size_t count, loff_t *ppos)
{
	struct debugfs_blob_wrapper *blob = file->private_data;
	return simple_read_from_buffer(user_buf, count, ppos, blob->data,
				       blob->size);
}

static int blob_open(struct inode *inode, struct file *file)
{
	if (inode->i_private)
		file->private_data = inode->i_private;
	return 0;
}

static struct file_operations fops_blob = {
	.read = read_file_blob,
	.open = blob_open,
};

static struct dentry *debugfs_create_blob(const char *name, mode_t mode,
					  struct dentry *parent,
					  struct debugfs_blob_wrapper *blob)
{
	return debugfs_create_file(name, mode, parent, blob, &fops_blob);
}
#endif /* LINUX_VERSION_CODE */

static abort_t init_debug_buf(struct update *update)
{
	update->debug_blob.size = 0;
	update->debug_blob.data = NULL;
	update->debugfs_dentry =
	    debugfs_create_blob(update->name, S_IFREG | S_IRUSR, NULL,
				&update->debug_blob);
	if (update->debugfs_dentry == NULL)
		return OUT_OF_MEMORY;
	return OK;
}

static void clear_debug_buf(struct update *update)
{
	if (update->debugfs_dentry == NULL)
		return;
	debugfs_remove(update->debugfs_dentry);
	update->debugfs_dentry = NULL;
	update->debug_blob.size = 0;
	vfree(update->debug_blob.data);
	update->debug_blob.data = NULL;
}

static int _ksdebug(struct update *update, const char *fmt, ...)
{
	va_list args;
	unsigned long size, old_size, new_size;

	if (update->debug == 0)
		return 0;

	/* size includes the trailing '\0' */
	va_start(args, fmt);
	size = 1 + vsnprintf(update->debug_blob.data, 0, fmt, args);
	va_end(args);
	old_size = update->debug_blob.size == 0 ? 0 :
	    max(PAGE_SIZE, roundup_pow_of_two(update->debug_blob.size));
	new_size = update->debug_blob.size + size == 0 ? 0 :
	    max(PAGE_SIZE, roundup_pow_of_two(update->debug_blob.size + size));
	if (new_size > old_size) {
		char *buf = vmalloc(new_size);
		if (buf == NULL)
			return -ENOMEM;
		memcpy(buf, update->debug_blob.data, update->debug_blob.size);
		vfree(update->debug_blob.data);
		update->debug_blob.data = buf;
	}
	va_start(args, fmt);
	update->debug_blob.size += vsnprintf(update->debug_blob.data +
					     update->debug_blob.size,
					     size, fmt, args);
	va_end(args);
	return 0;
}
#else /* CONFIG_DEBUG_FS */
static abort_t init_debug_buf(struct update *update)
{
	return OK;
}

static void clear_debug_buf(struct update *update)
{
	return;
}

static int _ksdebug(struct update *update, const char *fmt, ...)
{
	va_list args;

	if (update->debug == 0)
		return 0;

	if (!update->debug_continue_line)
		printk(KERN_DEBUG "ksplice: ");

	va_start(args, fmt);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
	vprintk(fmt, args);
#else /* LINUX_VERSION_CODE < */
/* 683b229286b429244f35726b3c18caec429233bd was after 2.6.8 */
	{
		char *buf = kvasprintf(GFP_KERNEL, fmt, args);
		printk("%s", buf);
		kfree(buf);
	}
#endif /* LINUX_VERSION_CODE */
	va_end(args);

	update->debug_continue_line =
	    fmt[0] == '\0' || fmt[strlen(fmt) - 1] != '\n';
	return 0;
}
#endif /* CONFIG_DEBUG_FS */

#ifdef KSPLICE_NO_KERNEL_SUPPORT
#ifdef CONFIG_KALLSYMS
static int kallsyms_on_each_symbol(int (*fn)(void *, const char *,
					     struct module *, unsigned long),
				   void *data)
{
	char namebuf[KSYM_NAME_LEN];
	unsigned long i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	unsigned int off;
#endif /* LINUX_VERSION_CODE */
	int ret;

/*  kallsyms compression was added by 5648d78927ca65e74aadc88a2b1d6431e55e78ec
 *  2.6.10 was the first release after this commit
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	for (i = 0, off = 0; i < kallsyms_num_syms; i++) {
		off = kallsyms_expand_symbol(off, namebuf);
		ret = fn(data, namebuf, NULL, kallsyms_addresses[i]);
		if (ret != 0)
			return ret;
	}
#else /* LINUX_VERSION_CODE < */
	char *knames;

	for (i = 0, knames = kallsyms_names; i < kallsyms_num_syms; i++) {
		unsigned prefix = *knames++;

		strlcpy(namebuf + prefix, knames, KSYM_NAME_LEN - prefix);

		ret = fn(data, namebuf, NULL, kallsyms_addresses[i]);
		if (ret != OK)
			return ret;

		knames += strlen(knames) + 1;
	}
#endif /* LINUX_VERSION_CODE */
	return module_kallsyms_on_each_symbol(fn, data);
}

/*  kallsyms compression was added by 5648d78927ca65e74aadc88a2b1d6431e55e78ec
 *  2.6.10 was the first release after this commit
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
extern u8 kallsyms_token_table[];
extern u16 kallsyms_token_index[];

static unsigned int kallsyms_expand_symbol(unsigned int off, char *result)
{
	long len, skipped_first = 0;
	const u8 *tptr, *data;

	data = &kallsyms_names[off];
	len = *data;
	data++;

	off += len + 1;

	while (len) {
		tptr = &kallsyms_token_table[kallsyms_token_index[*data]];
		data++;
		len--;

		while (*tptr) {
			if (skipped_first) {
				*result = *tptr;
				result++;
			} else
				skipped_first = 1;
			tptr++;
		}
	}

	*result = '\0';

	return off;
}
#endif /* LINUX_VERSION_CODE */

static int module_kallsyms_on_each_symbol(int (*fn)(void *, const char *,
						    struct module *,
						    unsigned long),
					  void *data)
{
	struct module *mod;
	unsigned int i;
	int ret;

	list_for_each_entry(mod, &modules, list) {
		for (i = 0; i < mod->num_symtab; i++) {
			ret = fn(data, mod->strtab + mod->symtab[i].st_name,
				 mod, mod->symtab[i].st_value);
			if (ret != 0)
				return ret;
		}
	}
	return 0;
}
#endif /* CONFIG_KALLSYMS */

static struct module *find_module(const char *name)
{
	struct module *mod;

	list_for_each_entry(mod, &modules, list) {
		if (strcmp(mod->name, name) == 0)
			return mod;
	}
	return NULL;
}

#ifdef CONFIG_MODULE_UNLOAD
struct module_use {
	struct list_head list;
	struct module *module_which_uses;
};

/* I'm not yet certain whether we need the strong form of this. */
static inline int strong_try_module_get(struct module *mod)
{
	if (mod && mod->state != MODULE_STATE_LIVE)
		return -EBUSY;
	if (try_module_get(mod))
		return 0;
	return -ENOENT;
}

/* Does a already use b? */
static int already_uses(struct module *a, struct module *b)
{
	struct module_use *use;
	list_for_each_entry(use, &b->modules_which_use_me, list) {
		if (use->module_which_uses == a)
			return 1;
	}
	return 0;
}

/* Make it so module a uses b.  Must be holding module_mutex */
static int use_module(struct module *a, struct module *b)
{
	struct module_use *use;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
/* 270a6c4cad809e92d7b81adde92d0b3d94eeb8ee was after 2.6.20 */
	int no_warn;
#endif /* LINUX_VERSION_CODE */
	if (b == NULL || already_uses(a, b))
		return 1;

	if (strong_try_module_get(b) < 0)
		return 0;

	use = kmalloc(sizeof(*use), GFP_ATOMIC);
	if (!use) {
		module_put(b);
		return 0;
	}
	use->module_which_uses = a;
	list_add(&use->list, &b->modules_which_use_me);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
/* 270a6c4cad809e92d7b81adde92d0b3d94eeb8ee was after 2.6.20 */
	no_warn = sysfs_create_link(b->holders_dir, &a->mkobj.kobj, a->name);
#endif /* LINUX_VERSION_CODE */
	return 1;
}
#else /* CONFIG_MODULE_UNLOAD */
static int use_module(struct module *a, struct module *b)
{
	return 1;
}
#endif /* CONFIG_MODULE_UNLOAD */

#ifndef CONFIG_MODVERSIONS
#define symversion(base, idx) NULL
#else
#define symversion(base, idx) ((base != NULL) ? ((base) + (idx)) : NULL)
#endif

static bool each_symbol_in_section(const struct symsearch *arr,
				   unsigned int arrsize,
				   struct module *owner,
				   bool (*fn)(const struct symsearch *syms,
					      struct module *owner,
					      unsigned int symnum, void *data),
				   void *data)
{
	unsigned int i, j;

	for (j = 0; j < arrsize; j++) {
		for (i = 0; i < arr[j].stop - arr[j].start; i++)
			if (fn(&arr[j], owner, i, data))
				return true;
	}

	return false;
}

/* Returns true as soon as fn returns true, otherwise false. */
static bool each_symbol(bool (*fn)(const struct symsearch *arr,
				   struct module *owner,
				   unsigned int symnum, void *data),
			void *data)
{
	struct module *mod;
	const struct symsearch arr[] = {
		{ __start___ksymtab, __stop___ksymtab, __start___kcrctab,
		  NOT_GPL_ONLY, false },
		{ __start___ksymtab_gpl, __stop___ksymtab_gpl,
		  __start___kcrctab_gpl,
		  GPL_ONLY, false },
#ifdef KSPLICE_KSYMTAB_FUTURE_SUPPORT
		{ __start___ksymtab_gpl_future, __stop___ksymtab_gpl_future,
		  __start___kcrctab_gpl_future,
		  WILL_BE_GPL_ONLY, false },
#endif /* KSPLICE_KSYMTAB_FUTURE_SUPPORT */
#ifdef KSPLICE_KSYMTAB_UNUSED_SUPPORT
		{ __start___ksymtab_unused, __stop___ksymtab_unused,
		  __start___kcrctab_unused,
		  NOT_GPL_ONLY, true },
		{ __start___ksymtab_unused_gpl, __stop___ksymtab_unused_gpl,
		  __start___kcrctab_unused_gpl,
		  GPL_ONLY, true },
#endif /* KSPLICE_KSYMTAB_UNUSED_SUPPORT */
	};

	if (each_symbol_in_section(arr, ARRAY_SIZE(arr), NULL, fn, data))
		return 1;

	list_for_each_entry(mod, &modules, list) {
		struct symsearch module_arr[] = {
			{ mod->syms, mod->syms + mod->num_syms, mod->crcs,
			  NOT_GPL_ONLY, false },
			{ mod->gpl_syms, mod->gpl_syms + mod->num_gpl_syms,
			  mod->gpl_crcs,
			  GPL_ONLY, false },
#ifdef KSPLICE_KSYMTAB_FUTURE_SUPPORT
			{ mod->gpl_future_syms,
			  mod->gpl_future_syms + mod->num_gpl_future_syms,
			  mod->gpl_future_crcs,
			  WILL_BE_GPL_ONLY, false },
#endif /* KSPLICE_KSYMTAB_FUTURE_SUPPORT */
#ifdef KSPLICE_KSYMTAB_UNUSED_SUPPORT
			{ mod->unused_syms,
			  mod->unused_syms + mod->num_unused_syms,
			  mod->unused_crcs,
			  NOT_GPL_ONLY, true },
			{ mod->unused_gpl_syms,
			  mod->unused_gpl_syms + mod->num_unused_gpl_syms,
			  mod->unused_gpl_crcs,
			  GPL_ONLY, true },
#endif /* KSPLICE_KSYMTAB_UNUSED_SUPPORT */
		};

		if (each_symbol_in_section(module_arr, ARRAY_SIZE(module_arr),
					   mod, fn, data))
			return true;
	}
	return false;
}

struct find_symbol_arg {
	/* Input */
	const char *name;
	bool gplok;
	bool warn;

	/* Output */
	struct module *owner;
	const unsigned long *crc;
	const struct kernel_symbol *sym;
};

static bool find_symbol_in_section(const struct symsearch *syms,
				   struct module *owner,
				   unsigned int symnum, void *data)
{
	struct find_symbol_arg *fsa = data;

	if (strcmp(syms->start[symnum].name, fsa->name) != 0)
		return false;

	if (!fsa->gplok) {
		if (syms->licence == GPL_ONLY)
			return false;
		if (syms->licence == WILL_BE_GPL_ONLY && fsa->warn) {
			printk(KERN_WARNING "Symbol %s is being used "
			       "by a non-GPL module, which will not "
			       "be allowed in the future\n", fsa->name);
			printk(KERN_WARNING "Please see the file "
			       "Documentation/feature-removal-schedule.txt "
			       "in the kernel source tree for more details.\n");
		}
	}

#ifdef CONFIG_UNUSED_SYMBOLS
	if (syms->unused && fsa->warn) {
		printk(KERN_WARNING "Symbol %s is marked as UNUSED, "
		       "however this module is using it.\n", fsa->name);
		printk(KERN_WARNING
		       "This symbol will go away in the future.\n");
		printk(KERN_WARNING
		       "Please evalute if this is the right api to use and if "
		       "it really is, submit a report the linux kernel "
		       "mailinglist together with submitting your code for "
		       "inclusion.\n");
	}
#endif

	fsa->owner = owner;
	fsa->crc = symversion(syms->crcs, symnum);
	fsa->sym = &syms->start[symnum];
	return true;
}

/* Find a symbol and return it, along with, (optional) crc and
 * (optional) module which owns it */
static const struct kernel_symbol *find_symbol(const char *name,
					       struct module **owner,
					       const unsigned long **crc,
					       bool gplok, bool warn)
{
	struct find_symbol_arg fsa;

	fsa.name = name;
	fsa.gplok = gplok;
	fsa.warn = warn;

	if (each_symbol(find_symbol_in_section, &fsa)) {
		if (owner)
			*owner = fsa.owner;
		if (crc)
			*crc = fsa.crc;
		return fsa.sym;
	}

	return NULL;
}

static inline int within_module_core(unsigned long addr, struct module *mod)
{
        return (unsigned long)mod->module_core <= addr &&
               addr < (unsigned long)mod->module_core + mod->core_size;
}

static inline int within_module_init(unsigned long addr, struct module *mod)
{
        return (unsigned long)mod->module_init <= addr &&
               addr < (unsigned long)mod->module_init + mod->init_size;
}

static struct module *__module_address(unsigned long addr)
{
	struct module *mod;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
	list_for_each_entry_rcu(mod, &modules, list)
#else
/* d72b37513cdfbd3f53f3d485a8c403cc96d2c95f was after 2.6.27 */
	list_for_each_entry(mod, &modules, list)
#endif
		if (within_module_core(addr, mod) ||
		    within_module_init(addr, mod))
			return mod;
	return NULL;
}
#endif /* KSPLICE_NO_KERNEL_SUPPORT */

struct update_attribute {
	struct attribute attr;
	ssize_t (*show)(struct update *update, char *buf);
	ssize_t (*store)(struct update *update, const char *buf, size_t len);
};

static ssize_t update_attr_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct update_attribute *attribute =
	    container_of(attr, struct update_attribute, attr);
	struct update *update = container_of(kobj, struct update, kobj);
	if (attribute->show == NULL)
		return -EIO;
	return attribute->show(update, buf);
}

static ssize_t update_attr_store(struct kobject *kobj, struct attribute *attr,
				 const char *buf, size_t len)
{
	struct update_attribute *attribute =
	    container_of(attr, struct update_attribute, attr);
	struct update *update = container_of(kobj, struct update, kobj);
	if (attribute->store == NULL)
		return -EIO;
	return attribute->store(update, buf, len);
}

static struct sysfs_ops update_sysfs_ops = {
	.show = update_attr_show,
	.store = update_attr_store,
};

static void update_release(struct kobject *kobj)
{
	struct update *update;
	update = container_of(kobj, struct update, kobj);
	cleanup_ksplice_update(update);
}

static ssize_t stage_show(struct update *update, char *buf)
{
	switch (update->stage) {
	case STAGE_PREPARING:
		return snprintf(buf, PAGE_SIZE, "preparing\n");
	case STAGE_APPLIED:
		return snprintf(buf, PAGE_SIZE, "applied\n");
	case STAGE_REVERSED:
		return snprintf(buf, PAGE_SIZE, "reversed\n");
	}
	return 0;
}

static ssize_t abort_cause_show(struct update *update, char *buf)
{
	switch (update->abort_cause) {
	case OK:
		return snprintf(buf, PAGE_SIZE, "ok\n");
	case NO_MATCH:
		return snprintf(buf, PAGE_SIZE, "no_match\n");
#ifdef KSPLICE_STANDALONE
	case BAD_SYSTEM_MAP:
		return snprintf(buf, PAGE_SIZE, "bad_system_map\n");
#endif /* KSPLICE_STANDALONE */
	case CODE_BUSY:
		return snprintf(buf, PAGE_SIZE, "code_busy\n");
	case MODULE_BUSY:
		return snprintf(buf, PAGE_SIZE, "module_busy\n");
	case OUT_OF_MEMORY:
		return snprintf(buf, PAGE_SIZE, "out_of_memory\n");
	case FAILED_TO_FIND:
		return snprintf(buf, PAGE_SIZE, "failed_to_find\n");
	case ALREADY_REVERSED:
		return snprintf(buf, PAGE_SIZE, "already_reversed\n");
	case MISSING_EXPORT:
		return snprintf(buf, PAGE_SIZE, "missing_export\n");
	case UNEXPECTED_RUNNING_TASK:
		return snprintf(buf, PAGE_SIZE, "unexpected_running_task\n");
	case TARGET_NOT_LOADED:
		return snprintf(buf, PAGE_SIZE, "target_not_loaded\n");
	case CALL_FAILED:
		return snprintf(buf, PAGE_SIZE, "call_failed\n");
	case COLD_UPDATE_LOADED:
		return snprintf(buf, PAGE_SIZE, "cold_update_loaded\n");
	case UNEXPECTED:
		return snprintf(buf, PAGE_SIZE, "unexpected\n");
	default:
		return snprintf(buf, PAGE_SIZE, "unknown\n");
	}
	return 0;
}

static ssize_t conflict_show(struct update *update, char *buf)
{
	const struct conflict *conf;
	const struct conflict_addr *ca;
	int used = 0;
	mutex_lock(&module_mutex);
	list_for_each_entry(conf, &update->conflicts, list) {
		used += snprintf(buf + used, PAGE_SIZE - used, "%s %d",
				 conf->process_name, conf->pid);
		list_for_each_entry(ca, &conf->stack, list) {
			if (!ca->has_conflict)
				continue;
			used += snprintf(buf + used, PAGE_SIZE - used, " %s",
					 ca->label);
		}
		used += snprintf(buf + used, PAGE_SIZE - used, "\n");
	}
	mutex_unlock(&module_mutex);
	return used;
}

/* Used to pass maybe_cleanup_ksplice_update to kthread_run */
static int maybe_cleanup_ksplice_update_wrapper(void *updateptr)
{
	struct update *update = updateptr;
	mutex_lock(&module_mutex);
	maybe_cleanup_ksplice_update(update);
	mutex_unlock(&module_mutex);
	return 0;
}

static ssize_t stage_store(struct update *update, const char *buf, size_t len)
{
	enum stage old_stage;
	mutex_lock(&module_mutex);
	old_stage = update->stage;
	if ((strncmp(buf, "applied", len) == 0 ||
	     strncmp(buf, "applied\n", len) == 0) &&
	    update->stage == STAGE_PREPARING)
		update->abort_cause = apply_update(update);
	else if ((strncmp(buf, "reversed", len) == 0 ||
		  strncmp(buf, "reversed\n", len) == 0) &&
		 update->stage == STAGE_APPLIED)
		update->abort_cause = reverse_patches(update);
	else if ((strncmp(buf, "cleanup", len) == 0 ||
		  strncmp(buf, "cleanup\n", len) == 0) &&
		 update->stage == STAGE_REVERSED)
		kthread_run(maybe_cleanup_ksplice_update_wrapper, update,
			    "ksplice_cleanup_%s", update->kid);

	if (old_stage != STAGE_REVERSED && update->abort_cause == OK)
		printk(KERN_INFO "ksplice: Update %s %s successfully\n",
		       update->kid,
		       update->stage == STAGE_APPLIED ? "applied" : "reversed");
	mutex_unlock(&module_mutex);
	return len;
}

static ssize_t debug_show(struct update *update, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", update->debug);
}

static ssize_t debug_store(struct update *update, const char *buf, size_t len)
{
	unsigned long l;
	int ret = strict_strtoul(buf, 10, &l);
	if (ret != 0)
		return ret;
	update->debug = l;
	return len;
}

static ssize_t partial_show(struct update *update, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", update->partial);
}

static ssize_t partial_store(struct update *update, const char *buf, size_t len)
{
	unsigned long l;
	int ret = strict_strtoul(buf, 10, &l);
	if (ret != 0)
		return ret;
	update->partial = l;
	return len;
}

static struct update_attribute stage_attribute =
	__ATTR(stage, 0600, stage_show, stage_store);
static struct update_attribute abort_cause_attribute =
	__ATTR(abort_cause, 0400, abort_cause_show, NULL);
static struct update_attribute debug_attribute =
	__ATTR(debug, 0600, debug_show, debug_store);
static struct update_attribute partial_attribute =
	__ATTR(partial, 0600, partial_show, partial_store);
static struct update_attribute conflict_attribute =
	__ATTR(conflicts, 0400, conflict_show, NULL);

static struct attribute *update_attrs[] = {
	&stage_attribute.attr,
	&abort_cause_attribute.attr,
	&debug_attribute.attr,
	&partial_attribute.attr,
	&conflict_attribute.attr,
	NULL
};

static struct kobj_type update_ktype = {
	.sysfs_ops = &update_sysfs_ops,
	.release = update_release,
	.default_attrs = update_attrs,
};

#ifdef KSPLICE_STANDALONE
static int debug;
module_param(debug, int, 0600);
MODULE_PARM_DESC(debug, "Debug level");

extern struct ksplice_system_map ksplice_system_map[], ksplice_system_map_end[];

static struct ksplice_pack bootstrap_pack = {
	.name = "ksplice_" __stringify(KSPLICE_KID),
	.kid = "init_" __stringify(KSPLICE_KID),
	.target_name = NULL,
	.target = NULL,
	.map_printk = MAP_PRINTK,
	.primary = THIS_MODULE,
	.primary_system_map = ksplice_system_map,
	.primary_system_map_end = ksplice_system_map_end,
};
#endif /* KSPLICE_STANDALONE */

static int init_ksplice(void)
{
#ifdef KSPLICE_STANDALONE
	struct ksplice_pack *pack = &bootstrap_pack;
	pack->update = init_ksplice_update(pack->kid);
	sort(pack->primary_system_map,
	     pack->primary_system_map_end - pack->primary_system_map,
	     sizeof(struct ksplice_system_map), compare_system_map, NULL);
	if (pack->update == NULL)
		return -ENOMEM;
	add_to_update(pack, pack->update);
	pack->update->debug = debug;
	pack->update->abort_cause =
	    apply_relocs(pack, ksplice_init_relocs, ksplice_init_relocs_end);
	if (pack->update->abort_cause == OK)
		bootstrapped = true;
	cleanup_ksplice_update(bootstrap_pack.update);
#else /* !KSPLICE_STANDALONE */
	ksplice_kobj = kobject_create_and_add("ksplice", kernel_kobj);
	if (ksplice_kobj == NULL)
		return -ENOMEM;
#endif /* KSPLICE_STANDALONE */
	return 0;
}

static void cleanup_ksplice(void)
{
#ifndef KSPLICE_STANDALONE
	kobject_put(ksplice_kobj);
#endif /* KSPLICE_STANDALONE */
}

module_init(init_ksplice);
module_exit(cleanup_ksplice);

MODULE_AUTHOR("Ksplice, Inc.");
MODULE_DESCRIPTION("Ksplice rebootless update system");
#ifdef KSPLICE_VERSION
MODULE_VERSION(KSPLICE_VERSION);
#endif
MODULE_LICENSE("GPL v2");
