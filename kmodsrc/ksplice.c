/*  Copyright (C) 2007-2008  Jeffrey Brian Arnold <jbarnold@mit.edu>
 *  Copyright (C) 2008  Anders Kaseorg <andersk@mit.edu>,
 *                      Tim Abbott <tabbott@mit.edu>
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/* 6e21828743247270d09a86756a0c11702500dbfb was after 2.6.18 */
#define bool _Bool
#define false 0
#define true 1
#endif /* LINUX_VERSION_CODE */

enum stage {
	STAGE_PREPARING, STAGE_APPLIED, STAGE_REVERSED
};

enum run_pre_mode {
	RUN_PRE_INITIAL, RUN_PRE_DEBUG, RUN_PRE_FINAL
};

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
#ifdef KSPLICE_STANDALONE
#define BAD_SYSTEM_MAP ((__force abort_t) 10)
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
	struct list_head packs;
	struct list_head conflicts;
	struct list_head list;
};

struct conflict {
	const char *process_name;
	pid_t pid;
	struct list_head stack;
	struct list_head list;
};

struct conflict_addr {
	unsigned long addr;
	bool has_conflict;
	const char *label;
	struct list_head list;
};

#if defined(CONFIG_DEBUG_FS) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
/* Old kernels don't have debugfs_create_blob */
struct debugfs_blob_wrapper {
	void *data;
	unsigned long size;
};
#endif /* CONFIG_DEBUG_FS && LINUX_VERSION_CODE */

struct labelval {
	struct list_head list;
	const char *label;
	unsigned long val;
	enum { NOVAL, TEMP, VAL } status;
};

struct safety_record {
	struct list_head list;
	const char *label;
	unsigned long addr;
	unsigned long size;
	bool first_byte_safe;
};

struct candidate_val {
	struct list_head list;
	unsigned long val;
};

struct accumulate_struct {
	struct ksplice_pack *pack;
	const char *desired_name;
	struct list_head *vals;
};

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
	if (!virtual_address_mapped((unsigned long)src) ||
	    !virtual_address_mapped((unsigned long)src + size))
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

static struct kobj_type ksplice_ktype;

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
static void add_to_update(struct ksplice_pack *pack, struct update *update);
static int ksplice_sysfs_init(struct update *update);

/* Preparing the relocations and patches for application */
static abort_t apply_update(struct update *update);
static abort_t prepare_pack(struct ksplice_pack *pack);
static abort_t finalize_pack(struct ksplice_pack *pack);
static abort_t finalize_exports(struct ksplice_pack *pack);
static abort_t finalize_patches(struct ksplice_pack *pack);
static abort_t add_dependency_on_address(struct ksplice_pack *pack,
					 unsigned long addr);
static abort_t apply_relocs(struct ksplice_pack *pack,
			    const struct ksplice_reloc *relocs,
			    const struct ksplice_reloc *relocs_end);
static abort_t apply_reloc(struct ksplice_pack *pack,
			   const struct ksplice_reloc *r);
static abort_t read_reloc_value(struct ksplice_pack *pack,
				const struct ksplice_reloc *r,
				unsigned long addr, unsigned long *valp);
static abort_t write_reloc_value(struct ksplice_pack *pack,
				 const struct ksplice_reloc *r,
				 unsigned long addr, unsigned long sym_addr);
static void __attribute__((noreturn)) ksplice_deleted(void);

/* run-pre matching */
static abort_t match_pack_sections(struct ksplice_pack *pack,
				   bool consider_data_sections);
static abort_t find_section(struct ksplice_pack *pack,
			    const struct ksplice_section *sect);
static abort_t try_addr(struct ksplice_pack *pack,
			const struct ksplice_section *sect,
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
				const struct ksplice_section *sect,
				unsigned long run_addr,
				struct list_head *safety_records,
				enum run_pre_mode mode);
#endif /* CONFIG_FUNCTION_DATA_SECTIONS */
static void print_bytes(struct ksplice_pack *pack,
			const unsigned char *run, int runc,
			const unsigned char *pre, int prec);
#ifdef KSPLICE_STANDALONE
static abort_t brute_search(struct ksplice_pack *pack,
			    const struct ksplice_section *sect,
			    const void *start, unsigned long len,
			    struct list_head *vals);
static abort_t brute_search_all(struct ksplice_pack *pack,
				const struct ksplice_section *sect,
				struct list_head *vals);
#endif /* KSPLICE_STANDALONE */
static abort_t lookup_reloc(struct ksplice_pack *pack, unsigned long addr,
			    const struct ksplice_reloc **relocp);
static abort_t handle_reloc(struct ksplice_pack *pack,
			    const struct ksplice_reloc *r,
			    unsigned long run_addr, enum run_pre_mode mode);

/* Computing possible addresses for symbols */
static abort_t lookup_symbol(struct ksplice_pack *pack,
			     const struct ksplice_symbol *ksym,
			     struct list_head *vals);
#ifdef KSPLICE_STANDALONE
static abort_t
add_system_map_candidates(struct ksplice_pack *pack,
			  const struct ksplice_system_map *start,
			  const struct ksplice_system_map *end,
			  const char *label, struct list_head *vals);
#endif /* KSPLICE_STANDALONE */
#ifdef CONFIG_KALLSYMS
static abort_t lookup_symbol_kallsyms(struct ksplice_pack *pack,
				      const char *name, struct list_head *vals);
static int accumulate_matching_names(void *data, const char *sym_name,
				     struct module *sym_owner,
				     unsigned long sym_val);
#endif /* CONFIG_KALLSYMS */
static abort_t exported_symbol_lookup(const char *name, struct list_head *vals);
static abort_t new_export_lookup(struct update *update,
				 const char *name, struct list_head *vals);

/* Atomic update insertion and removal */
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
static void insert_trampoline(struct ksplice_trampoline *t);
static abort_t verify_trampoline(struct ksplice_pack *pack,
				 const struct ksplice_trampoline *t);
static void remove_trampoline(const struct ksplice_trampoline *t);

static struct labelval *find_labelval(struct ksplice_pack *pack,
				      const char *label);
static abort_t create_labelval(struct ksplice_pack *pack, const char *label,
			       unsigned long val, int status);
static abort_t create_safety_record(struct ksplice_pack *pack,
				    const struct ksplice_section *sect,
				    struct list_head *record_list,
				    unsigned long run_addr,
				    unsigned long run_size);
static abort_t add_candidate_val(struct list_head *vals, unsigned long val);
static void prune_trampoline_vals(struct ksplice_pack *pack,
				  struct list_head *vals);
static void release_vals(struct list_head *vals);
static void set_temp_labelvals(struct ksplice_pack *pack, int status_val);

static int contains_canary(struct ksplice_pack *pack, unsigned long blank_addr,
			   int size, long dst_mask);
static unsigned long follow_trampolines(struct ksplice_pack *pack,
					unsigned long addr);
static bool patches_module(const struct module *a, const struct module *b);
static bool starts_with(const char *str, const char *prefix);
static bool singular(struct list_head *list);

/* Debugging */
static abort_t init_debug_buf(struct update *update);
static void clear_debug_buf(struct update *update);
static int __attribute__((format(printf, 2, 3)))
_ksdebug(struct update *update, const char *fmt, ...);
#define ksdebug(pack, fmt, ...) \
	_ksdebug(pack->update, fmt, ## __VA_ARGS__)

#if defined(KSPLICE_STANDALONE) && \
    !defined(CONFIG_KSPLICE) && !defined(CONFIG_KSPLICE_MODULE)
#define KSPLICE_NO_KERNEL_SUPPORT 1
#endif /* KSPLICE_STANDALONE && !CONFIG_KSPLICE && !CONFIG_KSPLICE_MODULE */

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
static struct module *__module_data_address(unsigned long addr);
#endif /* KSPLICE_NO_KERNEL_SUPPORT */

/* Architecture-specific functions defined in arch/ARCH/kernel/ksplice-arch.c */
static abort_t prepare_trampoline(struct ksplice_pack *pack,
				  struct ksplice_trampoline *t);
static abort_t trampoline_target(struct ksplice_pack *pack, unsigned long addr,
				 unsigned long *new_addr);
static abort_t handle_paravirt(struct ksplice_pack *pack, unsigned long pre,
			       unsigned long run, int *matched);
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

int init_ksplice_pack(struct ksplice_pack *pack)
{
	struct update *update;
	int ret = 0;

#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return -1;
#endif /* KSPLICE_STANDALONE */

	INIT_LIST_HEAD(&pack->labelvals);
	INIT_LIST_HEAD(&pack->safety_records);

	mutex_lock(&module_mutex);
	if (strcmp(pack->target_name, "vmlinux") == 0) {
		pack->target = NULL;
	} else {
		pack->target = find_module(pack->target_name);
		if (pack->target == NULL || !module_is_live(pack->target)) {
			ret = -ENODEV;
			goto out;
		}
		ret = use_module(pack->primary, pack->target);
		if (ret != 1) {
			ret = -ENODEV;
			goto out;
		}
	}
	list_for_each_entry(update, &updates, list) {
		if (strcmp(pack->kid, update->kid) == 0) {
			if (update->stage != STAGE_PREPARING) {
				ret = -EPERM;
				goto out;
			}
			add_to_update(pack, update);
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
EXPORT_SYMBOL(init_ksplice_pack);

void cleanup_ksplice_pack(struct ksplice_pack *pack)
{
	if (pack->update == NULL || pack->update->stage == STAGE_APPLIED)
		return;
	mutex_lock(&module_mutex);
	list_del(&pack->list);
	mutex_unlock(&module_mutex);
	if (list_empty(&pack->update->packs))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
		kobject_put(&pack->update->kobj);
#else /* LINUX_VERSION_CODE < */
/* 6d06adfaf82d154023141ddc0c9de18b6a49090b was after 2.6.24 */
		kobject_unregister(&pack->update->kobj);
#endif /* LINUX_VERSION_CODE */
	pack->update = NULL;
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
	INIT_LIST_HEAD(&update->packs);
	if (init_debug_buf(update) != OK) {
		kfree(update->kid);
		kfree(update->name);
		kfree(update);
		return NULL;
	}
	list_add(&update->list, &updates);
	update->stage = STAGE_PREPARING;
	update->abort_cause = OK;
	INIT_LIST_HEAD(&update->conflicts);
	return update;
}

static void cleanup_ksplice_update(struct update *update)
{
#ifdef KSPLICE_STANDALONE
	if (bootstrapped)
		mutex_lock(&module_mutex);
	list_del(&update->list);
	if (bootstrapped)
		mutex_unlock(&module_mutex);
#else /* !KSPLICE_STANDALONE */
	mutex_lock(&module_mutex);
	list_del(&update->list);
	mutex_unlock(&module_mutex);
#endif /* KSPLICE_STANDALONE */
	cleanup_conflicts(update);
	clear_debug_buf(update);
	kfree(update->kid);
	kfree(update->name);
	kfree(update);
}

static void add_to_update(struct ksplice_pack *pack, struct update *update)
{
	pack->update = update;
	list_add(&pack->list, &update->packs);
	pack->module_list_entry.target = pack->target;
	pack->module_list_entry.primary = pack->primary;
}

static int ksplice_sysfs_init(struct update *update)
{
	int ret = 0;
	memset(&update->kobj, 0, sizeof(update->kobj));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#ifndef KSPLICE_STANDALONE
	ret = kobject_init_and_add(&update->kobj, &ksplice_ktype,
				   ksplice_kobj, "%s", update->kid);
#else /* KSPLICE_STANDALONE */
/* 6d06adfaf82d154023141ddc0c9de18b6a49090b was after 2.6.24 */
	ret = kobject_init_and_add(&update->kobj, &ksplice_ktype,
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
	update->kobj.ktype = &ksplice_ktype;
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
	struct ksplice_pack *pack;
	abort_t ret;

	mutex_lock(&module_mutex);
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	list_for_each_entry(pack, &update->packs, list) {
		if (pack->target == NULL) {
			apply_paravirt(pack->primary_parainstructions,
				       pack->primary_parainstructions_end);
			apply_paravirt(pack->helper_parainstructions,
				       pack->helper_parainstructions_end);
		}
	}
#endif /* KSPLICE_NEED_PARAINSTRUCTIONS */

	list_for_each_entry(pack, &update->packs, list) {
		ret = prepare_pack(pack);
		if (ret != OK)
			goto out;
	}
	ret = apply_patches(update);
out:
	list_for_each_entry(pack, &update->packs, list) {
		clear_list(&pack->labelvals, struct labelval, list);
		if (update->stage == STAGE_PREPARING)
			clear_list(&pack->safety_records, struct safety_record,
				   list);
	}
	mutex_unlock(&module_mutex);
	return ret;
}


static abort_t prepare_pack(struct ksplice_pack *pack)
{
	abort_t ret;

	ksdebug(pack, "Preparing and checking %s\n", pack->name);
	ret = match_pack_sections(pack, false);
	if (ret == NO_MATCH) {
		/* It is possible that by using relocations from .data sections
		   we can successfully run-pre match the rest of the sections.
		   To avoid using any symbols obtained from .data sections
		   (which may be unreliable) in the post code, we first prepare
		   the post code and then try to run-pre match the remaining
		   sections with the help of .data sections.
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

	ret = finalize_exports(pack);
	if (ret != OK)
		return ret;

	return OK;
}

static abort_t finalize_exports(struct ksplice_pack *pack)
{
	struct ksplice_export *exp;
	struct module *m;
	const struct kernel_symbol *sym;

	for (exp = pack->exports; exp < pack->exports_end; exp++) {
		sym = find_symbol(exp->name, &m, NULL, true, false);
		if (sym == NULL) {
			ksdebug(pack, "Could not find kernel_symbol struct for "
				"%s\n", exp->name);
			return MISSING_EXPORT;
		}

		/* Cast away const since we are planning to mutate the
		 * kernel_symbol structure. */
		exp->sym = (struct kernel_symbol *)sym;
		exp->saved_name = exp->sym->name;
		if (m != pack->primary && use_module(pack->primary, m) != 1) {
			ksdebug(pack, "Aborted.  Could not add dependency on "
				"symbol %s from module %s.\n", sym->name,
				m->name);
			return UNEXPECTED;
		}
	}
	return OK;
}

static abort_t finalize_patches(struct ksplice_pack *pack)
{
	struct ksplice_patch *p;
	struct safety_record *rec;
	abort_t ret;

	for (p = pack->patches; p < pack->patches_end; p++) {
		struct labelval *lv = find_labelval(pack, p->label);
		bool found = false;
		if (lv == NULL) {
			ksdebug(pack, "Failed to find %s for oldaddr\n",
				p->label);
			return FAILED_TO_FIND;
		}
		p->trampoline.oldaddr = lv->val;

		list_for_each_entry(rec, &pack->safety_records, list) {
			if (strcmp(rec->label, p->label) == 0 &&
			    follow_trampolines(pack, p->trampoline.oldaddr)
			    == rec->addr) {
				found = true;
				break;
			}
		}
		if (!found) {
			ksdebug(pack, "No safety record for patch %s\n",
				p->label);
			return NO_MATCH;
		}
		if (rec->size < p->trampoline.size) {
			ksdebug(pack, "Symbol %s is too short for trampoline\n",
				p->label);
			return UNEXPECTED;
		}

		if (p->trampoline.repladdr == 0)
			p->trampoline.repladdr = (unsigned long)ksplice_deleted;
		else
			rec->first_byte_safe = true;

		ret = prepare_trampoline(pack, &p->trampoline);
		if (ret != OK)
			return ret;

		if (p->trampoline.oldaddr != rec->addr) {
			/* If there's already a trampoline at oldaddr, prepare
			   a reverse trampoline to install there */
			p->reverse_trampoline.oldaddr = rec->addr;
			p->reverse_trampoline.repladdr = p->trampoline.oldaddr;
			ret = prepare_trampoline(pack, &p->reverse_trampoline);
			if (ret != OK)
				return ret;
		} else {
			p->reverse_trampoline.size = 0;
		}

		ret = add_dependency_on_address(pack, p->trampoline.oldaddr);
		if (ret != OK)
			return ret;
	}
	return OK;
}

static abort_t add_dependency_on_address(struct ksplice_pack *pack,
					 unsigned long addr)
{
	struct module *m =
	    __module_text_address(follow_trampolines(pack, addr));
	if (m == NULL || m == pack->primary)
		return OK;
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
	abort_t ret;
	int canary_ret;
	unsigned long sym_addr;
	LIST_HEAD(vals);

	canary_ret = contains_canary(pack, r->blank_addr, r->size, r->dst_mask);
	if (canary_ret < 0)
		return UNEXPECTED;
	if (canary_ret == 0) {
		ksdebug(pack, "reloc: skipped %s:%lx (altinstr)\n",
			r->symbol->label, r->blank_offset);
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
	if (!singular(&vals)) {
		release_vals(&vals);
		ksdebug(pack, "Failed to find %s for reloc\n",
			r->symbol->label);
		return FAILED_TO_FIND;
	}
	sym_addr = list_entry(vals.next, struct candidate_val, list)->val;
	release_vals(&vals);

	ret = write_reloc_value(pack, r, r->blank_addr,
				r->pcrel ? sym_addr - r->blank_addr : sym_addr);
	if (ret != OK)
		return ret;

	ksdebug(pack, "reloc: %s:%lx", r->symbol->label, r->blank_offset);
	ksdebug(pack, "(S=%lx A=%lx ", sym_addr, r->addend);
	switch (r->size) {
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
	/* Create labelvals so that we can verify our choices in the second
	   round of run-pre matching that considers data sections. */
	ret = create_labelval(pack, r->symbol->label, sym_addr, VAL);
	if (ret != OK)
		return ret;
	return add_dependency_on_address(pack, sym_addr);
}

static abort_t read_reloc_value(struct ksplice_pack *pack,
				const struct ksplice_reloc *r,
				unsigned long addr, unsigned long *valp)
{
	unsigned char bytes[sizeof(long)];
	unsigned long val;

	if (probe_kernel_read(bytes, (void *)addr, r->size) == -EFAULT)
		return NO_MATCH;

	switch (r->size) {
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

	val &= r->dst_mask;
	if (r->signed_addend)
		val |= -(val & (r->dst_mask & ~(r->dst_mask >> 1)));
	val <<= r->rightshift;
	val -= r->addend;
	*valp = val;
	return OK;
}

static abort_t write_reloc_value(struct ksplice_pack *pack,
				 const struct ksplice_reloc *r,
				 unsigned long addr, unsigned long sym_addr)
{
	unsigned long val = sym_addr + r->addend;
	val >>= r->rightshift;
	switch (r->size) {
	case 1:
		*(uint8_t *)addr =
		    (*(uint8_t *)addr & ~r->dst_mask) | (val & r->dst_mask);
		break;
	case 2:
		*(uint16_t *)addr =
		    (*(uint16_t *)addr & ~r->dst_mask) | (val & r->dst_mask);
		break;
	case 4:
		*(uint32_t *)addr =
		    (*(uint32_t *)addr & ~r->dst_mask) | (val & r->dst_mask);
		break;
#if BITS_PER_LONG >= 64
	case 8:
		*(uint64_t *)addr =
		    (*(uint64_t *)addr & ~r->dst_mask) | (val & r->dst_mask);
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

static void __attribute__((noreturn)) ksplice_deleted(void)
{
	printk(KERN_CRIT "Called a kernel function deleted by Ksplice!\n");
	BUG();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
/* 91768d6c2bad0d2766a166f13f2f57e197de3458 was after 2.6.19 */
	for (;;);
#endif
}

static abort_t match_pack_sections(struct ksplice_pack *pack,
				   bool consider_data_sections)
{
	const struct ksplice_section *sect;
	abort_t ret;
	char *finished;
	int i, remaining = 0;
	bool progress;

	finished = kcalloc(pack->helper_sections_end - pack->helper_sections,
			   sizeof(*finished), GFP_KERNEL);
	if (finished == NULL)
		return OUT_OF_MEMORY;
	for (sect = pack->helper_sections; sect < pack->helper_sections_end;
	     sect++) {
		if ((sect->flags & KSPLICE_SECTION_DATA) == 0)
			remaining++;
	}

	while (remaining > 0) {
		progress = false;
		for (sect = pack->helper_sections;
		     sect < pack->helper_sections_end; sect++) {
			i = sect - pack->helper_sections;
			if (finished[i])
				continue;
			if (!consider_data_sections &&
			    (sect->flags & KSPLICE_SECTION_DATA) != 0)
				continue;
			ret = find_section(pack, sect);
			if (ret == OK) {
				finished[i] = 1;
				if ((sect->flags & KSPLICE_SECTION_DATA) == 0)
					remaining--;
				progress = true;
			} else if (ret != NO_MATCH) {
				kfree(finished);
				return ret;
			}
		}

		if (progress)
			continue;

		for (sect = pack->helper_sections;
		     sect < pack->helper_sections_end; sect++) {
			i = sect - pack->helper_sections;
			if (finished[i] == 0)
				ksdebug(pack, "run-pre: could not match "
					"section %s\n", sect->symbol->label);
		}
		ksdebug(pack, "Aborted.  run-pre: could not match some "
			"sections.\n");
		kfree(finished);
		return NO_MATCH;
	}
	kfree(finished);
	return OK;
}

static abort_t find_section(struct ksplice_pack *pack,
			    const struct ksplice_section *sect)
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

#ifdef KSPLICE_STANDALONE
	if (list_empty(&vals) && (sect->flags & KSPLICE_SECTION_DATA) == 0) {
		ret = brute_search_all(pack, sect, &vals);
		if (ret != OK) {
			release_vals(&vals);
			return ret;
		}
		/* Make sure run-pre matching output is displayed if
		   brute_search succeeds */
		prune_trampoline_vals(pack, &vals);
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
#endif /* KSPLICE_STANDALONE */

	prune_trampoline_vals(pack, &vals);
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

static abort_t try_addr(struct ksplice_pack *pack,
			const struct ksplice_section *sect,
			unsigned long run_addr,
			struct list_head *safety_records,
			enum run_pre_mode mode)
{
	abort_t ret;
	const struct module *run_module;

	if ((sect->flags & KSPLICE_SECTION_RODATA) != 0 ||
	    (sect->flags & KSPLICE_SECTION_DATA) != 0)
		run_module = __module_data_address(run_addr);
	else
		run_module = __module_text_address(run_addr);
	if (!patches_module(run_module, pack->target)) {
		ksdebug(pack, "run-pre: ignoring address %lx in other module "
			"%s for sect %s\n", run_addr, run_module == NULL ?
			"vmlinux" : run_module->name, sect->symbol->label);
		return NO_MATCH;
	}

	ret = create_labelval(pack, sect->symbol->label, run_addr, TEMP);
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
			(sect->flags & KSPLICE_SECTION_RODATA) != 0 ? "data" :
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

static abort_t run_pre_cmp(struct ksplice_pack *pack,
			   const struct ksplice_section *sect,
			   unsigned long run_addr,
			   struct list_head *safety_records,
			   enum run_pre_mode mode)
{
	int matched = 0;
	abort_t ret;
	const struct ksplice_reloc *r;
	const unsigned char *pre, *run, *pre_start, *run_start;
	unsigned char runval;

	if ((sect->flags & KSPLICE_SECTION_TEXT) != 0)
		run_addr = follow_trampolines(pack, run_addr);

	pre_start = (const unsigned char *)sect->address;
	run_start = (const unsigned char *)run_addr;

	pre = pre_start;
	run = run_start;
	while (pre < pre_start + sect->size) {
		unsigned long offset = pre - pre_start;
		ret = lookup_reloc(pack, (unsigned long)pre, &r);
		if (ret == OK) {
			ret = handle_reloc(pack, r, (unsigned long)run, mode);
			if (ret != OK) {
				if (mode == RUN_PRE_INITIAL)
					ksdebug(pack, "reloc in sect does not "
						"match after %lx/%lx bytes\n",
						offset, sect->size);
				return ret;
			}
			if (mode == RUN_PRE_DEBUG)
				print_bytes(pack, run, r->size, pre, r->size);
			pre += r->size;
			run += r->size;
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

#ifdef KSPLICE_STANDALONE
static abort_t brute_search(struct ksplice_pack *pack,
			    const struct ksplice_section *sect,
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
			ret = add_candidate_val(vals, addr);
			if (ret != OK)
				return ret;
		} else if (ret != NO_MATCH) {
			return ret;
		}
	}

	return OK;
}

static abort_t brute_search_all(struct ksplice_pack *pack,
				const struct ksplice_section *sect,
				struct list_head *vals)
{
	struct module *m;
	abort_t ret = OK;
	int saved_debug;

	ksdebug(pack, "brute_search: searching for %s\n", sect->symbol->label);
	saved_debug = pack->update->debug;
	pack->update->debug = 0;

	list_for_each_entry(m, &modules, list) {
		if (!patches_module(m, pack->target))
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
#endif /* KSPLICE_STANDALONE */

static abort_t lookup_reloc(struct ksplice_pack *pack, unsigned long addr,
			    const struct ksplice_reloc **relocp)
{
	const struct ksplice_reloc *r;
	int canary_ret;
	for (r = pack->helper_relocs; r < pack->helper_relocs_end; r++) {
		if (addr >= r->blank_addr && addr < r->blank_addr + r->size) {
			canary_ret = contains_canary(pack, r->blank_addr,
						     r->size, r->dst_mask);
			if (canary_ret < 0)
				return UNEXPECTED;
			if (canary_ret == 0) {
				ksdebug(pack, "reloc: skipped %s:%lx "
					"(altinstr)\n", r->symbol->label,
					r->blank_offset);
				return NO_MATCH;
			}
			if (addr != r->blank_addr) {
				ksdebug(pack, "Invalid nonzero relocation "
					"offset\n");
				return UNEXPECTED;
			}
			*relocp = r;
			return OK;
		}
	}
	return NO_MATCH;
}

static abort_t handle_reloc(struct ksplice_pack *pack,
			    const struct ksplice_reloc *r,
			    unsigned long run_addr, enum run_pre_mode mode)
{
	unsigned long val;
	abort_t ret;

	ret = read_reloc_value(pack, r, run_addr, &val);
	if (ret != OK)
		return ret;
	if (r->pcrel)
		val += run_addr;

	if (mode == RUN_PRE_INITIAL)
		ksdebug(pack, "run-pre: reloc at r_a=%lx p_a=%lx to %s+%lx: "
			"found %s = %lx\n", run_addr, r->blank_addr,
			r->symbol->label, r->addend, r->symbol->label, val);

	if (starts_with(r->symbol->label, ".rodata.str"))
		return OK;

	if (contains_canary(pack, run_addr, r->size, r->dst_mask) != 0) {
		ksdebug(pack, "Aborted.  Unexpected canary in run code at %lx"
			"\n", run_addr);
		return UNEXPECTED;
	}

	ret = create_labelval(pack, r->symbol->label, val, TEMP);
	if (ret == NO_MATCH && mode == RUN_PRE_INITIAL) {
		struct labelval *lv = find_labelval(pack, r->symbol->label);
		ksdebug(pack, "run-pre: reloc at r_a=%lx p_a=%lx: labelval %s "
			"= %lx(%d) does not match expected %lx\n", run_addr,
			r->blank_addr, r->symbol->label, lv->val, lv->status,
			val);
	}
	return ret;
}

static abort_t lookup_symbol(struct ksplice_pack *pack,
			     const struct ksplice_symbol *ksym,
			     struct list_head *vals)
{
	abort_t ret;
	struct labelval *lv;

#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return OK;
#endif /* KSPLICE_STANDALONE */

	lv = find_labelval(pack, ksym->label);
	if (lv != NULL) {
		release_vals(vals);
		ksdebug(pack, "using detected sym %s=%lx\n", ksym->label,
			lv->val);
		return add_candidate_val(vals, lv->val);
	}

	if (starts_with(ksym->label, ".rodata.str"))
		return OK;

#ifdef CONFIG_MODULE_UNLOAD
	if (strcmp(ksym->label, "cleanup_module") == 0 && pack->target != NULL
	    && pack->target->exit != NULL) {
		ret = add_candidate_val(vals,
					(unsigned long)pack->target->exit);
		if (ret != OK)
			return ret;
	}
#endif

	ret = exported_symbol_lookup(ksym->name, vals);
	if (ret != OK)
		return ret;

	ret = new_export_lookup(pack->update, ksym->name, vals);
	if (ret != OK)
		return ret;

#ifdef CONFIG_KALLSYMS
	ret = lookup_symbol_kallsyms(pack, ksym->name, vals);
	if (ret != OK)
		return ret;
#endif /* CONFIG_KALLSYMS */

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
	for (smap = start; smap < end; smap++) {
		if (strcmp(smap->label, label) == 0)
			break;
	}
	if (smap >= end)
		return OK;
	for (i = 0; i < smap->nr_candidates; i++) {
		ret = add_candidate_val(vals, smap->candidates[i] + off);
		if (ret != OK)
			return ret;
	}
	return OK;
}
#endif /* !KSPLICE_STANDALONE */

#ifdef CONFIG_KALLSYMS
static abort_t lookup_symbol_kallsyms(struct ksplice_pack *pack,
				      const char *name, struct list_head *vals)
{
	struct accumulate_struct acc = { pack, name, vals };
	return (__force abort_t)
	    kallsyms_on_each_symbol(accumulate_matching_names, &acc);
}

static int accumulate_matching_names(void *data, const char *sym_name,
				     struct module *sym_owner,
				     unsigned long sym_val)
{
	struct accumulate_struct *acc = data;
	if (strcmp(sym_name, acc->desired_name) == 0 &&
	    patches_module(sym_owner, acc->pack->target) &&
	    sym_owner != acc->pack->primary)
		return (__force int)add_candidate_val(acc->vals, sym_val);
	return (__force int)OK;
}
#endif /* CONFIG_KALLSYMS */

static abort_t exported_symbol_lookup(const char *name, struct list_head *vals)
{
	const struct kernel_symbol *sym;
	sym = find_symbol(name, NULL, NULL, true, false);
	if (sym == NULL)
		return OK;
	return add_candidate_val(vals, sym->value);
}

static abort_t new_export_lookup(struct update *update,
				 const char *name, struct list_head *vals)
{
	struct ksplice_pack *pack;
	struct ksplice_export *exp;
	list_for_each_entry(pack, &update->packs, list) {
		for (exp = pack->exports; exp < pack->exports_end; exp++) {
			if (strcmp(exp->new_name, name) == 0 &&
			    exp->sym != NULL &&
			    contains_canary(pack,
					    (unsigned long)&exp->sym->value,
					    sizeof(unsigned long), -1) == 0)
				return add_candidate_val(vals, exp->sym->value);
		}
	}
	return OK;
}

static abort_t apply_patches(struct update *update)
{
	int i;
	abort_t ret;
	struct ksplice_pack *pack;
	const struct ksplice_section *sect;

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

	if (ret == CODE_BUSY) {
		print_conflicts(update);
		_ksdebug(update, "Aborted %s.  stack check: to-be-replaced "
			 "code is busy.\n", update->kid);
	} else if (ret == ALREADY_REVERSED) {
		_ksdebug(update, "Aborted %s.  Ksplice update %s is already "
			 "reversed.\n", update->kid, update->kid);
	}

	if (ret != OK)
		return ret;

	list_for_each_entry(pack, &update->packs, list) {
		for (sect = pack->primary_sections;
		     sect < pack->primary_sections_end; sect++) {
			ret = create_safety_record(pack, sect,
						   &pack->safety_records,
						   sect->address, sect->size);
			if (ret != OK)
				return ret;
		}
	}

	_ksdebug(update, "Update %s applied successfully\n", update->kid);
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
	list_for_each_entry(pack, &update->packs, list)
		clear_list(&pack->safety_records, struct safety_record, list);

	if (ret == CODE_BUSY) {
		print_conflicts(update);
		_ksdebug(update, "Aborted %s.  stack check: to-be-reversed "
			 "code is busy.\n", update->kid);
	} else if (ret == MODULE_BUSY) {
		_ksdebug(update, "Update %s is in use by another module\n",
			 update->kid);
	}

	if (ret != OK)
		return ret;

	_ksdebug(update, "Update %s reversed successfully\n", update->kid);
	return OK;
}

static int __apply_patches(void *updateptr)
{
	struct update *update = updateptr;
	struct ksplice_pack *pack;
	struct ksplice_patch *p;
	struct ksplice_export *exp;
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
			return (__force int)UNEXPECTED;
		}
	}

	update->stage = STAGE_APPLIED;

	list_for_each_entry(pack, &update->packs, list)
		list_add(&pack->module_list_entry.list, &ksplice_module_list);

	list_for_each_entry(pack, &update->packs, list) {
		for (exp = pack->exports; exp < pack->exports_end; exp++)
			exp->sym->name = exp->new_name;
	}

	list_for_each_entry(pack, &update->packs, list) {
		for (p = pack->patches; p < pack->patches_end; p++) {
			insert_trampoline(&p->trampoline);
			insert_trampoline(&p->reverse_trampoline);
		}
	}
	return (__force int)OK;
}

static int __reverse_patches(void *updateptr)
{
	struct update *update = updateptr;
	struct ksplice_pack *pack;
	const struct ksplice_patch *p;
	struct ksplice_export *exp;
	abort_t ret;

	if (update->stage != STAGE_APPLIED)
		return (__force int)OK;

#ifdef CONFIG_MODULE_UNLOAD
	list_for_each_entry(pack, &update->packs, list) {
		if (module_refcount(pack->primary) != 1)
			return (__force int)MODULE_BUSY;
	}
#endif /* CONFIG_MODULE_UNLOAD */

	ret = check_each_task(update);
	if (ret != OK)
		return (__force int)ret;

	list_for_each_entry(pack, &update->packs, list) {
		for (p = pack->patches; p < pack->patches_end; p++) {
			ret = verify_trampoline(pack, &p->trampoline);
			if (ret != OK)
				return (__force int)ret;
			ret = verify_trampoline(pack, &p->reverse_trampoline);
			if (ret != OK)
				return (__force int)ret;
		}
	}

	update->stage = STAGE_REVERSED;

	list_for_each_entry(pack, &update->packs, list)
		module_put(pack->primary);

	list_for_each_entry(pack, &update->packs, list)
		list_del(&pack->module_list_entry.list);

	list_for_each_entry(pack, &update->packs, list) {
		for (exp = pack->exports; exp < pack->exports_end; exp++)
			exp->sym->name = exp->saved_name;
	}

	list_for_each_entry(pack, &update->packs, list) {
		for (p = pack->patches; p < pack->patches_end; p++) {
			remove_trampoline(&p->trampoline);
			remove_trampoline(&p->reverse_trampoline);
		}
	}
	return (__force int)OK;
}

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
		list_for_each_entry(rec, &pack->safety_records, list) {
			ret = check_record(ca, rec, addr);
			if (ret != OK)
				status = ret;
		}
	}
	return status;
}

static abort_t check_record(struct conflict_addr *ca,
			    const struct safety_record *rec, unsigned long addr)
{
	if ((addr > rec->addr && addr < rec->addr + rec->size) ||
	    (addr == rec->addr && !rec->first_byte_safe)) {
		if (ca != NULL) {
			ca->label = rec->label;
			ca->has_conflict = true;
		}
		return CODE_BUSY;
	}
	return OK;
}

static bool is_stop_machine(const struct task_struct *t)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	const char *num;
	if (!starts_with(t->comm, "kstop"))
		return false;
	num = t->comm + strlen("kstop");
	return num[strspn(num, "0123456789")] == '\0';
#else /* LINUX_VERSION_CODE < */
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

static void insert_trampoline(struct ksplice_trampoline *t)
{
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	memcpy((void *)t->saved, (void *)t->oldaddr, t->size);
	memcpy((void *)t->oldaddr, (void *)t->trampoline, t->size);
	flush_icache_range(t->oldaddr, t->oldaddr + t->size);
	set_fs(old_fs);
}

static abort_t verify_trampoline(struct ksplice_pack *pack,
				 const struct ksplice_trampoline *t)
{
	if (memcmp((void *)t->oldaddr, (void *)t->trampoline, t->size) != 0) {
		ksdebug(pack, "Aborted.  Trampoline at %lx has been "
			"overwritten.\n", t->oldaddr);
		return CODE_BUSY;
	}
	return OK;
}

static void remove_trampoline(const struct ksplice_trampoline *t)
{
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	memcpy((void *)t->oldaddr, (void *)t->saved, t->size);
	flush_icache_range(t->oldaddr, t->oldaddr + t->size);
	set_fs(old_fs);
}

static struct labelval *find_labelval(struct ksplice_pack *pack,
				      const char *label)
{
	struct labelval *lv;
	list_for_each_entry(lv, &pack->labelvals, list) {
		if (strcmp(lv->label, label) == 0)
			return lv;
	}
	return NULL;
}

static abort_t create_labelval(struct ksplice_pack *pack, const char *label,
			       unsigned long val, int status)
{
	struct labelval *lv = find_labelval(pack, label);
	if (lv != NULL)
		return lv->val == val ? OK : NO_MATCH;

	lv = kmalloc(sizeof(*lv), GFP_KERNEL);
	if (lv == NULL)
		return OUT_OF_MEMORY;
	lv->label = label;
	lv->val = val;
	lv->status = status;
	list_add(&lv->list, &pack->labelvals);
	return OK;
}

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
		if (strcmp(sect->symbol->label, p->label) == 0)
			break;
	}
	if (p >= pack->patches_end)
		return OK;

	if ((sect->flags & KSPLICE_SECTION_TEXT) == 0 &&
	    p->trampoline.repladdr != 0) {
		ksdebug(pack, "Error: ksplice_patch %s is matched to a "
			"non-deleted non-text section!\n", sect->symbol->label);
		return UNEXPECTED;
	}

	rec = kmalloc(sizeof(*rec), GFP_KERNEL);
	if (rec == NULL)
		return OUT_OF_MEMORY;
	rec->addr = run_addr;
	rec->size = run_size;
	rec->label = sect->symbol->label;
	rec->first_byte_safe = false;

	list_add(&rec->list, record_list);
	return OK;
}

static abort_t add_candidate_val(struct list_head *vals, unsigned long val)
{
	struct candidate_val *tmp, *new;

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

/* If there are only two candidates and their addresses are related by
   a trampoline, then we have successfully found a function patched by a
   previous update.  We remove the endpoint of the trampoline from the vals
   list, so that this update uses the patched function's original address. */
static void prune_trampoline_vals(struct ksplice_pack *pack,
				  struct list_head *vals)
{
	struct candidate_val *val1, *val2;

	if (list_empty(vals) || singular(vals))
		return;
	if (vals->next->next->next != vals)
		return;

	val1 = list_entry(vals->next, struct candidate_val, list);
	val2 = list_entry(vals->next->next, struct candidate_val, list);

	if (val1->val == follow_trampolines(pack, val2->val)) {
		list_del(&val1->list);
		kfree(val1);
		return;
	}
	if (val2->val == follow_trampolines(pack, val1->val)) {
		list_del(&val2->list);
		kfree(val2);
		return;
	}
}

static void release_vals(struct list_head *vals)
{
	clear_list(vals, struct candidate_val, list);
}

static void set_temp_labelvals(struct ksplice_pack *pack, int status)
{
	struct labelval *lv, *n;
	list_for_each_entry_safe(lv, n, &pack->labelvals, list) {
		if (lv->status == TEMP) {
			if (status == NOVAL) {
				list_del(&lv->list);
				kfree(lv);
			} else {
				lv->status = status;
			}
		}
	}
}

static int contains_canary(struct ksplice_pack *pack, unsigned long blank_addr,
			   int size, long dst_mask)
{
	switch (size) {
	case 1:
		return (*(uint8_t *)blank_addr & dst_mask) ==
		    (KSPLICE_CANARY & dst_mask);
	case 2:
		return (*(uint16_t *)blank_addr & dst_mask) ==
		    (KSPLICE_CANARY & dst_mask);
	case 4:
		return (*(uint32_t *)blank_addr & dst_mask) ==
		    (KSPLICE_CANARY & dst_mask);
#if BITS_PER_LONG >= 64
	case 8:
		return (*(uint64_t *)blank_addr & dst_mask) ==
		    (KSPLICE_CANARY & dst_mask);
#endif /* BITS_PER_LONG */
	default:
		ksdebug(pack, "Aborted.  Invalid relocation size.\n");
		return -1;
	}
}

static unsigned long follow_trampolines(struct ksplice_pack *pack,
					unsigned long addr)
{
	unsigned long new_addr;
	struct module *m;

	if (trampoline_target(pack, addr, &new_addr) != OK)
		return addr;

	/* Confirm that it is a jump into a ksplice module */
	m = __module_text_address(new_addr);
	if (m != NULL && m != pack->target && starts_with(m->name, "ksplice")) {
		ksdebug(pack, "Following trampoline %lx %lx(%s)\n", addr,
			new_addr, m->name);
		return new_addr;
	}
	return addr;
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
		if (entry->target == b && entry->primary == a)
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

static struct module *__module_data_address(unsigned long addr)
{
	struct module *mod;

	list_for_each_entry(mod, &modules, list) {
		if (addr >= (unsigned long)mod->module_core +
		    mod->core_text_size &&
		    addr < (unsigned long)mod->module_core + mod->core_size)
			return mod;
	}
	return NULL;
}
#endif /* KSPLICE_NO_KERNEL_SUPPORT */

struct ksplice_attribute {
	struct attribute attr;
	ssize_t (*show)(struct update *update, char *buf);
	ssize_t (*store)(struct update *update, const char *buf, size_t len);
};

static ssize_t ksplice_attr_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct ksplice_attribute *attribute =
	    container_of(attr, struct ksplice_attribute, attr);
	struct update *update = container_of(kobj, struct update, kobj);
	if (attribute->show == NULL)
		return -EIO;
	return attribute->show(update, buf);
}

static ssize_t ksplice_attr_store(struct kobject *kobj, struct attribute *attr,
				  const char *buf, size_t len)
{
	struct ksplice_attribute *attribute =
	    container_of(attr, struct ksplice_attribute, attr);
	struct update *update = container_of(kobj, struct update, kobj);
	if (attribute->store == NULL)
		return -EIO;
	return attribute->store(update, buf, len);
}

static struct sysfs_ops ksplice_sysfs_ops = {
	.show = ksplice_attr_show,
	.store = ksplice_attr_store,
};

static void ksplice_release(struct kobject *kobj)
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
	case UNEXPECTED:
		return snprintf(buf, PAGE_SIZE, "unexpected\n");
	}
	return 0;
}

static ssize_t conflict_show(struct update *update, char *buf)
{
	const struct conflict *conf;
	const struct conflict_addr *ca;
	int used = 0;
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
	return used;
}

static ssize_t stage_store(struct update *update, const char *buf, size_t len)
{
	if ((strncmp(buf, "applied", len) == 0 ||
	     strncmp(buf, "applied\n", len) == 0) &&
	    update->stage == STAGE_PREPARING)
		update->abort_cause = apply_update(update);
	else if ((strncmp(buf, "reversed", len) == 0 ||
		  strncmp(buf, "reversed\n", len) == 0) &&
		 update->stage == STAGE_APPLIED)
		update->abort_cause = reverse_patches(update);
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

static struct ksplice_attribute stage_attribute =
	__ATTR(stage, 0600, stage_show, stage_store);
static struct ksplice_attribute abort_cause_attribute =
	__ATTR(abort_cause, 0400, abort_cause_show, NULL);
static struct ksplice_attribute debug_attribute =
	__ATTR(debug, 0600, debug_show, debug_store);
static struct ksplice_attribute conflict_attribute =
	__ATTR(conflicts, 0400, conflict_show, NULL);

static struct attribute *ksplice_attrs[] = {
	&stage_attribute.attr,
	&abort_cause_attribute.attr,
	&debug_attribute.attr,
	&conflict_attribute.attr,
	NULL
};

static struct kobj_type ksplice_ktype = {
	.sysfs_ops = &ksplice_sysfs_ops,
	.release = ksplice_release,
	.default_attrs = ksplice_attrs,
};

#ifdef KSPLICE_STANDALONE
static int debug;
module_param(debug, int, 0600);
MODULE_PARM_DESC(debug, "Debug level");

extern struct ksplice_system_map ksplice_system_map[], ksplice_system_map_end[];

static struct ksplice_pack bootstrap_pack = {
	.name = "ksplice_" STR(KSPLICE_KID),
	.kid = "init_" STR(KSPLICE_KID),
	.target_name = NULL,
	.target = NULL,
	.map_printk = MAP_PRINTK,
	.primary = THIS_MODULE,
	.labelvals = LIST_HEAD_INIT(bootstrap_pack.labelvals),
	.primary_system_map = ksplice_system_map,
	.primary_system_map_end = ksplice_system_map_end,
};
#endif /* KSPLICE_STANDALONE */

static int init_ksplice(void)
{
#ifdef KSPLICE_STANDALONE
	struct ksplice_pack *pack = &bootstrap_pack;
	pack->update = init_ksplice_update(pack->kid);
	if (pack->update == NULL)
		return -ENOMEM;
	add_to_update(pack, pack->update);
	pack->update->debug = debug;
	pack->update->abort_cause =
	    apply_relocs(pack, ksplice_init_relocs, ksplice_init_relocs_end);
	if (pack->update->abort_cause == OK)
		bootstrapped = true;
#else /* !KSPLICE_STANDALONE */
	ksplice_kobj = kobject_create_and_add("ksplice", kernel_kobj);
	if (ksplice_kobj == NULL)
		return -ENOMEM;
#endif /* KSPLICE_STANDALONE */
	return 0;
}

static void cleanup_ksplice(void)
{
#ifdef KSPLICE_STANDALONE
	cleanup_ksplice_update(bootstrap_pack.update);
#else /* !KSPLICE_STANDALONE */
	kobject_put(ksplice_kobj);
#endif /* KSPLICE_STANDALONE */
}

module_init(init_ksplice);
module_exit(cleanup_ksplice);

MODULE_AUTHOR("Jeffrey Brian Arnold <jbarnold@mit.edu>");
MODULE_DESCRIPTION("Ksplice rebootless update system");
#ifdef KSPLICE_VERSION
MODULE_VERSION(KSPLICE_VERSION);
#endif
MODULE_LICENSE("GPL v2");
