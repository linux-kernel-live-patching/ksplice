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

#if BITS_PER_LONG == 32
#define ADDR "08lx"
#elif BITS_PER_LONG == 64
#define ADDR "016lx"
#endif /* BITS_PER_LONG */

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
#define BAD_SYSTEM_MAP ((__force abort_t) 2)
#define CODE_BUSY ((__force abort_t) 3)
#define MODULE_BUSY ((__force abort_t) 4)
#define OUT_OF_MEMORY ((__force abort_t) 5)
#define FAILED_TO_FIND ((__force abort_t) 6)
#define ALREADY_REVERSED ((__force abort_t) 7)
#define MISSING_EXPORT ((__force abort_t) 8)
#define UNEXPECTED_RUNNING_TASK ((__force abort_t) 9)
#define UNEXPECTED ((__force abort_t) 10)

struct update_bundle {
	const char *kid;
	const char *name;
	struct kobject kobj;
	enum stage stage;
	abort_t abort_cause;
	int debug;
#ifdef CONFIG_DEBUG_FS
	struct debugfs_blob_wrapper debug_blob;
	struct dentry *debugfs_dentry;
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

struct conflict_frame {
	unsigned long addr;
	int has_conflict;
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

struct reloc_nameval {
	struct list_head list;
	const char *label;
	unsigned long val;
	enum { NOVAL, TEMP, VAL } status;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
/* c33fa9f5609e918824446ef9a75319d4a802f1f4 was after 2.6.25 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
/* 2fff0a48416af891dce38fd425246e337831e0bb was after 2.6.19 */
static int virtual_address_mapped(unsigned long addr)
{
	char retval;
	return probe_kernel_address(addr, retval) != -EFAULT;
}
#else /* LINUX_VERSION_CODE < */
static int virtual_address_mapped(unsigned long addr);
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

static struct reloc_nameval *find_nameval(struct module_pack *pack,
					  const char *label);
static abort_t create_nameval(struct module_pack *pack, const char *label,
			      unsigned long val, int status);
static abort_t lookup_reloc(struct module_pack *pack, unsigned long addr,
			    const struct ksplice_reloc **relocp);
static abort_t handle_reloc(struct module_pack *pack,
			    const struct ksplice_reloc *r,
			    unsigned long run_addr, enum run_pre_mode mode);

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

static bool singular(struct list_head *list)
{
	return !list_empty(list) && list->next->next == list;
}

#ifdef CONFIG_DEBUG_FS
static abort_t init_debug_buf(struct update_bundle *bundle);
static void clear_debug_buf(struct update_bundle *bundle);
static int __attribute__((format(printf, 2, 3)))
__ksdebug(struct update_bundle *bundle, const char *fmt, ...);
#else /* !CONFIG_DEBUG_FS */
static inline abort_t init_debug_buf(struct update_bundle *bundle)
{
	return OK;
}

static inline void clear_debug_buf(struct update_bundle *bundle)
{
	return;
}

#define __ksdebug(bundle, fmt, ...) printk(fmt, ## __VA_ARGS__)
#endif /* CONFIG_DEBUG_FS */

#define _ksdebug(bundle, level, fmt, ...)			\
	do {							\
		if ((bundle)->debug >= (level))			\
			__ksdebug(bundle, fmt, ## __VA_ARGS__);	\
	} while (0)
#define ksdebug(pack, level, fmt, ...) \
	do { _ksdebug((pack)->bundle, level, fmt, ## __VA_ARGS__); } while (0)
#define failed_to_find(pack, sym_name) \
	ksdebug(pack, 0, KERN_ERR "ksplice: Failed to find symbol %s at " \
		"%s:%d\n", sym_name, __FILE__, __LINE__)

static inline void print_abort(struct module_pack *pack, const char *str)
{
	ksdebug(pack, 0, KERN_ERR "ksplice: Aborted. (%s)\n", str);
}

static LIST_HEAD(update_bundles);
#ifdef KSPLICE_STANDALONE
#if defined(CONFIG_KSPLICE) || defined(CONFIG_KSPLICE_MODULE)
extern struct list_head ksplice_module_list;
#else /* !CONFIG_KSPLICE */
LIST_HEAD(ksplice_module_list);
#endif /* CONFIG_KSPLICE */
#else /* !KSPLICE_STANDALONE */
LIST_HEAD(ksplice_module_list);
EXPORT_SYMBOL_GPL(ksplice_module_list);
#endif /* KSPLICE_STANDALONE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
/* Old kernels do not have kcalloc
 * e629946abd0bb8266e9c3d0fd1bff2ef8dec5443 was after 2.6.8
 */
static inline void *kcalloc(size_t n, size_t size, typeof(GFP_KERNEL) flags)
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

static int bootstrapped = 0;

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

static abort_t apply_relocs(struct module_pack *pack,
			    const struct ksplice_reloc *relocs,
			    const struct ksplice_reloc *relocs_end);
static abort_t apply_reloc(struct module_pack *pack,
			   const struct ksplice_reloc *r);
static abort_t write_reloc_value(struct module_pack *pack,
				 const struct ksplice_reloc *r,
				 unsigned long sym_addr);
static abort_t add_system_map_candidates(struct module_pack *pack,
					 const struct ksplice_symbol *symbol,
					 struct list_head *vals);
static abort_t compute_address(struct module_pack *pack,
			       const struct ksplice_symbol *ksym,
			       struct list_head *vals);

struct accumulate_struct {
	const char *desired_name;
	struct list_head *vals;
};

#ifdef CONFIG_KALLSYMS
static int accumulate_matching_names(void *data, const char *sym_name,
				     unsigned long sym_val);
static abort_t kernel_lookup(const char *name, struct list_head *vals);
static abort_t other_module_lookup(struct module_pack *pack, const char *name,
				   struct list_head *vals);
#ifdef KSPLICE_STANDALONE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
static unsigned long ksplice_kallsyms_expand_symbol(unsigned long off,
						    char *result);
#endif /* LINUX_VERSION_CODE */
#endif /* KSPLICE_STANDALONE */
#endif /* CONFIG_KALLSYMS */
static abort_t exported_symbol_lookup(const char *name, struct list_head *vals);
static abort_t new_export_lookup(struct update_bundle *bundle,
				 const char *name, struct list_head *vals);

#ifdef KSPLICE_STANDALONE
static abort_t brute_search_all(struct module_pack *pack,
				const struct ksplice_size *s,
				struct list_head *vals);
#endif /* KSPLICE_STANDALONE */

static abort_t add_candidate_val(struct list_head *vals, unsigned long val);
static void release_vals(struct list_head *vals);
static void set_temp_myst_relocs(struct module_pack *pack, int status_val);
static int contains_canary(struct module_pack *pack, unsigned long blank_addr,
			   int size, long dst_mask);
static int starts_with(const char *str, const char *prefix);
static int ends_with(const char *str, const char *suffix);

#define clear_list(head, type, member)				\
	do {							\
		struct list_head *_pos, *_n;			\
		list_for_each_safe(_pos, _n, head) {		\
			list_del(_pos);				\
			kfree(list_entry(_pos, type, member));	\
		}						\
	} while (0)

/* primary */
static abort_t activate_primary(struct module_pack *pack);
static abort_t process_exports(struct module_pack *pack);
static abort_t process_patches(struct module_pack *pack);
static int __apply_patches(void *bundle);
static int __reverse_patches(void *bundle);
static abort_t check_each_task(struct update_bundle *bundle);
static abort_t check_task(struct update_bundle *bundle,
			  const struct task_struct *t, int rerun);
static abort_t check_stack(struct update_bundle *bundle, struct conflict *conf,
			   const struct thread_info *tinfo,
			   const unsigned long *stack);
static abort_t check_address(struct update_bundle *bundle,
			     struct conflict *conf, unsigned long addr);
static abort_t check_record(struct conflict_frame *frame,
			    const struct safety_record *rec,
			    unsigned long addr);
static int valid_stack_ptr(const struct thread_info *tinfo, const void *p);
static int is_stop_machine(const struct task_struct *t);
static void cleanup_conflicts(struct update_bundle *bundle);
static void print_conflicts(struct update_bundle *bundle);
static void insert_trampoline(struct ksplice_patch *p);
static void remove_trampoline(const struct ksplice_patch *p);
/* Architecture-specific functions defined in ARCH/ksplice-arch.c */
static abort_t create_trampoline(struct ksplice_patch *p);
static unsigned long follow_trampolines(struct module_pack *pack,
					unsigned long addr);
static abort_t handle_paravirt(struct module_pack *pack, unsigned long pre,
			       unsigned long run, int *matched);

static abort_t add_dependency_on_address(struct module_pack *pack,
					 unsigned long addr);
static abort_t add_patch_dependencies(struct module_pack *pack);

#if defined(KSPLICE_STANDALONE) && \
    !defined(CONFIG_KSPLICE) && !defined(CONFIG_KSPLICE_MODULE)
#define KSPLICE_NO_KERNEL_SUPPORT 1
#endif /* KSPLICE_STANDALONE && !CONFIG_KSPLICE && !CONFIG_KSPLICE_MODULE */

#ifdef KSPLICE_NO_KERNEL_SUPPORT
/* Functions defined here that will be exported in later kernels */
#ifdef CONFIG_KALLSYMS
static int module_kallsyms_on_each_symbol(const struct module *mod,
					  int (*fn)(void *, const char *,
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

/* helper */
static abort_t activate_helper(struct module_pack *pack,
			       bool consider_data_sections);
static abort_t search_for_match(struct module_pack *pack,
				const struct ksplice_size *s);
static abort_t try_addr(struct module_pack *pack, const struct ksplice_size *s,
			unsigned long run_addr,
			struct list_head *safety_records,
			enum run_pre_mode mode);
static abort_t run_pre_cmp(struct module_pack *pack,
			   const struct ksplice_size *s,
			   unsigned long run_addr,
			   struct list_head *safety_records,
			   enum run_pre_mode mode);
#ifndef FUNCTION_SECTIONS
/* defined in $ARCH/ksplice-arch.c */
static abort_t arch_run_pre_cmp(struct module_pack *pack,
				const struct ksplice_size *s,
				unsigned long run_addr,
				struct list_head *safety_records,
				enum run_pre_mode mode);
#endif /* FUNCTION_SECTIONS */
static void print_bytes(struct module_pack *pack,
			const unsigned char *run, int runc,
			const unsigned char *pre, int prec);
static abort_t create_safety_record(struct module_pack *pack,
				    const struct ksplice_size *s,
				    struct list_head *record_list,
				    unsigned long run_addr,
				    unsigned long run_size);

static abort_t reverse_patches(struct update_bundle *bundle);
static abort_t apply_patches(struct update_bundle *bundle);
static abort_t apply_update(struct update_bundle *bundle);
static int register_ksplice_module(struct module_pack *pack);
static struct update_bundle *init_ksplice_bundle(const char *kid);
static void cleanup_ksplice_bundle(struct update_bundle *bundle);
static void add_to_bundle(struct module_pack *pack,
			  struct update_bundle *bundle);
static int ksplice_sysfs_init(struct update_bundle *bundle);

#ifndef KSPLICE_STANDALONE
#include "ksplice-arch.c"
#elif defined CONFIG_X86
#include "x86/ksplice-arch.c"
#elif defined CONFIG_ARM
#include "arm/ksplice-arch.c"
#endif /* KSPLICE_STANDALONE */

#ifndef KSPLICE_STANDALONE
static struct kobject *ksplice_kobj;
#endif /* !KSPLICE_STANDALONE */

struct ksplice_attribute {
	struct attribute attr;
	ssize_t (*show)(struct update_bundle *bundle, char *buf);
	ssize_t (*store)(struct update_bundle *bundle, const char *buf,
			 size_t len);
};

static ssize_t ksplice_attr_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct ksplice_attribute *attribute =
	    container_of(attr, struct ksplice_attribute, attr);
	struct update_bundle *bundle =
	    container_of(kobj, struct update_bundle, kobj);
	if (attribute->show == NULL)
		return -EIO;
	return attribute->show(bundle, buf);
}

static ssize_t ksplice_attr_store(struct kobject *kobj, struct attribute *attr,
				  const char *buf, size_t len)
{
	struct ksplice_attribute *attribute =
	    container_of(attr, struct ksplice_attribute, attr);
	struct update_bundle *bundle =
	    container_of(kobj, struct update_bundle, kobj);
	if (attribute->store == NULL)
		return -EIO;
	return attribute->store(bundle, buf, len);
}

static struct sysfs_ops ksplice_sysfs_ops = {
	.show = ksplice_attr_show,
	.store = ksplice_attr_store,
};

static void ksplice_release(struct kobject *kobj)
{
	struct update_bundle *bundle;
	bundle = container_of(kobj, struct update_bundle, kobj);
	cleanup_ksplice_bundle(bundle);
}

static ssize_t stage_show(struct update_bundle *bundle, char *buf)
{
	switch (bundle->stage) {
	case STAGE_PREPARING:
		return snprintf(buf, PAGE_SIZE, "preparing\n");
	case STAGE_APPLIED:
		return snprintf(buf, PAGE_SIZE, "applied\n");
	case STAGE_REVERSED:
		return snprintf(buf, PAGE_SIZE, "reversed\n");
	}
	return 0;
}

static ssize_t abort_cause_show(struct update_bundle *bundle, char *buf)
{
	switch (bundle->abort_cause) {
	case OK:
		return snprintf(buf, PAGE_SIZE, "ok\n");
	case NO_MATCH:
		return snprintf(buf, PAGE_SIZE, "no_match\n");
	case BAD_SYSTEM_MAP:
		return snprintf(buf, PAGE_SIZE, "bad_system_map\n");
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

static ssize_t conflict_show(struct update_bundle *bundle, char *buf)
{
	const struct conflict *conf;
	const struct conflict_frame *frame;
	int used = 0;
	list_for_each_entry(conf, &bundle->conflicts, list) {
		used += snprintf(buf + used, PAGE_SIZE - used, "%s %d",
				 conf->process_name, conf->pid);
		list_for_each_entry(frame, &conf->stack, list) {
			if (!frame->has_conflict)
				continue;
			used += snprintf(buf + used, PAGE_SIZE - used, " %s",
					 frame->label);
		}
		used += snprintf(buf + used, PAGE_SIZE - used, "\n");
	}
	return used;
}

static ssize_t stage_store(struct update_bundle *bundle,
			   const char *buf, size_t len)
{
	if (strncmp(buf, "applied\n", len) == 0 &&
	    bundle->stage == STAGE_PREPARING)
		bundle->abort_cause = apply_update(bundle);
	else if (strncmp(buf, "reversed\n", len) == 0 &&
		 bundle->stage == STAGE_APPLIED)
		bundle->abort_cause = reverse_patches(bundle);
	return len;
}

static ssize_t debug_show(struct update_bundle *bundle, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", bundle->debug);
}

static ssize_t debug_store(struct update_bundle *bundle, const char *buf,
			   size_t len)
{
	unsigned long l;
	int ret = strict_strtoul(buf, 10, &l);
	if (ret != 0)
		return ret;
	bundle->debug = l;
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

static abort_t activate_primary(struct module_pack *pack)
{
	abort_t ret;
	ret = apply_relocs(pack, pack->primary_relocs,
			   pack->primary_relocs_end);
	if (ret != OK)
		return ret;

	ret = process_patches(pack);
	if (ret != OK)
		return ret;

	ret = process_exports(pack);
	if (ret != OK)
		return ret;

	ret = add_patch_dependencies(pack);
	if (ret != OK)
		return ret;

	return OK;
}

static void __attribute__((noreturn)) ksplice_deleted(void)
{
	printk(KERN_CRIT "Attempted call of kernel function deleted by Ksplice "
	       "update!\n");
	BUG();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
/* 91768d6c2bad0d2766a166f13f2f57e197de3458 was after 2.6.19 */
	for (;;);
#endif
}

static abort_t process_patches(struct module_pack *pack)
{
	struct ksplice_patch *p;
	struct safety_record *rec;
	abort_t ret;

	/* Check every patch has a safety_record */
	for (p = pack->patches; p < pack->patches_end; p++) {
		struct reloc_nameval *nv = find_nameval(pack, p->label);
		int found = 0;
		if (nv == NULL) {
			failed_to_find(pack, p->label);
			return FAILED_TO_FIND;
		}
		p->oldaddr = nv->val;

		list_for_each_entry(rec, &pack->safety_records, list) {
			if (strcmp(rec->label, p->label) == 0 &&
			    follow_trampolines(pack, p->oldaddr) == rec->addr) {
				found = 1;
				break;
			}
		}
		if (!found) {
			ksdebug(pack, 0, KERN_DEBUG "No safety record for "
				"patch %s\n", p->label);
			return UNEXPECTED;
		}
		if (rec->size < p->size) {
			ksdebug(pack, 0, KERN_DEBUG "Symbol %s is too short "
				"for trampoline\n", p->label);
			return UNEXPECTED;
		}

		if (p->repladdr == 0)
			p->repladdr = (unsigned long)ksplice_deleted;
		else
			rec->first_byte_safe = true;

		ret = create_trampoline(p);
		if (ret != OK)
			return ret;
	}
	return OK;
}

static abort_t process_exports(struct module_pack *pack)
{
	struct ksplice_export *export;
	struct module *m;
	const struct kernel_symbol *sym;

	for (export = pack->exports; export < pack->exports_end; export++) {
		sym = find_symbol(export->name, &m, NULL, true, false);
		if (sym == NULL) {
			ksdebug(pack, 0, "Could not find kernel_symbol struct"
				"for %s\n", export->name);
			return MISSING_EXPORT;
		}

		/* Cast away const since we are planning to mutate the
		 * kernel_symbol structure. */
		export->sym = (struct kernel_symbol *)sym;
		export->saved_name = export->sym->name;
		if (m != pack->primary && use_module(pack->primary, m) != 1)
			return UNEXPECTED;
	}
	return OK;
}

static void insert_trampoline(struct ksplice_patch *p)
{
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	memcpy((void *)p->saved, (void *)p->oldaddr, p->size);
	memcpy((void *)p->oldaddr, (void *)p->trampoline, p->size);
	flush_icache_range(p->oldaddr, p->oldaddr + p->size);
	set_fs(old_fs);
}

static void remove_trampoline(const struct ksplice_patch *p)
{
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	memcpy((void *)p->oldaddr, (void *)p->saved, p->size);
	flush_icache_range(p->oldaddr, p->oldaddr + p->size);
	set_fs(old_fs);
}

static abort_t apply_patches(struct update_bundle *bundle)
{
	int i;
	abort_t ret;

	for (i = 0; i < 5; i++) {
		cleanup_conflicts(bundle);
#ifdef KSPLICE_STANDALONE
		bust_spinlocks(1);
#endif /* KSPLICE_STANDALONE */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
		ret = (__force abort_t)stop_machine(__apply_patches, bundle,
						    NULL);
#else /* LINUX_VERSION_CODE < */
/* 9b1a4d38373a5581a4e01032a3ccdd94cd93477b was after 2.6.26 */
		ret = (__force abort_t)stop_machine_run(__apply_patches, bundle,
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

	if (ret == OK) {
		struct module_pack *pack;
		const struct ksplice_size *s;
		struct safety_record *rec;
		list_for_each_entry(pack, &bundle->packs, list) {
			for (s = pack->primary_sizes;
			     s < pack->primary_sizes_end; s++) {
				rec = kmalloc(sizeof(*rec), GFP_KERNEL);
				if (rec == NULL)
					return OUT_OF_MEMORY;
				rec->addr = s->thismod_addr;
				rec->size = s->size;
				rec->label = s->symbol->label;
				list_add(&rec->list, &pack->safety_records);
			}
		}
		_ksdebug(bundle, 0, KERN_INFO "ksplice: Update %s applied "
			 "successfully\n", bundle->kid);
		return 0;
	} else if (ret == CODE_BUSY) {
		print_conflicts(bundle);
		_ksdebug(bundle, 0, KERN_ERR "ksplice: Aborted %s.  stack "
			 "check: to-be-replaced code is busy\n", bundle->kid);
	} else if (ret == ALREADY_REVERSED) {
		_ksdebug(bundle, 0, KERN_ERR "ksplice: Aborted %s.  Ksplice "
			 "update %s is already reversed.\n", bundle->kid,
			 bundle->kid);
	}
	return ret;
}

static abort_t reverse_patches(struct update_bundle *bundle)
{
	int i;
	abort_t ret;
	struct module_pack *pack;

	clear_debug_buf(bundle);
	ret = init_debug_buf(bundle);
	if (ret != OK)
		return ret;

	_ksdebug(bundle, 0, KERN_INFO "ksplice: Preparing to reverse %s\n",
		 bundle->kid);

	for (i = 0; i < 5; i++) {
		cleanup_conflicts(bundle);
		clear_list(&bundle->conflicts, struct conflict, list);
#ifdef KSPLICE_STANDALONE
		bust_spinlocks(1);
#endif /* KSPLICE_STANDALONE */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
		ret = (__force abort_t)stop_machine(__reverse_patches, bundle,
						    NULL);
#else /* LINUX_VERSION_CODE < */
/* 9b1a4d38373a5581a4e01032a3ccdd94cd93477b was after 2.6.26 */
		ret = (__force abort_t)stop_machine_run(__reverse_patches,
							bundle, NR_CPUS);
#endif /* LINUX_VERSION_CODE */
#ifdef KSPLICE_STANDALONE
		bust_spinlocks(0);
#endif /* KSPLICE_STANDALONE */
		if (ret != CODE_BUSY)
			break;
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
	}
	list_for_each_entry(pack, &bundle->packs, list)
		clear_list(&pack->safety_records, struct safety_record, list);
	if (ret == OK) {
		_ksdebug(bundle, 0, KERN_INFO "ksplice: Update %s reversed"
			 " successfully\n", bundle->kid);
	} else if (ret == CODE_BUSY) {
		print_conflicts(bundle);
		_ksdebug(bundle, 0, KERN_ERR "ksplice: Aborted %s.  stack "
			 "check: to-be-reversed code is busy\n", bundle->kid);
	} else if (ret == MODULE_BUSY) {
		_ksdebug(bundle, 0, KERN_ERR "ksplice: Update %s is"
			 " in use by another module\n", bundle->kid);
	}
	return ret;
}

static int __apply_patches(void *bundleptr)
{
	struct update_bundle *bundle = bundleptr;
	struct module_pack *pack;
	struct ksplice_patch *p;
	struct ksplice_export *export;
	abort_t ret;

	if (bundle->stage == STAGE_APPLIED)
		return (__force int)OK;

	if (bundle->stage != STAGE_PREPARING)
		return (__force int)UNEXPECTED;

	ret = check_each_task(bundle);
	if (ret != OK)
		return (__force int)ret;

	list_for_each_entry(pack, &bundle->packs, list) {
		if (try_module_get(pack->primary) != 1) {
			struct module_pack *pack1;
			list_for_each_entry(pack1, &bundle->packs, list) {
				if (pack1 == pack)
					break;
				module_put(pack1->primary);
			}
			return (__force int)UNEXPECTED;
		}
	}

	bundle->stage = STAGE_APPLIED;

	list_for_each_entry(pack, &bundle->packs, list) {
		for (export = pack->exports; export < pack->exports_end;
		     export++)
			export->sym->name = export->new_name;
	}

	list_for_each_entry(pack, &bundle->packs, list) {
		for (p = pack->patches; p < pack->patches_end; p++)
			insert_trampoline(p);
	}
	return (__force int)OK;
}

static int __reverse_patches(void *bundleptr)
{
	struct update_bundle *bundle = bundleptr;
	struct module_pack *pack;
	const struct ksplice_patch *p;
	struct ksplice_export *export;
	abort_t ret;

	if (bundle->stage != STAGE_APPLIED)
		return (__force int)OK;

#ifdef CONFIG_MODULE_UNLOAD
	/* primary's refcount isn't changed by accessing ksplice.ko's sysfs */
	list_for_each_entry(pack, &bundle->packs, list) {
		if (module_refcount(pack->primary) != 1)
			return (__force int)MODULE_BUSY;
	}
#endif /* CONFIG_MODULE_UNLOAD */

	ret = check_each_task(bundle);
	if (ret != OK)
		return (__force int)ret;

	bundle->stage = STAGE_REVERSED;

	list_for_each_entry(pack, &bundle->packs, list)
		module_put(pack->primary);

	list_for_each_entry(pack, &bundle->packs, list) {
		for (export = pack->exports; export < pack->exports_end;
		     export++)
			export->sym->name = export->saved_name;
	}

	list_for_each_entry(pack, &bundle->packs, list) {
		for (p = pack->patches; p < pack->patches_end; p++)
			remove_trampoline(p);
	}
	return (__force int)OK;
}

static abort_t check_each_task(struct update_bundle *bundle)
{
	const struct task_struct *g, *p;
	abort_t status = OK, ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
/* 5d4564e68210e4b1edb3f013bc3e59982bb35737 was after 2.6.10 */
	read_lock(&tasklist_lock);
#endif /* LINUX_VERSION_CODE */
	do_each_thread(g, p) {
		/* do_each_thread is a double loop! */
		ret = check_task(bundle, p, 0);
		if (ret != OK) {
			check_task(bundle, p, 1);
			status = ret;
		}
		if (ret != OK && ret != CODE_BUSY)
			goto out;
	} while_each_thread(g, p);
out:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
/* 5d4564e68210e4b1edb3f013bc3e59982bb35737 was after 2.6.10 */
	read_unlock(&tasklist_lock);
#endif /* LINUX_VERSION_CODE */
	return status;
}

static abort_t check_task(struct update_bundle *bundle,
			  const struct task_struct *t, int rerun)
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
		list_add(&conf->list, &bundle->conflicts);
	}

	status = check_address(bundle, conf, KSPLICE_IP(t));
	if (t == current) {
		ret = check_stack(bundle, conf, task_thread_info(t),
				  (unsigned long *)__builtin_frame_address(0));
		if (status == OK)
			status = ret;
	} else if (!task_curr(t)) {
		ret = check_stack(bundle, conf, task_thread_info(t),
				  (unsigned long *)KSPLICE_SP(t));
		if (status == OK)
			status = ret;
	} else if (!is_stop_machine(t)) {
		status = UNEXPECTED_RUNNING_TASK;
	}
	return status;
}

/* Modified version of Linux's print_context_stack */
static abort_t check_stack(struct update_bundle *bundle, struct conflict *conf,
			   const struct thread_info *tinfo,
			   const unsigned long *stack)
{
	abort_t status = OK, ret;
	unsigned long addr;

	while (valid_stack_ptr(tinfo, stack)) {
		addr = *stack++;
		ret = check_address(bundle, conf, addr);
		if (ret != OK)
			status = ret;
	}
	return status;
}

static abort_t check_address(struct update_bundle *bundle,
			     struct conflict *conf, unsigned long addr)
{
	abort_t status = OK, ret;
	const struct safety_record *rec;
	struct module_pack *pack;
	struct conflict_frame *frame = NULL;

	if (conf != NULL) {
		frame = kmalloc(sizeof(*frame), GFP_ATOMIC);
		if (frame == NULL)
			return OUT_OF_MEMORY;
		frame->addr = addr;
		frame->has_conflict = 0;
		frame->label = NULL;
		list_add(&frame->list, &conf->stack);
	}

	list_for_each_entry(pack, &bundle->packs, list) {
		list_for_each_entry(rec, &pack->safety_records, list) {
			ret = check_record(frame, rec, addr);
			if (ret != OK)
				status = ret;
		}
	}
	return status;
}

static abort_t check_record(struct conflict_frame *frame,
			    const struct safety_record *rec, unsigned long addr)
{
	if ((addr > rec->addr && addr < rec->addr + rec->size) ||
	    (addr == rec->addr && !rec->first_byte_safe)) {
		if (frame != NULL) {
			frame->label = rec->label;
			frame->has_conflict = 1;
		}
		return CODE_BUSY;
	}
	return OK;
}

/* Modified version of Linux's valid_stack_ptr */
static int valid_stack_ptr(const struct thread_info *tinfo, const void *p)
{
	return p > (const void *)tinfo
	    && p <= (const void *)tinfo + THREAD_SIZE - sizeof(long);
}

static int is_stop_machine(const struct task_struct *t)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	const char *num;
	if (!starts_with(t->comm, "kstop"))
		return 0;
	num = t->comm + strlen("kstop");
	return num[strspn(num, "0123456789")] == '\0';
#else /* LINUX_VERSION_CODE < */
	return strcmp(t->comm, "kstopmachine") == 0;
#endif /* LINUX_VERSION_CODE */
}

static void cleanup_conflicts(struct update_bundle *bundle)
{
	struct conflict *conf;
	list_for_each_entry(conf, &bundle->conflicts, list) {
		clear_list(&conf->stack, struct conflict_frame, list);
		kfree(conf->process_name);
	}
	clear_list(&bundle->conflicts, struct conflict, list);
}

static void print_conflicts(struct update_bundle *bundle)
{
	const struct conflict *conf;
	const struct conflict_frame *frame;
	list_for_each_entry(conf, &bundle->conflicts, list) {
		_ksdebug(bundle, 2, KERN_DEBUG "ksplice: stack check: pid %d "
			 "(%s):", conf->pid, conf->process_name);
		list_for_each_entry(frame, &conf->stack, list) {
			_ksdebug(bundle, 2, " %" ADDR, frame->addr);
			if (frame->has_conflict)
				_ksdebug(bundle, 2, " [<-CONFLICT]");
		}
		_ksdebug(bundle, 2, "\n");
	}
}

#ifdef KSPLICE_NO_KERNEL_SUPPORT
static struct module *find_module(const char *name)
{
	struct module *mod;

	list_for_each_entry(mod, &modules, list) {
		if (strcmp(mod->name, name) == 0)
			return mod;
	}
	return NULL;
}
#endif /* KSPLICE_NO_KERNEL_SUPPORT */

static int register_ksplice_module(struct module_pack *pack)
{
	struct update_bundle *bundle;
	int ret = 0;

	INIT_LIST_HEAD(&pack->reloc_namevals);
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
	}
	list_for_each_entry(bundle, &update_bundles, list) {
		if (strcmp(pack->kid, bundle->kid) == 0) {
			if (bundle->stage != STAGE_PREPARING) {
				ret = -EPERM;
				goto out;
			}
			add_to_bundle(pack, bundle);
			list_add(&pack->module_list_entry.list,
				 &ksplice_module_list);
			goto out;
		}
	}
	bundle = init_ksplice_bundle(pack->kid);
	if (bundle == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	ret = ksplice_sysfs_init(bundle);
	if (ret != 0) {
		cleanup_ksplice_bundle(bundle);
		goto out;
	}
	add_to_bundle(pack, bundle);
	list_add(&pack->module_list_entry.list, &ksplice_module_list);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void cleanup_ksplice_module(struct module_pack *pack)
{
	if (pack->bundle == NULL || pack->bundle->stage == STAGE_APPLIED)
		return;
	mutex_lock(&module_mutex);
	list_del(&pack->list);
	list_del(&pack->module_list_entry.list);
	mutex_unlock(&module_mutex);
	if (list_empty(&pack->bundle->packs))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
		kobject_put(&pack->bundle->kobj);
#else /* LINUX_VERSION_CODE < */
/* 6d06adfaf82d154023141ddc0c9de18b6a49090b was after 2.6.24 */
		kobject_unregister(&pack->bundle->kobj);
#endif /* LINUX_VERSION_CODE */
	pack->bundle = NULL;
}
EXPORT_SYMBOL_GPL(cleanup_ksplice_module);

static void add_to_bundle(struct module_pack *pack,
			  struct update_bundle *bundle)
{
	pack->bundle = bundle;
	list_add(&pack->list, &bundle->packs);
	pack->module_list_entry.target = pack->target;
	pack->module_list_entry.primary = pack->primary;
}

static void cleanup_ksplice_bundle(struct update_bundle *bundle)
{
	mutex_lock(&module_mutex);
	list_del(&bundle->list);
	mutex_unlock(&module_mutex);
	cleanup_conflicts(bundle);
	clear_debug_buf(bundle);
	kfree(bundle->kid);
	kfree(bundle->name);
	kfree(bundle);
}

static struct update_bundle *init_ksplice_bundle(const char *kid)
{
	struct update_bundle *bundle;
	const char *str = "ksplice_";
	char *buf;
	bundle = kcalloc(1, sizeof(struct update_bundle), GFP_KERNEL);
	if (bundle == NULL)
		return NULL;
	buf = kmalloc(strlen(kid) + strlen(str) + 1, GFP_KERNEL);
	if (buf == NULL) {
		kfree(bundle);
		return NULL;
	}
	snprintf(buf, strlen(kid) + strlen(str) + 1, "%s%s", str, kid);
	bundle->name = buf;
	bundle->kid = kstrdup(kid, GFP_KERNEL);
	if (bundle->kid == NULL) {
		kfree(bundle->name);
		kfree(bundle);
		return NULL;
	}
	INIT_LIST_HEAD(&bundle->packs);
	if (init_debug_buf(bundle) != OK) {
		kfree(bundle->kid);
		kfree(bundle->name);
		kfree(bundle);
		return NULL;
	}
	list_add(&bundle->list, &update_bundles);
	bundle->stage = STAGE_PREPARING;
	bundle->abort_cause = OK;
	INIT_LIST_HEAD(&bundle->conflicts);
	return bundle;
}

static int ksplice_sysfs_init(struct update_bundle *bundle)
{
	int ret = 0;
	memset(&bundle->kobj, 0, sizeof(bundle->kobj));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#ifndef KSPLICE_STANDALONE
	ret = kobject_init_and_add(&bundle->kobj, &ksplice_ktype,
				   ksplice_kobj, "%s", bundle->kid);
#else /* KSPLICE_STANDALONE */
/* 6d06adfaf82d154023141ddc0c9de18b6a49090b was after 2.6.24 */
	ret = kobject_init_and_add(&bundle->kobj, &ksplice_ktype,
				   &THIS_MODULE->mkobj.kobj, "ksplice");
#endif /* KSPLICE_STANDALONE */
#else /* LINUX_VERSION_CODE < */
	ret = kobject_set_name(&bundle->kobj, "%s", "ksplice");
	if (ret != 0)
		return ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
	bundle->kobj.parent = &THIS_MODULE->mkobj.kobj;
#else /* LINUX_VERSION_CODE < */
/* b86ab02803095190d6b72bcc18dcf620bf378df9 was after 2.6.10 */
	bundle->kobj.parent = &THIS_MODULE->mkobj->kobj;
#endif /* LINUX_VERSION_CODE */
	bundle->kobj.ktype = &ksplice_ktype;
	ret = kobject_register(&bundle->kobj);
#endif /* LINUX_VERSION_CODE */
	if (ret != 0)
		return ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
	kobject_uevent(&bundle->kobj, KOBJ_ADD);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
/* 312c004d36ce6c739512bac83b452f4c20ab1f62 was after 2.6.14 */
/* 12025235884570ba7f02a6f427f973ac6be7ec54 was after 2.6.9 */
	kobject_uevent(&bundle->kobj, KOBJ_ADD, NULL);
#endif /* LINUX_VERSION_CODE */
	return 0;
}

int init_ksplice_module(struct module_pack *pack)
{
#ifdef KSPLICE_STANDALONE
	if (bootstrapped == 0)
		return -1;
#endif /* KSPLICE_STANDALONE */
	return register_ksplice_module(pack);
}
EXPORT_SYMBOL(init_ksplice_module);

static abort_t apply_update(struct update_bundle *bundle)
{
	struct module_pack *pack;
	abort_t ret;

	mutex_lock(&module_mutex);
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	list_for_each_entry(pack, &bundle->packs, list) {
		if (pack->target == NULL) {
			apply_paravirt(pack->primary_parainstructions,
				       pack->primary_parainstructions_end);
			apply_paravirt(pack->helper_parainstructions,
				       pack->helper_parainstructions_end);
		}
	}
#endif /* KSPLICE_NEED_PARAINSTRUCTIONS */

	list_for_each_entry(pack, &bundle->packs, list) {
		ksdebug(pack, 0, KERN_INFO "ksplice_h: Preparing and checking "
			"%s\n", pack->name);
		ret = activate_helper(pack, false);
		if (ret == NO_MATCH) {
			ksdebug(pack, 1, KERN_DEBUG "ksplice: "
				"Trying to continue without the unmatched "
				"sections; we will find them later.\n");
			ret = activate_primary(pack);
			if (ret != OK) {
				ksdebug(pack, 1, KERN_DEBUG "ksplice: "
					"Aborted.  Unable to continue without "
					"the unmatched sections.\n");
				goto out;
			}
			ksdebug(pack, 1, KERN_DEBUG "ksplice: run-pre: "
				"Considering .data sections to find the "
				"unmatched sections\n");
			ret = activate_helper(pack, true);
			if (ret != OK)
				goto out;
			ksdebug(pack, 1, KERN_DEBUG "ksplice_h: run-pre: "
				"Found all previously unmatched sections\n");
		} else if (ret != OK) {
			goto out;
		} else {
			ret = activate_primary(pack);
			if (ret != OK)
				goto out;
		}
	}
	ret = apply_patches(bundle);
out:
	list_for_each_entry(pack, &bundle->packs, list) {
		clear_list(&pack->reloc_namevals, struct reloc_nameval, list);
		if (bundle->stage == STAGE_PREPARING)
			clear_list(&pack->safety_records, struct safety_record,
				   list);
	}
	mutex_unlock(&module_mutex);
	return ret;
}

static abort_t activate_helper(struct module_pack *pack,
			       bool consider_data_sections)
{
	const struct ksplice_size *s;
	abort_t ret;
	char *finished;
	int i, remaining = 0;
	bool progress;

	finished = kcalloc(pack->helper_sizes_end - pack->helper_sizes,
			   sizeof(*finished), GFP_KERNEL);
	if (finished == NULL)
		return OUT_OF_MEMORY;
	for (s = pack->helper_sizes; s < pack->helper_sizes_end; s++) {
		if ((s->flags & KSPLICE_SIZE_DATA) == 0)
			remaining++;
	}

	while (remaining > 0) {
		progress = false;
		for (s = pack->helper_sizes; s < pack->helper_sizes_end; s++) {
			i = s - pack->helper_sizes;
			if (finished[i])
				continue;
			if (!consider_data_sections &&
			    (s->flags & KSPLICE_SIZE_DATA) != 0)
				continue;
			ret = search_for_match(pack, s);
			if (ret == OK) {
				finished[i] = 1;
				if ((s->flags & KSPLICE_SIZE_DATA) == 0)
					remaining--;
				progress = true;
			} else if (ret != NO_MATCH) {
				kfree(finished);
				return ret;
			}
		}

		if (progress)
			continue;

		for (s = pack->helper_sizes; s < pack->helper_sizes_end; s++) {
			i = s - pack->helper_sizes;
			if (finished[i] == 0)
				ksdebug(pack, 2, KERN_DEBUG "ksplice: run-pre: "
					"could not match section %s\n",
					s->symbol->label);
		}
		print_abort(pack, "run-pre: could not match some sections");
		kfree(finished);
		return NO_MATCH;
	}
	kfree(finished);
	return OK;
}

static abort_t search_for_match(struct module_pack *pack,
				const struct ksplice_size *s)
{
	int i;
	abort_t ret;
	unsigned long run_addr;
	LIST_HEAD(vals);
	struct candidate_val *v, *n;

	ret = add_system_map_candidates(pack, s->symbol, &vals);
	if (ret != OK) {
		release_vals(&vals);
		return ret;
	}
	ret = compute_address(pack, s->symbol, &vals);
	if (ret != OK) {
		release_vals(&vals);
		return ret;
	}

	ksdebug(pack, 3, KERN_DEBUG "ksplice_h: run-pre: starting sect search "
		"for %s\n", s->symbol->label);

	list_for_each_entry_safe(v, n, &vals, list) {
		run_addr = v->val;

		yield();
		ret = try_addr(pack, s, run_addr, NULL, RUN_PRE_INITIAL);
		if (ret == NO_MATCH) {
			list_del(&v->list);
			kfree(v);
		} else if (ret != OK) {
			release_vals(&vals);
			return ret;
		}
	}

#ifdef KSPLICE_STANDALONE
	if (list_empty(&vals) && (s->flags & KSPLICE_SIZE_DATA) == 0) {
		ret = brute_search_all(pack, s, &vals);
		if (ret != OK) {
			release_vals(&vals);
			return ret;
		}
		/* Make sure run-pre matching output is displayed if
		   brute_search succeeds */
		if (singular(&vals)) {
			run_addr = list_entry(vals.next, struct candidate_val,
					      list)->val;
			ret = try_addr(pack, s, run_addr, NULL,
				       RUN_PRE_INITIAL);
			if (ret != OK) {
				ksdebug(pack, 3, KERN_DEBUG "ksplice_h: "
					"run-pre: Debug run failed for sect "
					"%s:\n", s->symbol->label);
				release_vals(&vals);
				return ret;
			}
		}
	}
#endif /* KSPLICE_STANDALONE */

	if (singular(&vals)) {
		LIST_HEAD(safety_records);
		run_addr = list_entry(vals.next, struct candidate_val,
				      list)->val;
		ret = try_addr(pack, s, run_addr, &safety_records,
			       RUN_PRE_FINAL);
		release_vals(&vals);
		if (ret != OK) {
			clear_list(&safety_records, struct safety_record, list);
			ksdebug(pack, 3, KERN_DEBUG "ksplice_h: run-pre: "
				"Final run failed for sect %s:\n",
				s->symbol->label);
		} else {
			list_splice(&safety_records, &pack->safety_records);
		}
		return ret;
	} else if (!list_empty(&vals)) {
		struct candidate_val *val;
		ksdebug(pack, 3, KERN_DEBUG "ksplice_h: run-pre: multiple "
			"candidates for sect %s:\n", s->symbol->label);
		i = 0;
		list_for_each_entry(val, &vals, list) {
			i++;
			ksdebug(pack, 3, KERN_DEBUG "%lx\n", val->val);
			if (i > 5) {
				ksdebug(pack, 3, KERN_DEBUG "...\n");
				break;
			}
		}
		release_vals(&vals);
		return NO_MATCH;
	}
	release_vals(&vals);
	return NO_MATCH;
}

static void print_bytes(struct module_pack *pack,
			const unsigned char *run, int runc,
			const unsigned char *pre, int prec)
{
	int o;
	int matched = min(runc, prec);
	for (o = 0; o < matched; o++) {
		if (run[o] == pre[o])
			ksdebug(pack, 0, "%02x ", run[o]);
		else
			ksdebug(pack, 0, "%02x/%02x ", run[o], pre[o]);
	}
	for (o = matched; o < runc; o++)
		ksdebug(pack, 0, "%02x/ ", run[o]);
	for (o = matched; o < prec; o++)
		ksdebug(pack, 0, "/%02x ", pre[o]);
}

static abort_t run_pre_cmp(struct module_pack *pack,
			   const struct ksplice_size *s,
			   unsigned long run_addr,
			   struct list_head *safety_records,
			   enum run_pre_mode mode)
{
	int matched = 0;
	abort_t ret;
	unsigned long pre_addr = s->thismod_addr;
	const struct ksplice_reloc *r;
	const unsigned char *pre, *run;
	unsigned char runval;

	if ((s->flags & KSPLICE_SIZE_TEXT) != 0)
		run_addr = follow_trampolines(pack, run_addr);

	pre = (const unsigned char *)pre_addr;
	run = (const unsigned char *)run_addr;
	while (pre < (const unsigned char *)pre_addr + s->size) {
		ret = lookup_reloc(pack, (unsigned long)pre, &r);
		if (ret == OK) {
			ret = handle_reloc(pack, r, (unsigned long)run, mode);
			if (ret != OK) {
				if (mode == RUN_PRE_INITIAL)
					ksdebug(pack, 3, "reloc in sect does "
						"not match after %lx/%lx bytes"
						"\n", (unsigned long)pre -
						pre_addr, s->size);
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

		if ((s->flags & KSPLICE_SIZE_TEXT) != 0) {
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
				ksdebug(pack, 3, "sect unmapped after "
					"%lx/%lx bytes\n",
					(unsigned long)pre - pre_addr, s->size);
			return NO_MATCH;
		}

		if (runval != *pre && (s->flags & KSPLICE_SIZE_DATA) == 0) {
			if (mode == RUN_PRE_INITIAL)
				ksdebug(pack, 3, "sect does not match after "
					"%lx/%lx bytes\n",
					(unsigned long)pre - pre_addr, s->size);
			if (mode == RUN_PRE_DEBUG) {
				print_bytes(pack, run, 1, pre, 1);
				ksdebug(pack, 0, "[p_o=%lx] ! ",
					(unsigned long)pre - pre_addr);
				print_bytes(pack, run + 1, 2, pre + 1, 2);
			}
			return NO_MATCH;
		}
		if (mode == RUN_PRE_DEBUG)
			print_bytes(pack, run, 1, pre, 1);
		pre++;
		run++;
	}
	return create_safety_record(pack, s, safety_records, run_addr,
				    (unsigned long)run - run_addr);
}

#ifdef KSPLICE_NO_KERNEL_SUPPORT
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

static abort_t try_addr(struct module_pack *pack, const struct ksplice_size *s,
			unsigned long run_addr,
			struct list_head *safety_records,
			enum run_pre_mode mode)
{
	abort_t ret;
	const struct module *run_module;

	if ((s->flags & KSPLICE_SIZE_RODATA) != 0 ||
	    (s->flags & KSPLICE_SIZE_DATA) != 0)
		run_module = __module_data_address(run_addr);
	else
		run_module = __module_text_address(run_addr);
	if (run_module != pack->target) {
		ksdebug(pack, 1, KERN_DEBUG "ksplice_h: run-pre: ignoring "
			"address %" ADDR " in other module %s for sect %s\n",
			run_addr,
			run_module == NULL ? "vmlinux" : run_module->name,
			s->symbol->label);
		return NO_MATCH;
	}

	ret = create_nameval(pack, s->symbol->label, run_addr, TEMP);
	if (ret != OK)
		return ret;

#ifdef FUNCTION_SECTIONS
	ret = run_pre_cmp(pack, s, run_addr, safety_records, mode);
#else
	if ((s->flags & KSPLICE_SIZE_TEXT) != 0)
		ret = arch_run_pre_cmp(pack, s, run_addr, safety_records, mode);
	else
		ret = run_pre_cmp(pack, s, run_addr, safety_records, mode);
#endif
	if (ret == NO_MATCH && mode != RUN_PRE_FINAL) {
		set_temp_myst_relocs(pack, NOVAL);
		ksdebug(pack, 1, KERN_DEBUG "ksplice_h: run-pre: %s sect %s "
			"does not match ",
			(s->flags & KSPLICE_SIZE_RODATA) != 0 ? "data" : "text",
			s->symbol->label);
		ksdebug(pack, 1, "(r_a=%" ADDR " p_a=%" ADDR " s=%ld)\n",
			run_addr, s->thismod_addr, s->size);
		ksdebug(pack, 1, KERN_DEBUG "ksplice_h: run-pre: ");
		if (pack->bundle->debug >= 1) {
#ifdef FUNCTION_SECTIONS
			ret = run_pre_cmp(pack, s, run_addr, safety_records,
					  RUN_PRE_DEBUG);
#else
			if ((s->flags & KSPLICE_SIZE_TEXT) != 0)
				ret = arch_run_pre_cmp(pack, s, run_addr,
						       safety_records,
						       RUN_PRE_DEBUG);
			else
				ret = run_pre_cmp(pack, s, run_addr,
						  safety_records,
						  RUN_PRE_DEBUG);
#endif
			set_temp_myst_relocs(pack, NOVAL);
		}
		ksdebug(pack, 1, "\n");
		return ret;
	} else if (ret != OK) {
		set_temp_myst_relocs(pack, NOVAL);
		return ret;
	} else if (mode != RUN_PRE_FINAL) {
		set_temp_myst_relocs(pack, NOVAL);
		ksdebug(pack, 3, KERN_DEBUG "ksplice_h: run-pre: candidate "
			"for sect %s=%" ADDR "\n", s->symbol->label, run_addr);
		return OK;
	}

	set_temp_myst_relocs(pack, VAL);
	ksdebug(pack, 3, KERN_DEBUG "ksplice_h: run-pre: found sect %s=%" ADDR
		"\n", s->symbol->label, run_addr);
	return OK;
}

static abort_t create_safety_record(struct module_pack *pack,
				    const struct ksplice_size *s,
				    struct list_head *record_list,
				    unsigned long run_addr,
				    unsigned long run_size)
{
	struct safety_record *rec;
	struct ksplice_patch *p;

	if (record_list == NULL)
		return OK;

	for (p = pack->patches; p < pack->patches_end; p++) {
		if (strcmp(s->symbol->label, p->label) == 0)
			break;
	}
	if (p >= pack->patches_end)
		return OK;

	if ((s->flags & KSPLICE_SIZE_TEXT) == 0 && p->repladdr != 0) {
		ksdebug(pack, 3, KERN_DEBUG "ksplice_h: Error: ksplice_patch "
			"%s is matched to a non-deleted non-text section!\n",
			s->symbol->label);
		return UNEXPECTED;
	}

	rec = kmalloc(sizeof(*rec), GFP_KERNEL);
	if (rec == NULL)
		return OUT_OF_MEMORY;
	rec->addr = run_addr;
	rec->size = run_size;
	rec->label = s->symbol->label;
	rec->first_byte_safe = false;

	list_add(&rec->list, record_list);
	return OK;
}

static abort_t handle_reloc(struct module_pack *pack,
			    const struct ksplice_reloc *r,
			    unsigned long run_addr, enum run_pre_mode mode)
{
	long run_reloc_val, expected;
	abort_t ret;
	struct reloc_nameval *nv = find_nameval(pack, r->symbol->label);
	unsigned char bytes[8];

	if (probe_kernel_read(bytes, (void *)run_addr, r->size) == -EFAULT)
		return NO_MATCH;

	switch (r->size) {
	case 1:
		run_reloc_val = *(int8_t *)bytes & (int8_t)r->dst_mask;
		break;
	case 2:
		run_reloc_val = *(int16_t *)bytes & (int16_t)r->dst_mask;
		break;
	case 4:
		run_reloc_val = *(int32_t *)bytes & (int32_t)r->dst_mask;
		break;
	case 8:
		run_reloc_val = *(int64_t *)bytes & (int64_t)r->dst_mask;
		break;
	default:
		print_abort(pack, "Invalid relocation size");
		return UNEXPECTED;
	}

	if (r->signed_addend)
		run_reloc_val |=
		    -(run_reloc_val & (r->dst_mask & ~(r->dst_mask >> 1)));

	run_reloc_val <<= r->rightshift;

	if (mode == RUN_PRE_INITIAL) {
		ksdebug(pack, 3, KERN_DEBUG "ksplice_h: run-pre: reloc at r_a=%"
			ADDR " p_a=%" ADDR ": ", run_addr, r->blank_addr);
		ksdebug(pack, 3, "%s=%" ADDR " (A=%" ADDR " *r=%" ADDR ")\n",
			r->symbol->label, nv != NULL ? nv->val : 0, r->addend,
			run_reloc_val);
	}

	if (!starts_with(r->symbol->label, ".rodata.str")) {
		if (contains_canary(pack, run_addr, r->size, r->dst_mask) != 0)
			return UNEXPECTED;

		expected = run_reloc_val - r->addend;
		if (r->pcrel)
			expected += run_addr;

		ret = create_nameval(pack, r->symbol->label, expected, TEMP);
		if (ret == NO_MATCH && mode == RUN_PRE_INITIAL) {
			ksdebug(pack, 1, KERN_DEBUG "ksplice_h: run-pre reloc: "
				"Nameval address %" ADDR "(%d) does not match "
				"expected %" ADDR " for %s!\n", nv->val,
				nv->status, expected, r->symbol->label);
			ksdebug(pack, 1, KERN_DEBUG "ksplice_h: run-pre reloc: "
				"run_reloc: %" ADDR " %" ADDR " %" ADDR "\n",
				run_addr, run_reloc_val, r->addend);
			return ret;
		} else if (ret != OK) {
			return ret;
		}
	}
	return OK;
}

static abort_t write_reloc_value(struct module_pack *pack,
				 const struct ksplice_reloc *r,
				 unsigned long sym_addr)
{
	unsigned long val = sym_addr + r->addend;
	if (r->pcrel)
		val -= r->blank_addr;
	switch (r->size) {
	case 1:
		*(int8_t *)r->blank_addr =
		    (*(int8_t *)r->blank_addr & ~(int8_t)r->dst_mask)
		    | ((val >> r->rightshift) & (int8_t)r->dst_mask);
		break;
	case 2:
		*(int16_t *)r->blank_addr =
		    (*(int16_t *)r->blank_addr & ~(int16_t)r->dst_mask)
		    | ((val >> r->rightshift) & (int16_t)r->dst_mask);
		break;
	case 4:
		*(int32_t *)r->blank_addr =
		    (*(int32_t *)r->blank_addr & ~(int32_t)r->dst_mask)
		    | ((val >> r->rightshift) & (int32_t)r->dst_mask);
		break;
	case 8:
		*(int64_t *)r->blank_addr =
		    (*(int64_t *)r->blank_addr & ~r->dst_mask) |
		    ((val >> r->rightshift) & r->dst_mask);
		break;
	default:
		print_abort(pack, "Invalid relocation size");
		return UNEXPECTED;
	}
	return OK;
}

static abort_t apply_relocs(struct module_pack *pack,
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

static abort_t apply_reloc(struct module_pack *pack,
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
		ksdebug(pack, 4, KERN_DEBUG "ksplice: reloc: skipped %s:%"
			ADDR " (altinstr)\n", r->symbol->label,
			r->blank_offset);
		return OK;
	}

#ifdef KSPLICE_STANDALONE
	if (!bootstrapped) {
		ret = add_system_map_candidates(pack, r->symbol, &vals);
		if (ret != OK) {
			release_vals(&vals);
			return ret;
		}
	}
#else /* !KSPLICE_STANDALONE */
#ifdef CONFIG_KALLSYMS
	ret = add_system_map_candidates(pack, r->symbol, &vals);
	if (ret != OK) {
		release_vals(&vals);
		return ret;
	}
#endif /* CONFIG_KALLSYMS */
#endif /* KSPLICE_STANDALONE */
	ret = compute_address(pack, r->symbol, &vals);
	if (ret != OK) {
		release_vals(&vals);
		return ret;
	}
	if (!singular(&vals)) {
		release_vals(&vals);
		failed_to_find(pack, r->symbol->label);
		return FAILED_TO_FIND;
	}
	sym_addr = list_entry(vals.next, struct candidate_val, list)->val;
	release_vals(&vals);

	ret = write_reloc_value(pack, r, sym_addr);
	if (ret != OK)
		return ret;

	ksdebug(pack, 4, KERN_DEBUG "ksplice: reloc: %s:%" ADDR " ",
		r->symbol->label, r->blank_offset);
	ksdebug(pack, 4, "(S=%" ADDR " A=%" ADDR " ", sym_addr, r->addend);
	switch (r->size) {
	case 1:
		ksdebug(pack, 4, "aft=%02x)\n", *(int8_t *)r->blank_addr);
		break;
	case 2:
		ksdebug(pack, 4, "aft=%04x)\n", *(int16_t *)r->blank_addr);
		break;
	case 4:
		ksdebug(pack, 4, "aft=%08x)\n", *(int32_t *)r->blank_addr);
		break;
	case 8:
		ksdebug(pack, 4, "aft=%016llx)\n", *(int64_t *)r->blank_addr);
		break;
	default:
		print_abort(pack, "Invalid relocation size");
		return UNEXPECTED;
	}
#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return OK;
#endif /* KSPLICE_STANDALONE */
	/* Create namevals so that we can verify our choices in the second
	   round of run-pre matching that considers data sections. */
	ret = create_nameval(pack, r->symbol->label, sym_addr, VAL);
	if (ret != OK)
		return ret;
	return add_dependency_on_address(pack, sym_addr);
}

static abort_t add_system_map_candidates(struct module_pack *pack,
					 const struct ksplice_symbol *symbol,
					 struct list_head *vals)
{
	abort_t ret;
	long off;
	int i;

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
		print_abort(pack, "System.map does not match kernel");
		return BAD_SYSTEM_MAP;
	}
	for (i = 0; i < symbol->nr_candidates; i++) {
		ret = add_candidate_val(vals, symbol->candidates[i] + off);
		if (ret != OK)
			return ret;
	}
	return OK;
}

static abort_t add_dependency_on_address(struct module_pack *pack,
					 unsigned long addr)
{
	struct module *m =
	    __module_text_address(follow_trampolines(pack, addr));
	if (m == NULL || starts_with(m->name, pack->name) ||
	    ends_with(m->name, "_helper"))
		return OK;
	if (use_module(pack->primary, m) != 1)
		return MODULE_BUSY;
	return OK;
}

static abort_t add_patch_dependencies(struct module_pack *pack)
{
	abort_t ret;
	const struct ksplice_patch *p;
	for (p = pack->patches; p < pack->patches_end; p++) {
		ret = add_dependency_on_address(pack, p->oldaddr);
		if (ret != OK)
			return ret;
	}
	return 0;
}

#ifdef KSPLICE_NO_KERNEL_SUPPORT
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
#endif /* KSPLICE_NO_KERNEL_SUPPORT */

static abort_t compute_address(struct module_pack *pack,
			       const struct ksplice_symbol *ksym,
			       struct list_head *vals)
{
	abort_t ret;
	struct reloc_nameval *nv;

#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return OK;
#endif /* KSPLICE_STANDALONE */

	nv = find_nameval(pack, ksym->label);
	if (nv != NULL) {
		release_vals(vals);
		ksdebug(pack, 1, KERN_DEBUG "ksplice: using detected "
			"sym %s=%" ADDR "\n", ksym->label, nv->val);
		return add_candidate_val(vals, nv->val);
	}

	if (starts_with(ksym->label, ".rodata"))
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
	if (ret == OK)
		ret = new_export_lookup(pack->bundle, ksym->name, vals);
#ifdef CONFIG_KALLSYMS
	if (ret == OK)
		ret = kernel_lookup(ksym->name, vals);
	if (ret == OK)
		ret = other_module_lookup(pack, ksym->name, vals);
#endif /* CONFIG_KALLSYMS */
	if (ret != OK)
		return ret;

	return OK;
}

static abort_t new_export_lookup(struct update_bundle *bundle,
				 const char *name, struct list_head *vals)
{
	struct module_pack *pack;
	struct ksplice_export *exp;
	list_for_each_entry(pack, &bundle->packs, list) {
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

static abort_t exported_symbol_lookup(const char *name, struct list_head *vals)
{
	const struct kernel_symbol *sym;
	sym = find_symbol(name, NULL, NULL, true, false);
	if (sym == NULL)
		return OK;
	return add_candidate_val(vals, sym->value);
}

#ifdef KSPLICE_NO_KERNEL_SUPPORT
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
#endif /* KSPLICE_NO_KERNEL_SUPPORT */

#ifdef CONFIG_KALLSYMS
#ifdef KSPLICE_NO_KERNEL_SUPPORT
static abort_t other_module_lookup(struct module_pack *pack, const char *name,
				   struct list_head *vals)
{
	abort_t ret = OK;
	struct accumulate_struct acc = { name, vals };
	const struct module *m;

	list_for_each_entry(m, &modules, list) {
		if (starts_with(m->name, pack->name) ||
		    !ends_with(m->name, pack->target_name))
			continue;
		ret = (__force abort_t)
		    module_kallsyms_on_each_symbol(m, accumulate_matching_names,
						   &acc);
		if (ret != OK)
			break;
	}
	return ret;
}
#else /* !KSPLICE_NO_KERNEL_SUPPORT */
static abort_t other_module_lookup(struct module_pack *pack, const char *name,
				   struct list_head *vals)
{
	struct accumulate_struct acc = { name, vals };
	struct ksplice_module_list_entry *entry;
	abort_t ret;

	list_for_each_entry(entry, &ksplice_module_list, list) {
		if (entry->target != pack->target ||
		    entry->primary == pack->primary)
			continue;
		ret = (__force abort_t)
		    module_kallsyms_on_each_symbol(entry->primary,
						   accumulate_matching_names,
						   &acc);
		if (ret != OK)
			return ret;
	}
	if (pack->target == NULL)
		return OK;
	ret = (__force abort_t)
	    module_kallsyms_on_each_symbol(pack->target,
					   accumulate_matching_names, &acc);
	return ret;
}
#endif /* KSPLICE_NO_KERNEL_SUPPORT */

static int accumulate_matching_names(void *data, const char *sym_name,
				     unsigned long sym_val)
{
	abort_t ret = OK;
	struct accumulate_struct *acc = data;

	if (strcmp(sym_name, acc->desired_name) == 0)
		ret = add_candidate_val(acc->vals, sym_val);
	return (__force int)ret;
}
#endif /* CONFIG_KALLSYMS */

#ifdef KSPLICE_STANDALONE
static abort_t brute_search(struct module_pack *pack,
			    const struct ksplice_size *s,
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

		pre = *(const unsigned char *)(s->thismod_addr);

		if (run != pre)
			continue;

		ret = try_addr(pack, s, addr, NULL, RUN_PRE_INITIAL);
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

static abort_t brute_search_all(struct module_pack *pack,
				const struct ksplice_size *s,
				struct list_head *vals)
{
	struct module *m;
	abort_t ret = OK;
	int saved_debug;

	ksdebug(pack, 2, KERN_DEBUG "ksplice: brute_search: searching for %s\n",
		s->symbol->label);
	saved_debug = pack->bundle->debug;
	pack->bundle->debug = 0;

	list_for_each_entry(m, &modules, list) {
		if (starts_with(m->name, pack->name) ||
		    ends_with(m->name, "_helper"))
			continue;
		ret = brute_search(pack, s, m->module_core, m->core_size, vals);
		if (ret != OK)
			break;
		ret = brute_search(pack, s, m->module_init, m->init_size, vals);
		if (ret != OK)
			break;
	}
	if (ret == OK)
		ret = brute_search(pack, s, (const void *)init_mm.start_code,
				   init_mm.end_code - init_mm.start_code, vals);
	pack->bundle->debug = saved_debug;

	return ret;
}

#ifdef CONFIG_KALLSYMS
/* Modified version of Linux's kallsyms_lookup_name */
static abort_t kernel_lookup(const char *name, struct list_head *vals)
{
	abort_t ret;
	char namebuf[KSYM_NAME_LEN + 1];
	unsigned long i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	unsigned long off;
#endif /* LINUX_VERSION_CODE */

/*  kallsyms compression was added by 5648d78927ca65e74aadc88a2b1d6431e55e78ec
 *  2.6.10 was the first release after this commit
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	for (i = 0, off = 0; i < kallsyms_num_syms; i++) {
		off = ksplice_kallsyms_expand_symbol(off, namebuf);

		if (strcmp(namebuf, name) == 0) {
			ret = add_candidate_val(vals, kallsyms_addresses[i]);
			if (ret != OK)
				return ret;
		}
	}
#else /* LINUX_VERSION_CODE < */
	char *knames;

	for (i = 0, knames = kallsyms_names; i < kallsyms_num_syms; i++) {
		unsigned prefix = *knames++;

		strlcpy(namebuf + prefix, knames, KSYM_NAME_LEN - prefix);

		if (strcmp(namebuf, name) == 0) {
			ret = add_candidate_val(vals, kallsyms_addresses[i]);
			if (ret != OK)
				return ret;
		}

		knames += strlen(knames) + 1;
	}
#endif /* LINUX_VERSION_CODE */

	return OK;
}

/*  kallsyms compression was added by 5648d78927ca65e74aadc88a2b1d6431e55e78ec
 *  2.6.10 was the first release after this commit
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
extern u8 kallsyms_token_table[];
extern u16 kallsyms_token_index[];
/* Modified version of Linux's kallsyms_expand_symbol */
static unsigned long ksplice_kallsyms_expand_symbol(unsigned long off,
						    char *result)
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

#ifdef KSPLICE_NO_KERNEL_SUPPORT
static int module_kallsyms_on_each_symbol(const struct module *mod,
					  int (*fn)(void *, const char *,
						    unsigned long),
					  void *data)
{
	unsigned int i;
	int ret;

	for (i = 0; i < mod->num_symtab; i++) {
		if ((ret =
		     fn(data, mod->strtab + mod->symtab[i].st_name,
			mod->symtab[i].st_value) != 0))
			return ret;
	}
	return 0;
}
#endif /* KSPLICE_NO_KERNEL_SUPPORT */
#endif /* CONFIG_KALLSYMS */
#else /* !KSPLICE_STANDALONE */

static abort_t kernel_lookup(const char *name, struct list_head *vals)
{
	struct accumulate_struct acc = { name, vals };
	return (__force abort_t)
	    kernel_kallsyms_on_each_symbol(accumulate_matching_names, &acc);
}
#endif /* KSPLICE_STANDALONE */

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

static void release_vals(struct list_head *vals)
{
	clear_list(vals, struct candidate_val, list);
}

static struct reloc_nameval *find_nameval(struct module_pack *pack,
					  const char *label)
{
	struct reloc_nameval *nv;
	list_for_each_entry(nv, &pack->reloc_namevals, list) {
		if (strcmp(nv->label, label) == 0)
			return nv;
	}
	return NULL;
}

static abort_t create_nameval(struct module_pack *pack, const char *label,
			      unsigned long val, int status)
{
	struct reloc_nameval *nv = find_nameval(pack, label);
	if (nv != NULL)
		return nv->val == val ? OK : NO_MATCH;

	nv = kmalloc(sizeof(*nv), GFP_KERNEL);
	if (nv == NULL)
		return OUT_OF_MEMORY;
	nv->label = label;
	nv->val = val;
	nv->status = status;
	list_add(&nv->list, &pack->reloc_namevals);
	return OK;
}

static abort_t lookup_reloc(struct module_pack *pack, unsigned long addr,
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
				ksdebug(pack, 4, KERN_DEBUG "ksplice_h: reloc: "
					"skipped %s:%" ADDR " (altinstr)\n",
					r->symbol->label, r->blank_offset);
				return NO_MATCH;
			}
			if (addr != r->blank_addr) {
				ksdebug(pack, 4, KERN_DEBUG "ksplice_h: Invalid"
					" nonzero relocation offset\n");
				return UNEXPECTED;
			}
			*relocp = r;
			return OK;
		}
	}
	return NO_MATCH;
}

static void set_temp_myst_relocs(struct module_pack *pack, int status_val)
{
	struct reloc_nameval *nv, *n;
	list_for_each_entry_safe(nv, n, &pack->reloc_namevals, list) {
		if (nv->status == TEMP) {
			if (status_val == NOVAL) {
				list_del(&nv->list);
				kfree(nv);
			} else {
				nv->status = status_val;
			}
		}
	}
}

static int contains_canary(struct module_pack *pack, unsigned long blank_addr,
			   int size, long dst_mask)
{
	switch (size) {
	case 1:
		return (*(int8_t *)blank_addr & (int8_t)dst_mask) ==
		    (0x77 & dst_mask);
	case 2:
		return (*(int16_t *)blank_addr & (int16_t)dst_mask) ==
		    (0x7777 & dst_mask);
	case 4:
		return (*(int32_t *)blank_addr & (int32_t)dst_mask) ==
		    (0x77777777 & dst_mask);
	case 8:
		return (*(int64_t *)blank_addr & dst_mask) ==
		    (0x7777777777777777ll & dst_mask);
	default:
		print_abort(pack, "Invalid relocation size");
		return -1;
	}
}

static int starts_with(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

static int ends_with(const char *str, const char *suffix)
{
	return strlen(str) >= strlen(suffix) &&
	    strcmp(&str[strlen(str) - strlen(suffix)], suffix) == 0;
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

static void clear_debug_buf(struct update_bundle *bundle)
{
	if (bundle->debugfs_dentry == NULL)
		return;
	debugfs_remove(bundle->debugfs_dentry);
	bundle->debugfs_dentry = NULL;
	bundle->debug_blob.size = 0;
	vfree(bundle->debug_blob.data);
	bundle->debug_blob.data = NULL;
}

static abort_t init_debug_buf(struct update_bundle *bundle)
{
	bundle->debug_blob.size = 0;
	bundle->debug_blob.data = NULL;
	bundle->debugfs_dentry =
	    debugfs_create_blob(bundle->name, S_IFREG | S_IRUSR, NULL,
				&bundle->debug_blob);
	if (bundle->debugfs_dentry == NULL)
		return OUT_OF_MEMORY;
	return OK;
}

static int __ksdebug(struct update_bundle *bundle, const char *fmt, ...)
{
	va_list args;
	unsigned long size, old_size, new_size;

	if ((bundle->debug_blob.data == NULL ||
	     ((char *)bundle->debug_blob.data)[bundle->debug_blob.size - 1] ==
	     '\n') && strlen(fmt) >= 3 && fmt[0] == '<' && fmt[1] >= '0' &&
	    fmt[1] <= '7' && fmt[2] == '>')
		fmt += 3;

	/* size includes the trailing '\0' */
	va_start(args, fmt);
	size = 1 + vsnprintf(bundle->debug_blob.data, 0, fmt, args);
	va_end(args);
	old_size = bundle->debug_blob.size == 0 ? 0 :
	    max(PAGE_SIZE, roundup_pow_of_two(bundle->debug_blob.size));
	new_size = bundle->debug_blob.size + size == 0 ? 0 :
	    max(PAGE_SIZE, roundup_pow_of_two(bundle->debug_blob.size + size));
	if (new_size > old_size) {
		char *buf = vmalloc(new_size);
		if (buf == NULL)
			return -ENOMEM;
		memcpy(buf, bundle->debug_blob.data, bundle->debug_blob.size);
		vfree(bundle->debug_blob.data);
		bundle->debug_blob.data = buf;
	}
	va_start(args, fmt);
	bundle->debug_blob.size += vsnprintf(bundle->debug_blob.data +
					     bundle->debug_blob.size,
					     size, fmt, args);
	va_end(args);
	return 0;
}
#endif /* CONFIG_DEBUG_FS */

#ifdef KSPLICE_STANDALONE
static int debug;
module_param(debug, int, 0600);
MODULE_PARM_DESC(debug, "Debug level");

static struct module_pack ksplice_pack = {
	.name = "ksplice_" STR(KSPLICE_KID),
	.kid = "init_" STR(KSPLICE_KID),
	.target_name = NULL,
	.target = NULL,
	.map_printk = MAP_PRINTK,
	.primary = THIS_MODULE,
	.reloc_namevals = LIST_HEAD_INIT(ksplice_pack.reloc_namevals),
};
#endif /* KSPLICE_STANDALONE */

static int init_ksplice(void)
{
#ifdef KSPLICE_STANDALONE
	struct module_pack *pack = &ksplice_pack;
	pack->bundle = init_ksplice_bundle(pack->kid);
	if (pack->bundle == NULL)
		return -ENOMEM;
	add_to_bundle(pack, pack->bundle);
	pack->bundle->debug = debug;
	pack->bundle->abort_cause =
	    apply_relocs(pack, ksplice_init_relocs, ksplice_init_relocs_end);
	if (pack->bundle->abort_cause == OK)
		bootstrapped = 1;
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
	cleanup_ksplice_bundle(ksplice_pack.bundle);
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
