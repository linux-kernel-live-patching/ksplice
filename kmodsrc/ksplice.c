/*  Copyright (C) 2008  Jeffrey Brian Arnold <jbarnold@mit.edu>
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
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
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
#include <linux/version.h>
#include <linux/vmalloc.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#include <linux/uaccess.h>
#else /* LINUX_VERSION_CODE < */
/* linux/uaccess.h doesn't exist in kernels before 2.6.18 */
#include <asm/uaccess.h>
#endif /* LINUX_VERSION_CODE */
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
#include <asm/alternative.h>
#endif /* KSPLICE_NEED_PARAINSTRUCTIONS */
#ifdef KSPLICE_STANDALONE
#include "ksplice.h"
#else /* !KSPLICE_STANDALONE */
#include <linux/ksplice.h>
#endif /* KSPLICE_STANDALONE */

#if BITS_PER_LONG == 32
#define ADDR "08lx"
#elif BITS_PER_LONG == 64
#define ADDR "016lx"
#endif /* BITS_PER_LONG */

enum ksplice_stage_enum {
	PREPARING, APPLIED, REVERSED
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
#define UNEXPECTED ((__force abort_t) 9)

struct update_bundle {
	const char *kid;
	const char *name;
	struct kobject kobj;
	enum ksplice_stage_enum stage;
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

struct ksplice_frame {
	unsigned long addr;
	int has_conflict;
	const char *symbol_name;
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
	const char *name;
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

static struct reloc_nameval *find_nameval(struct module_pack *pack,
					  const char *name, int create);
static struct reloc_addrmap *find_addrmap(struct module_pack *pack,
					  unsigned long addr);
static abort_t handle_myst_reloc(struct module_pack *pack,
				 unsigned long pre_addr, unsigned long run_addr,
				 int rerun, int *matched);

struct safety_record {
	struct list_head list;
	const char *name;
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

#ifdef KSPLICE_STANDALONE
#include "ksplice-run-pre.h"
#else /* !KSPLICE_STANDALONE */
#include <asm/ksplice-run-pre.h>
#endif /* KSPLICE_STANDALONE */

static LIST_HEAD(update_bundles);

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

#ifndef task_thread_info
#define task_thread_info(task) (task)->thread_info
#endif /* !task_thread_info */

#ifdef CONFIG_X86
#ifdef __ASM_X86_PROCESSOR_H	/* New unified x86 */
#define KSPLICE_IP(x) ((x)->thread.ip)
#define KSPLICE_SP(x) ((x)->thread.sp)
#elif defined(CONFIG_X86_64)	/* Old x86 64-bit */
/* The IP is on the stack, so we don't need to check it separately.
 * Instead, we need to prevent Ksplice from patching thread_return.
 */
extern const char thread_return[];
#define KSPLICE_IP(x) ((unsigned long)thread_return)
#define KSPLICE_SP(x) ((x)->thread.rsp)
#else /* Old x86 32-bit */
#define KSPLICE_IP(x) ((x)->thread.eip)
#define KSPLICE_SP(x) ((x)->thread.esp)
#endif /* __ASM_X86_PROCESSOR_H */
#endif /* CONFIG_X86 */

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
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

static abort_t process_ksplice_relocs(struct module_pack *pack,
				      const struct ksplice_reloc *relocs,
				      const struct ksplice_reloc *relocs_end,
				      int pre);
static abort_t process_reloc(struct module_pack *pack,
			     const struct ksplice_reloc *r, int pre);
static abort_t compute_address(struct module_pack *pack, const char *sym_name,
			       struct list_head *vals, int pre);

struct accumulate_struct {
	const char *desired_name;
	struct list_head *vals;
};

#ifdef CONFIG_KALLSYMS
static int accumulate_matching_names(void *data, const char *sym_name,
				     unsigned long sym_val);
static abort_t kernel_lookup(const char *name, struct list_head *vals);
static abort_t other_module_lookup(const char *name, struct list_head *vals,
				   const char *ksplice_name);
#ifdef KSPLICE_STANDALONE
static int module_on_each_symbol(const struct module *mod,
				 int (*fn)(void *, const char *, unsigned long),
				 void *data);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
static unsigned long ksplice_kallsyms_expand_symbol(unsigned long off,
						    char *result);
#endif /* LINUX_VERSION_CODE */
#endif /* KSPLICE_STANDALONE */
#endif /* CONFIG_KALLSYMS */
static int label_offset(const char *sym_name);
static char *dup_wolabel(const char *sym_name);
static abort_t exported_symbol_lookup(const char *name, struct list_head *vals);

#ifdef KSPLICE_STANDALONE
static abort_t brute_search_all(struct module_pack *pack,
				const struct ksplice_size *s);
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
static abort_t resolve_patch_symbols(struct module_pack *pack);
static abort_t process_exports(struct module_pack *pack);
static int __apply_patches(void *bundle);
static int __reverse_patches(void *bundle);
static abort_t check_each_task(struct update_bundle *bundle);
static abort_t check_task(struct update_bundle *bundle,
			  const struct task_struct *t, int save_conflicts);
static abort_t check_stack(struct update_bundle *bundle, struct conflict *conf,
			   const struct thread_info *tinfo,
			   const unsigned long *stack);
static abort_t check_address_for_conflict(struct update_bundle *bundle,
					  struct conflict *conf,
					  unsigned long addr);
static int valid_stack_ptr(const struct thread_info *tinfo, const void *p);
static int is_stop_machine(const struct task_struct *t);
static void cleanup_conflicts(struct update_bundle *bundle);
static void print_conflicts(struct update_bundle *bundle);
#ifdef KSPLICE_STANDALONE
static const struct kernel_symbol *__find_symbol(const char *name,
						 struct module **owner,
						 const unsigned long **crc,
						 const char **export_type,
						 _Bool gplok, _Bool warn);
#endif /* KSPLICE_STANDALONE */

static abort_t add_dependency_on_address(struct module_pack *pack,
					 unsigned long addr);
static abort_t add_patch_dependencies(struct module_pack *pack);
#ifdef KSPLICE_STANDALONE
static int use_module(struct module *a, struct module *b);
#endif /* KSPLICE_STANDALONE */

/* helper */
static abort_t activate_helper(struct module_pack *pack);
static abort_t search_for_match(struct module_pack *pack,
				const struct ksplice_size *s);
static abort_t try_addr(struct module_pack *pack, const struct ksplice_size *s,
			unsigned long run_addr, unsigned long pre_addr);

static abort_t reverse_patches(struct update_bundle *bundle);
static abort_t apply_patches(struct update_bundle *bundle);
static abort_t apply_update(struct update_bundle *bundle);
static int register_ksplice_module(struct module_pack *pack);
static void unregister_ksplice_module(struct module_pack *pack);
static struct update_bundle *init_ksplice_bundle(const char *kid);
static void cleanup_ksplice_bundle(struct update_bundle *bundle);
static void add_to_bundle(struct module_pack *pack,
			  struct update_bundle *bundle);
static int ksplice_sysfs_init(struct update_bundle *bundle);

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
	case PREPARING:
		return snprintf(buf, PAGE_SIZE, "preparing\n");
	case APPLIED:
		return snprintf(buf, PAGE_SIZE, "applied\n");
	case REVERSED:
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
	case UNEXPECTED:
		return snprintf(buf, PAGE_SIZE, "unexpected\n");
	}
	return 0;
}

static ssize_t conflict_show(struct update_bundle *bundle, char *buf)
{
	const struct conflict *conf;
	const struct ksplice_frame *frame;
	int used = 0;
	list_for_each_entry(conf, &bundle->conflicts, list) {
		used += snprintf(buf + used, PAGE_SIZE - used, "%s %d",
				 conf->process_name, conf->pid);
		list_for_each_entry(frame, &conf->stack, list) {
			if (!frame->has_conflict)
				continue;
			used += snprintf(buf + used, PAGE_SIZE - used, " %s",
					 frame->symbol_name);
		}
		used += snprintf(buf + used, PAGE_SIZE - used, "\n");
	}
	return used;
}

static ssize_t stage_store(struct update_bundle *bundle,
			   const char *buf, size_t len)
{
	if (strncmp(buf, "applied\n", len) == 0 && bundle->stage == PREPARING)
		bundle->abort_cause = apply_update(bundle);
	else if (strncmp(buf, "reversed\n", len) == 0 &&
		 bundle->stage == APPLIED)
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
	char *tmp;
	int d = simple_strtoul(buf, &tmp, 10);
	if (*buf && (*tmp == '\0' || *tmp == '\n')) {
		bundle->debug = d;
		return len;
	}
	return -EINVAL;
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

void cleanup_ksplice_module(struct module_pack *pack)
{
	if (pack->bundle == NULL)
		return;
	if (pack->bundle->stage != APPLIED)
		unregister_ksplice_module(pack);
}
EXPORT_SYMBOL_GPL(cleanup_ksplice_module);

static abort_t activate_primary(struct module_pack *pack)
{
	const struct ksplice_patch *p;
	struct safety_record *rec;
	abort_t ret;
	ret = process_ksplice_relocs(pack, pack->primary_relocs,
				     pack->primary_relocs_end, 0);
	if (ret != OK)
		return ret;

	ret = resolve_patch_symbols(pack);
	if (ret != OK)
		return ret;

	ret = process_exports(pack);
	if (ret != OK)
		return ret;

	ret = add_patch_dependencies(pack);
	if (ret != OK)
		return ret;

	list_for_each_entry(rec, &pack->safety_records, list) {
		for (p = pack->patches; p < pack->patches_end; p++) {
			if (p->oldaddr == rec->addr)
				rec->care = 1;
		}
	}
	return OK;
}

static abort_t resolve_patch_symbols(struct module_pack *pack)
{
	struct ksplice_patch *p;
	abort_t ret;
	LIST_HEAD(vals);

	for (p = pack->patches; p < pack->patches_end; p++) {
		ret = compute_address(pack, p->oldstr, &vals, 0);
		if (ret != OK)
			return ret;

		if (!singular(&vals)) {
			release_vals(&vals);
			failed_to_find(pack, p->oldstr);
			return FAILED_TO_FIND;
		}
		p->oldaddr =
		    list_entry(vals.next, struct candidate_val, list)->val;
		release_vals(&vals);
	}

	return OK;
}

static abort_t process_exports(struct module_pack *pack)
{
	struct ksplice_export *export;
	struct module *m;
	const struct kernel_symbol *sym;
	const char *export_type;

	for (export = pack->exports; export < pack->exports_end; export++) {
		sym = __find_symbol(export->name, &m, NULL, &export_type, 1, 0);
		if (sym == NULL) {
			ksdebug(pack, 0, "Could not find kernel_symbol struct"
				"for %s (%s)\n", export->name, export->type);
			return MISSING_EXPORT;
		}
		if (strcmp(export_type, export->type) != 0) {
			ksdebug(pack, 0, "Nonmatching export type for %s "
				"(%s/%s)\n", export->name, export->type,
				export_type);
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

static abort_t apply_patches(struct update_bundle *bundle)
{
	int i;
	abort_t ret;

	for (i = 0; i < 5; i++) {
		cleanup_conflicts(bundle);
		bust_spinlocks(1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
		ret = (__force abort_t)stop_machine(__apply_patches, bundle,
						    NULL);
#else /* LINUX_VERSION_CODE < */
/* 9b1a4d38373a5581a4e01032a3ccdd94cd93477b was after 2.6.26 */
		ret = (__force abort_t)stop_machine_run(__apply_patches, bundle,
							NR_CPUS);
#endif /* LINUX_VERSION_CODE */
		bust_spinlocks(0);
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
				rec->care = 1;
				rec->name = s->name;
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
		bust_spinlocks(1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
		ret = (__force abort_t)stop_machine(__reverse_patches, bundle,
						    NULL);
#else /* LINUX_VERSION_CODE < */
/* 9b1a4d38373a5581a4e01032a3ccdd94cd93477b was after 2.6.26 */
		ret = (__force abort_t)stop_machine_run(__reverse_patches,
							bundle, NR_CPUS);
#endif /* LINUX_VERSION_CODE */
		bust_spinlocks(0);
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
	mm_segment_t old_fs;
	abort_t ret;

	if (bundle->stage == APPLIED)
		return (__force int)OK;

	if (bundle->stage != PREPARING)
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

	bundle->stage = APPLIED;

	list_for_each_entry(pack, &bundle->packs, list) {
		for (export = pack->exports; export < pack->exports_end;
		     export++)
			export->sym->name = export->new_name;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	list_for_each_entry(pack, &bundle->packs, list) {
		for (p = pack->patches; p < pack->patches_end; p++) {
			memcpy((void *)p->saved, (void *)p->oldaddr, 5);
			*((u8 *)p->oldaddr) = 0xE9;
			*((u32 *)(p->oldaddr + 1)) =
			    p->repladdr - (p->oldaddr + 5);
			flush_icache_range(p->oldaddr, p->oldaddr + 5);
		}
	}
	set_fs(old_fs);
	return (__force int)OK;
}

static int __reverse_patches(void *bundleptr)
{
	struct update_bundle *bundle = bundleptr;
	struct module_pack *pack;
	const struct ksplice_patch *p;
	struct ksplice_export *export;
	mm_segment_t old_fs;
	abort_t ret;

	if (bundle->stage != APPLIED)
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

	bundle->stage = REVERSED;

	list_for_each_entry(pack, &bundle->packs, list)
		module_put(pack->primary);

	list_for_each_entry(pack, &bundle->packs, list) {
		for (export = pack->exports; export < pack->exports_end;
		     export++)
			export->sym->name = export->saved_name;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	list_for_each_entry(pack, &bundle->packs, list) {
		for (p = pack->patches; p < pack->patches_end; p++) {
			memcpy((void *)p->oldaddr, (void *)p->saved, 5);
			flush_icache_range(p->oldaddr, p->oldaddr + 5);
		}
	}
	set_fs(old_fs);
	return (__force int)OK;
}

static abort_t check_each_task(struct update_bundle *bundle)
{
	const struct task_struct *g, *p;
	abort_t ret = OK;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
/* 5d4564e68210e4b1edb3f013bc3e59982bb35737 was after 2.6.10 */
	read_lock(&tasklist_lock);
#endif /* LINUX_VERSION_CODE */
	do_each_thread(g, p) {
		/* do_each_thread is a double loop! */
		if (check_task(bundle, p, 0) != OK)
			ret = check_task(bundle, p, 1);
	}
	while_each_thread(g, p);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
/* 5d4564e68210e4b1edb3f013bc3e59982bb35737 was after 2.6.10 */
	read_unlock(&tasklist_lock);
#endif /* LINUX_VERSION_CODE */
	return ret;
}

static abort_t check_task(struct update_bundle *bundle,
			  const struct task_struct *t, int save_conflicts)
{
	abort_t status, ret;
	struct conflict *conf = NULL;

	if (save_conflicts == 1) {
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

	status = check_address_for_conflict(bundle, conf, KSPLICE_IP(t));
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
		status = UNEXPECTED;
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
		if (__kernel_text_address(addr)) {
			ret = check_address_for_conflict(bundle, conf, addr);
			if (ret != OK)
				status = ret;
		}
	}
	return status;
}

static abort_t check_address_for_conflict(struct update_bundle *bundle,
					  struct conflict *conf,
					  unsigned long addr)
{
	const struct safety_record *rec;
	struct module_pack *pack;
	struct ksplice_frame *frame = NULL;

	if (conf != NULL) {
		frame = kmalloc(sizeof(*frame), GFP_ATOMIC);
		if (frame == NULL)
			return OUT_OF_MEMORY;
		frame->addr = addr;
		frame->has_conflict = 0;
		frame->symbol_name = NULL;
		list_add(&frame->list, &conf->stack);
	}
	list_for_each_entry(pack, &bundle->packs, list) {
		list_for_each_entry(rec, &pack->safety_records, list) {
			if (rec->care == 1 && addr >= rec->addr
			    && addr < rec->addr + rec->size) {
				if (frame != NULL) {
					frame->symbol_name = rec->name;
					frame->has_conflict = 1;
				}
				return CODE_BUSY;
			}
		}
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
		clear_list(&conf->stack, struct ksplice_frame, list);
		kfree(conf->process_name);
	}
	clear_list(&bundle->conflicts, struct conflict, list);
}

static void print_conflicts(struct update_bundle *bundle)
{
	const struct conflict *conf;
	const struct ksplice_frame *frame;
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

static int register_ksplice_module(struct module_pack *pack)
{
	struct update_bundle *bundle;
	struct module *m;
	int ret = 0;

	INIT_LIST_HEAD(&pack->reloc_addrmaps);
	INIT_LIST_HEAD(&pack->reloc_namevals);
	INIT_LIST_HEAD(&pack->safety_records);

	mutex_lock(&module_mutex);
	pack->target = NULL;
	if (pack->target_name != NULL) {
		list_for_each_entry(m, &modules, list) {
			if (strcmp(pack->target_name, m->name) == 0)
				pack->target = m;
		}
		if (pack->target == NULL || !module_is_live(pack->target)) {
			ret = -ENODEV;
			goto out;
		}
	}
	list_for_each_entry(bundle, &update_bundles, list) {
		if (strcmp(pack->kid, bundle->kid) == 0) {
			if (bundle->stage != PREPARING) {
				ret = -EPERM;
				goto out;
			}
			add_to_bundle(pack, bundle);
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
out:
	mutex_unlock(&module_mutex);
	return ret;
}

static void unregister_ksplice_module(struct module_pack *pack)
{
	if (pack->bundle == NULL)
		return;
	if (pack->bundle->stage != APPLIED) {
		mutex_lock(&module_mutex);
		list_del(&pack->list);
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
}

static void add_to_bundle(struct module_pack *pack,
			  struct update_bundle *bundle)
{
	pack->bundle = bundle;
	list_add(&pack->list, &bundle->packs);
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
	bundle->stage = PREPARING;
	bundle->abort_cause = OK;
	INIT_LIST_HEAD(&bundle->conflicts);
	return bundle;
}

static int ksplice_sysfs_init(struct update_bundle *bundle)
{
	int ret = 0;
	memset(&bundle->kobj, 0, sizeof(bundle->kobj));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
/* 6d06adfaf82d154023141ddc0c9de18b6a49090b was after 2.6.24 */
	ret = kobject_init_and_add(&bundle->kobj, &ksplice_ktype,
				   &THIS_MODULE->mkobj.kobj, "%s",
				   bundle->name);
#else /* LINUX_VERSION_CODE < */
	ret = kobject_set_name(&bundle->kobj, "%s", bundle->name);
	if (ret != 0)
		return ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
/* b86ab02803095190d6b72bcc18dcf620bf378df9 was after 2.6.10 */
	bundle->kobj.parent = &THIS_MODULE->mkobj.kobj;
#else /* LINUX_VERSION_CODE < */
	bundle->kobj.parent = &THIS_MODULE->mkobj->kobj;
#endif /* LINUX_VERSION_CODE */
	bundle->kobj.ktype = &ksplice_ktype;
	ret = kobject_register(&bundle->kobj);
#endif /* LINUX_VERSION_CODE */
	if (ret != 0)
		return ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
/* 312c004d36ce6c739512bac83b452f4c20ab1f62 was after 2.6.14 */
	kobject_uevent(&bundle->kobj, KOBJ_ADD);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
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
		ret = activate_helper(pack);
		if (ret != OK)
			goto out;

		ret = activate_primary(pack);
		if (ret != OK)
			goto out;
	}
	ret = apply_patches(bundle);
out:
	list_for_each_entry(pack, &bundle->packs, list) {
		clear_list(&pack->reloc_namevals, struct reloc_nameval, list);
		clear_list(&pack->reloc_addrmaps, struct reloc_addrmap, list);
		if (bundle->stage == PREPARING)
			clear_list(&pack->safety_records, struct safety_record,
				   list);
	}
	mutex_unlock(&module_mutex);
	return ret;
}

static abort_t activate_helper(struct module_pack *pack)
{
	const struct ksplice_size *s;
	int i;
	abort_t ret;
	int record_count = pack->helper_sizes_end - pack->helper_sizes;
	char *finished;
	int numfinished, oldfinished = 0;
	int restart_count = 0;

	ret = process_ksplice_relocs(pack, pack->helper_relocs,
				      pack->helper_relocs_end, 1);
	if (ret != OK)
		return ret;

	finished = kcalloc(record_count, sizeof(char), GFP_KERNEL);
	if (finished == NULL)
		return OUT_OF_MEMORY;

start:
	for (s = pack->helper_sizes; s < pack->helper_sizes_end; s++) {
		i = s - pack->helper_sizes;
		if (s->size == 0)
			finished[i] = 1;
		if (finished[i])
			continue;

		ret = search_for_match(pack, s);
		if (ret == OK) {
			finished[i] = 1;
		} else if (ret != NO_MATCH) {
			kfree(finished);
			return ret;
		}
	}

	numfinished = 0;
	for (i = 0; i < record_count; i++) {
		if (finished[i])
			numfinished++;
	}
	if (numfinished == record_count) {
		kfree(finished);
		return OK;
	}

	if (oldfinished == numfinished) {
		for (s = pack->helper_sizes; s < pack->helper_sizes_end; s++) {
			i = s - pack->helper_sizes;
			if (finished[i] == 0)
				ksdebug(pack, 2, KERN_DEBUG "ksplice: run-pre: "
					"could not match section %s\n",
					s->name);
		}
		print_abort(pack, "run-pre: could not match some sections");
		kfree(finished);
		return NO_MATCH;
	}
	oldfinished = numfinished;

	if (restart_count < 20) {
		restart_count++;
		goto start;
	}
	print_abort(pack, "run-pre: restart limit exceeded");
	kfree(finished);
	return NO_MATCH;
}

static abort_t search_for_match(struct module_pack *pack,
				const struct ksplice_size *s)
{
	int i;
	abort_t ret;
	unsigned long run_addr;
	LIST_HEAD(vals);
	struct candidate_val *v;

	for (i = 0; i < s->num_sym_addrs; i++) {
		ret = add_candidate_val(&vals, s->sym_addrs[i]);
		if (ret != OK)
			return ret;
	}

	ret = compute_address(pack, s->name, &vals, 1);
	if (ret != OK)
		return ret;

	ksdebug(pack, 3, KERN_DEBUG "ksplice_h: run-pre: starting sect search "
		"for %s\n", s->name);

	list_for_each_entry(v, &vals, list) {
		run_addr = v->val;

		yield();
		ret = try_addr(pack, s, run_addr, s->thismod_addr);
		if (ret != NO_MATCH) {
			release_vals(&vals);
			return ret;
		}
	}
	release_vals(&vals);

#ifdef KSPLICE_STANDALONE
	ret = brute_search_all(pack, s);
	if (ret != NO_MATCH)
		return ret;
#endif /* KSPLICE_STANDALONE */

	return NO_MATCH;
}

static abort_t try_addr(struct module_pack *pack, const struct ksplice_size *s,
			unsigned long run_addr, unsigned long pre_addr)
{
	struct safety_record *rec;
	struct reloc_nameval *nv;
	abort_t ret;

	const struct module *run_module = module_text_address(run_addr);
	if (run_module != pack->target) {
		ksdebug(pack, 1, KERN_DEBUG "ksplice_h: run-pre: ignoring "
			"address %" ADDR " in other module %s for sect %s\n",
			run_addr,
			run_module == NULL ? "vmlinux" : run_module->name,
			s->name);
		return NO_MATCH;
	}

	ret = run_pre_cmp(pack, run_addr, pre_addr, s->size, 0);
	if (ret == NO_MATCH) {
		set_temp_myst_relocs(pack, NOVAL);
		ksdebug(pack, 1, KERN_DEBUG "ksplice_h: run-pre: sect %s does "
			"not match ", s->name);
		ksdebug(pack, 1, "(r_a=%" ADDR " p_a=%" ADDR " s=%ld)\n",
			run_addr, pre_addr, s->size);
		ksdebug(pack, 1, KERN_DEBUG "ksplice_h: run-pre: ");
		if (pack->bundle->debug >= 1) {
			run_pre_cmp(pack, run_addr, pre_addr, s->size, 1);
			set_temp_myst_relocs(pack, NOVAL);
		}
		ksdebug(pack, 1, "\n");
		return ret;
	} else if (ret != OK) {
		return ret;
	}

	set_temp_myst_relocs(pack, VAL);
	ksdebug(pack, 3, KERN_DEBUG "ksplice_h: run-pre: found sect %s=%" ADDR
		"\n", s->name, run_addr);

	rec = kmalloc(sizeof(*rec), GFP_KERNEL);
	if (rec == NULL)
		return OUT_OF_MEMORY;
	/* It is safe for addr to point to the beginning of a patched function,
	   because that location will be overwritten with a trampoline. */
	if ((s->flags & KSPLICE_SIZE_DELETED) == 0) {
		rec->addr = run_addr + 1;
		rec->size = s->size - 1;
		rec->care = 0;	/* May be changed later by ksplice_patches */
	} else {
		rec->addr = run_addr;
		rec->size = s->size;
		rec->care = 1;
	}
	rec->name = s->name;
	list_add(&rec->list, &pack->safety_records);

	nv = find_nameval(pack, s->name, 1);
	if (nv == NULL)
		return OUT_OF_MEMORY;
	nv->val = run_addr;
	nv->status = VAL;

	return OK;
}

static abort_t handle_myst_reloc(struct module_pack *pack,
				 unsigned long pre_addr, unsigned long run_addr,
				 int rerun, int *matched)
{
	unsigned long run_reloc_addr;
	long run_reloc_val, expected;
	int offset;

	struct reloc_addrmap *map = find_addrmap(pack, pre_addr);
	if (map == NULL) {
		*matched = 0;
		return OK;
	}
	offset = (int)(pre_addr - map->addr);
	run_reloc_addr = run_addr - offset;
	switch (map->size) {
	case 1:
		run_reloc_val =
		    *(int8_t *)run_reloc_addr & (int8_t)map->dst_mask;
		break;
	case 2:
		run_reloc_val =
		    *(int16_t *)run_reloc_addr & (int16_t)map->dst_mask;
		break;
	case 4:
		run_reloc_val =
		    *(int32_t *)run_reloc_addr & (int32_t)map->dst_mask;
		break;
	case 8:
		run_reloc_val = *(int64_t *)run_reloc_addr & map->dst_mask;
		break;
	default:
		print_abort(pack, "Invalid relocation size");
		return UNEXPECTED;
	}

	if (!rerun) {
		ksdebug(pack, 3, KERN_DEBUG "ksplice_h: run-pre: reloc at r_a=%"
			ADDR " p_a=%" ADDR ": ", run_addr, pre_addr);
		ksdebug(pack, 3, "%s=%" ADDR " (A=%" ADDR " *r=%" ADDR ")\n",
			map->nameval->name, map->nameval->val, map->addend,
			run_reloc_val);
	}

	if (!starts_with(map->nameval->name, ".rodata.str")) {
		if (contains_canary(pack, run_reloc_addr, map->size,
				    map->dst_mask) != 0)
			return UNEXPECTED;

		expected = run_reloc_val - map->addend;
		if (map->pcrel)
			expected += run_reloc_addr;
		if (map->nameval->status == NOVAL) {
			map->nameval->val = expected;
			map->nameval->status = TEMP;
		} else if (map->nameval->val != expected) {
			if (rerun)
				return NO_MATCH;
			ksdebug(pack, 0, KERN_DEBUG "ksplice_h: run-pre reloc: "
				"Nameval address %" ADDR " does not match "
				"expected %" ADDR " for %s!\n",
				map->nameval->val, expected,
				map->nameval->name);
			return NO_MATCH;
		}
	}
	*matched = map->size - offset;
	return OK;
}

static abort_t process_ksplice_relocs(struct module_pack *pack,
				      const struct ksplice_reloc *relocs,
				      const struct ksplice_reloc *relocs_end,
				      int pre)
{
	const struct ksplice_reloc *r;
	for (r = relocs; r < relocs_end; r++) {
		abort_t ret = process_reloc(pack, r, pre);
		if (ret != OK)
			return ret;
	}
	return OK;
}

static abort_t process_reloc(struct module_pack *pack,
			     const struct ksplice_reloc *r, int pre)
{
	int i, ret;
	abort_t ret1;
	long off;
	unsigned long sym_addr;
	struct reloc_addrmap *map;
	LIST_HEAD(vals);

#ifdef KSPLICE_STANDALONE
	/* run_pre_reloc: will this reloc be used for run-pre matching? */
	const int run_pre_reloc = pre && bootstrapped;
#endif /* KSPLICE_STANDALONE */

#ifndef CONFIG_KALLSYMS
#ifdef KSPLICE_STANDALONE
	if (bootstrapped)
		goto skip_using_system_map;
#else /* !KSPLICE_STANDALONE */
	goto skip_using_system_map;
#endif /* KSPLICE_STANDALONE */
#endif /* !CONFIG_KALLSYMS */

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
	for (i = 0; i < r->num_sym_addrs; i++) {
		ret1 = add_candidate_val(&vals, r->sym_addrs[i] + off);
		if (ret1 != OK)
			return ret1;
	}
#ifndef CONFIG_KALLSYMS
skip_using_system_map:
#endif /* !CONFIG_KALLSYMS */

	ret = contains_canary(pack, r->blank_addr, r->size, r->dst_mask);
	if (ret < 0) {
		release_vals(&vals);
		return UNEXPECTED;
	}
	if (ret == 0) {
		ksdebug(pack, 4, KERN_DEBUG "ksplice%s: reloc: skipped %s:%"
			ADDR " (altinstr)\n", (pre ? "_h" : ""), r->sym_name,
			r->blank_offset);
		release_vals(&vals);
		return OK;
	}

	ret1 = compute_address(pack, r->sym_name, &vals, pre);
	if (ret1 != OK)
		return ret1;
	if (!singular(&vals)) {
		release_vals(&vals);
#ifdef KSPLICE_STANDALONE
		if (!run_pre_reloc) {
#else /* !KSPLICE_STANDALONE */
		if (!pre) {
#endif /* KSPLICE_STANDALONE */
			failed_to_find(pack, r->sym_name);
			return FAILED_TO_FIND;
		}

		ksdebug(pack, 4, KERN_DEBUG "ksplice: reloc: deferred %s:%" ADDR
			" to run-pre\n", r->sym_name, r->blank_offset);

		map = kmalloc(sizeof(*map), GFP_KERNEL);
		if (map == NULL)
			return OUT_OF_MEMORY;
		map->addr = r->blank_addr;
		map->nameval = find_nameval(pack, r->sym_name, 1);
		if (map->nameval == NULL) {
			kfree(map);
			return OUT_OF_MEMORY;
		}
		map->pcrel = r->pcrel;
		map->addend = r->addend;
		map->size = r->size;
		map->dst_mask = r->dst_mask;
		list_add(&map->list, &pack->reloc_addrmaps);
		return OK;
	}
	sym_addr = list_entry(vals.next, struct candidate_val, list)->val;
	release_vals(&vals);

	if (!pre) {
		ret1 = add_dependency_on_address(pack, sym_addr);
		if (ret1 != OK)
			return ret1;
	}

#ifdef KSPLICE_STANDALONE
	if (r->pcrel && run_pre_reloc) {
#else /* !KSPLICE_STANDALONE */
	if (r->pcrel && pre) {
#endif /* KSPLICE_STANDALONE */
		map = kmalloc(sizeof(*map), GFP_KERNEL);
		if (map == NULL)
			return OUT_OF_MEMORY;
		map->addr = r->blank_addr;
		map->nameval = find_nameval(pack, "ksplice_zero", 1);
		if (map->nameval == NULL) {
			kfree(map);
			return OUT_OF_MEMORY;
		}
		map->nameval->val = 0;
		map->nameval->status = VAL;
		map->pcrel = r->pcrel;
		map->addend = sym_addr + r->addend;
		map->size = r->size;
		map->dst_mask = r->dst_mask;
		list_add(&map->list, &pack->reloc_addrmaps);

	} else {
		unsigned long val;
		if (r->pcrel)
			val = sym_addr + r->addend - r->blank_addr;
		else
			val = sym_addr + r->addend;

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
	}

	ksdebug(pack, 4, KERN_DEBUG "ksplice%s: reloc: %s:%" ADDR " ",
		(pre ? "_h" : ""), r->sym_name, r->blank_offset);
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
	return OK;
}

static abort_t add_dependency_on_address(struct module_pack *pack,
					 unsigned long addr)
{
	struct module *m = module_text_address(follow_trampolines(pack, addr));
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

#ifdef KSPLICE_STANDALONE
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
#endif /* KSPLICE_STANDALONE */

static abort_t compute_address(struct module_pack *pack, const char *sym_name,
			       struct list_head *vals, int pre)
{
	int i;
	abort_t ret;
	const char *prefix[] = { ".text.", ".bss.", ".data.", NULL };
	char *name;
#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return OK;
#endif /* KSPLICE_STANDALONE */

	if (!pre) {
		struct reloc_nameval *nv = find_nameval(pack, sym_name, 0);
		if (nv != NULL && nv->status != NOVAL) {
			release_vals(vals);
			ret = add_candidate_val(vals, nv->val);
			if (ret != OK)
				return ret;
			ksdebug(pack, 1, KERN_DEBUG "ksplice: using detected "
				"sym %s=%" ADDR "\n", sym_name, nv->val);
			return OK;
		}
	}

	if (starts_with(sym_name, ".rodata"))
		return OK;

	name = dup_wolabel(sym_name);
	ret = exported_symbol_lookup(name, vals);
#ifdef CONFIG_KALLSYMS
	if (ret == OK)
		ret = kernel_lookup(name, vals);
	if (ret == OK)
		ret = other_module_lookup(name, vals, pack->name);
#endif /* CONFIG_KALLSYMS */
	kfree(name);
	if (ret != OK)
		return ret;

	for (i = 0; prefix[i] != NULL; i++) {
		if (starts_with(sym_name, prefix[i])) {
			ret = compute_address(pack,
					      sym_name + strlen(prefix[i]),
					      vals, pre);
			if (ret != OK)
				return ret;
		}
	}
	return OK;
}

static abort_t exported_symbol_lookup(const char *name, struct list_head *vals)
{
	const struct kernel_symbol *sym;
	sym = __find_symbol(name, NULL, NULL, NULL, 1, 0);
	if (sym == NULL)
		return OK;
	return add_candidate_val(vals, sym->value);
}

#ifdef KSPLICE_STANDALONE
/* lookup symbol in given range of kernel_symbols */
static const struct kernel_symbol *lookup_symbol(const char *name,
						 const struct kernel_symbol *start,
						 const struct kernel_symbol *stop)
{
	const struct kernel_symbol *ks = start;
	for (; ks < stop; ks++)
		if (strcmp(ks->name, name) == 0)
			return ks;
	return NULL;
}

struct symsearch {
	const struct kernel_symbol *start, *stop;
	const unsigned long *crcs;
	const char *export_type;
};

#ifndef CONFIG_MODVERSIONS
#define symversion(base, idx) NULL
#else
#define symversion(base, idx) ((base != NULL) ? ((base) + (idx)) : NULL)
#endif

/* Modified version of search_symarrays from kernel/module.c */
static const struct kernel_symbol *search_symarrays(const struct symsearch *arr,
						    unsigned int num,
						    const char *name,
						    const char **export_type,
						    _Bool gplok,
						    _Bool warn,
						    const unsigned long **crc)
{
	unsigned int i;
	const struct kernel_symbol *ks;

	for (i = 0; i < num; i++) {
		ks = lookup_symbol(name, arr[i].start, arr[i].stop);
		if (!ks)
			continue;

		if (crc)
			*crc = symversion(arr[i].crcs, ks - arr[i].start);
		if (export_type)
			*export_type = arr[i].export_type;
		return ks;
	}
	return NULL;
}

/* Modified version of kernel/module.c's find_symbol */
static const struct kernel_symbol *__find_symbol(const char *name,
						 struct module **owner,
						 const unsigned long **crc,
						 const char **export_type,
						 _Bool gplok, _Bool warn)
{
	struct module *mod;
	const struct kernel_symbol *ks;

	const struct symsearch arr[] = {
		{ __start___ksymtab, __stop___ksymtab, __start___kcrctab, "" },
		{ __start___ksymtab_gpl, __stop___ksymtab_gpl,
		  __start___kcrctab_gpl, "_gpl" },
#ifdef KSPLICE_KSYMTAB_FUTURE_SUPPORT
		{ __start___ksymtab_gpl_future, __stop___ksymtab_gpl_future,
		  __start___kcrctab_gpl_future, "_gpl_future" },
#endif /* KSPLICE_KSYMTAB_FUTURE_SUPPORT */
#ifdef KSPLICE_KSYMTAB_UNUSED_SUPPORT
		{ __start___ksymtab_unused, __stop___ksymtab_unused,
		  __start___kcrctab_unused, "_unused" },
		{ __start___ksymtab_unused_gpl, __stop___ksymtab_unused_gpl,
		  __start___kcrctab_unused_gpl, "_unused_gpl" },
#endif /* KSPLICE_KSYMTAB_UNUSED_SUPPORT */
	};

	/* Core kernel first. */
	ks = search_symarrays(arr, ARRAY_SIZE(arr), name, export_type, gplok,
			      warn, crc);
	if (ks) {
		if (owner)
			*owner = NULL;
		return ks;
	}

	/* Now try modules. */
	list_for_each_entry(mod, &modules, list) {
		struct symsearch arr[] = {
			{ mod->syms, mod->syms + mod->num_syms, mod->crcs, "" },
			{ mod->gpl_syms, mod->gpl_syms + mod->num_gpl_syms,
			  mod->gpl_crcs, "_gpl" },
#ifdef KSPLICE_KSYMTAB_FUTURE_SUPPORT
			{ mod->gpl_future_syms,
			  mod->gpl_future_syms + mod->num_gpl_future_syms,
			  mod->gpl_future_crcs, "_gpl_future" },
#endif /* KSPLICE_KSYMTAB_FUTURE_SUPPORT */
#ifdef KSPLICE_KSYMTAB_UNUSED_SUPPORT
			{ mod->unused_syms,
			  mod->unused_syms + mod->num_unused_syms,
			  mod->unused_crcs, "_unused" },
			{ mod->unused_gpl_syms,
			  mod->unused_gpl_syms + mod->num_unused_gpl_syms,
			  mod->unused_gpl_crcs, "_unused_gpl" },
#endif /* KSPLICE_KSYMTAB_UNUSED_SUPPORT */
		};

		ks = search_symarrays(arr, ARRAY_SIZE(arr),
				      name, export_type, gplok, warn, crc);
		if (ks) {
			if (owner)
				*owner = mod;
			return ks;
		}
	}

	return NULL;
}
#endif /* KSPLICE_STANDALONE */

#ifdef CONFIG_KALLSYMS
static abort_t other_module_lookup(const char *name, struct list_head *vals,
				   const char *ksplice_name)
{
	abort_t ret = OK;
	struct accumulate_struct acc = { name, vals };
	const struct module *m;

	list_for_each_entry(m, &modules, list) {
		if (starts_with(m->name, ksplice_name) ||
		    ends_with(m->name, "_helper"))
			continue;
		ret = (__force abort_t)
		    module_on_each_symbol(m, accumulate_matching_names, &acc);
		if (ret != OK)
			break;
	}

	return ret;
}

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
			    const void *start, unsigned long len)
{
	unsigned long addr;
	char run, pre;
	abort_t ret;

	for (addr = (unsigned long)start; addr < (unsigned long)start + len;
	     addr++) {
		if (addr % 100000 == 0)
			yield();

		if (!virtual_address_mapped(addr))
			return OK;

		run = *(const unsigned char *)(addr);
		pre = *(const unsigned char *)(s->thismod_addr);

		if (run != pre)
			continue;

		ret = try_addr(pack, s, addr, s->thismod_addr);
		if (ret != NO_MATCH)
			return ret;
	}

	return NO_MATCH;
}

static abort_t brute_search_all(struct module_pack *pack,
				const struct ksplice_size *s)
{
	struct module *m;
	abort_t ret = NO_MATCH;
	int saved_debug;
	const char *where = NULL;

	ksdebug(pack, 2, KERN_DEBUG "ksplice: brute_search: searching for %s\n",
		s->name);
	saved_debug = pack->bundle->debug;
	pack->bundle->debug = 0;

	list_for_each_entry(m, &modules, list) {
		if (starts_with(m->name, pack->name) ||
		    ends_with(m->name, "_helper"))
			continue;
		if (brute_search(pack, s, m->module_core, m->core_size) == OK ||
		    brute_search(pack, s, m->module_init, m->init_size) == OK) {
			ret = OK;
			where = m->name;
			break;
		}
	}

	if (ret == NO_MATCH) {
		if (brute_search(pack, s, (const void *)init_mm.start_code,
				 init_mm.end_code - init_mm.start_code) == OK) {
			ret = OK;
			where = "vmlinux";
		}
	}

	pack->bundle->debug = saved_debug;
	if (ret == OK)
		ksdebug(pack, 2, KERN_DEBUG "ksplice: brute_search: found %s "
			"in %s\n", s->name, where);

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

static int module_on_each_symbol(const struct module *mod,
				 int (*fn)(void *, const char *, unsigned long),
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
#endif /* CONFIG_KALLSYMS */
#else /* !KSPLICE_STANDALONE */

static abort_t kernel_lookup(const char *name, struct list_head *vals)
{
	struct accumulate_struct acc = { name, vals };
	return (__force abort_t)
	    kallsyms_on_each_symbol(accumulate_matching_names, &acc);
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
					  const char *name, int create)
{
	struct reloc_nameval *nv, *new;
	const char *newname;
	if (starts_with(name, ".text."))
		name += 6;
	list_for_each_entry(nv, &pack->reloc_namevals, list) {
		newname = nv->name;
		if (starts_with(newname, ".text."))
			newname += 6;
		if (strcmp(newname, name) == 0)
			return nv;
	}
	if (!create)
		return NULL;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (new == NULL)
		return NULL;
	new->name = name;
	new->val = 0;
	new->status = NOVAL;
	list_add(&new->list, &pack->reloc_namevals);
	return new;
}

static struct reloc_addrmap *find_addrmap(struct module_pack *pack,
					  unsigned long addr)
{
	struct reloc_addrmap *map;
	list_for_each_entry(map, &pack->reloc_addrmaps, list) {
		if (addr >= map->addr && addr < map->addr + map->size)
			return map;
	}
	return NULL;
}

static void set_temp_myst_relocs(struct module_pack *pack, int status_val)
{
	struct reloc_nameval *nv;
	list_for_each_entry(nv, &pack->reloc_namevals, list) {
		if (nv->status == TEMP)
			nv->status = status_val;
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

static int label_offset(const char *sym_name)
{
	int i;
	for (i = 0;
	     sym_name[i] != 0 && sym_name[i + 1] != 0 && sym_name[i + 2] != 0
	     && sym_name[i + 3] != 0; i++) {
		if (sym_name[i] == '_' && sym_name[i + 1] == '_'
		    && sym_name[i + 2] == '_' && sym_name[i + 3] == '_')
			return i + 4;
	}
	return -1;
}

static char *dup_wolabel(const char *sym_name)
{
	int offset, entire_strlen, label_strlen, new_strlen;
	char *newstr;

	offset = label_offset(sym_name);
	if (offset == -1)
		label_strlen = 0;
	else
		label_strlen = strlen(&sym_name[offset]) + strlen("____");

	entire_strlen = strlen(sym_name);
	new_strlen = entire_strlen - label_strlen;
	newstr = kmalloc(new_strlen + 1, GFP_KERNEL);
	if (newstr == NULL)
		return NULL;
	memcpy(newstr, sym_name, new_strlen);
	newstr[new_strlen] = 0;
	return newstr;
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
		char *tmp = bundle->debug_blob.data;
		bundle->debug_blob.data = vmalloc(new_size);
		if (bundle->debug_blob.data != NULL) {
			memcpy(bundle->debug_blob.data, tmp,
			       bundle->debug_blob.size);
			vfree(tmp);
		} else {
			vfree(tmp);
			return -ENOMEM;
		}
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
	.reloc_addrmaps = LIST_HEAD_INIT(ksplice_pack.reloc_addrmaps),
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
	    process_ksplice_relocs(pack, ksplice_init_relocs,
				   ksplice_init_relocs_end, 1);
	if (pack->bundle->abort_cause == OK)
		bootstrapped = 1;
#endif /* KSPLICE_STANDALONE */
	return 0;
}

static void cleanup_ksplice(void)
{
#ifdef KSPLICE_STANDALONE
	cleanup_ksplice_bundle(ksplice_pack.bundle);
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
