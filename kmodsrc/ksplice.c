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
#endif
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kthread.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/stop_machine.h>
#include <linux/time.h>
#ifdef KSPLICE_STANDALONE
/* linux/uaccess.h doesn't exist in kernels before 2.6.18 */
#include <linux/version.h>
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
#include <asm/alternative.h>
#endif
#include <asm/uaccess.h>
#include "ksplice.h"
#include "ksplice-run-pre.h"
#else
#include <linux/uaccess.h>
#include <linux/ksplice.h>
#include <asm/ksplice-run-pre.h>
#endif

#ifdef KSPLICE_STANDALONE

/* Old kernels do not have kcalloc */
#define kcalloc ksplice_kcalloc
static inline void *ksplice_kcalloc(size_t n, size_t size,
				    typeof(GFP_KERNEL) flags)
{
	char *mem;
	if (n != 0 && size > ULONG_MAX / n)
		return NULL;
	mem = kmalloc(n * size, flags);
	if (mem)
		memset(mem, 0, n * size);
	return mem;
}

/* Old kernels use semaphore instead of mutex
   97d1f15b7ef52c1e9c28dc48b454024bb53a5fd2 was after 2.6.16 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#define mutex semaphore
#define mutex_lock down
#define mutex_unlock up
#endif

#ifndef task_thread_info
#define task_thread_info(task) (task)->thread_info
#endif /* task_thread_info */

#ifdef CONFIG_X86
#ifdef __ASM_X86_PROCESSOR_H	/* New unified x86 */
#define KSPLICE_IP(x) ((x)->thread.ip)
#define KSPLICE_SP(x) ((x)->thread.sp)
#elif defined CONFIG_X86_64	/* Old x86 64-bit */
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

#else /* KSPLICE_STANDALONE */
#define KSPLICE_IP(x) ((x)->thread.ip)
#define KSPLICE_SP(x) ((x)->thread.sp)
#endif /* KSPLICE_STANDALONE */

static int process_ksplice_relocs(struct module_pack *pack,
				  const struct ksplice_reloc *relocs,
				  const struct ksplice_reloc *relocs_end,
				  int pre);
static int process_reloc(struct module_pack *pack,
			 const struct ksplice_reloc *r, int pre);
static int compute_address(struct module_pack *pack, char *sym_name,
			   struct list_head *vals, int pre);

struct accumulate_struct {
	const char *desired_name;
	struct list_head *vals;
};

#ifdef CONFIG_KALLSYMS
static int label_offset(const char *sym_name);
static const char *dup_wolabel(const char *sym_name);
static int accumulate_matching_names(void *data, const char *sym_name,
				     unsigned long sym_val);
#ifdef KSPLICE_STANDALONE
static int module_on_each_symbol(struct module *mod,
				 int (*fn) (void *, const char *,
					    unsigned long), void *data);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
static unsigned long ksplice_kallsyms_expand_symbol(unsigned long off,
						    char *result);
#endif
#endif
static int kernel_lookup(const char *name, struct list_head *vals);
static int other_module_lookup(const char *name, struct list_head *vals,
			       const char *ksplice_name);
#endif

#ifdef KSPLICE_STANDALONE
static int brute_search_all(struct module_pack *pack,
			    const struct ksplice_size *s);

#endif

static int add_candidate_val(struct list_head *vals, unsigned long val);
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

int init_module(void);
void cleanup_module(void);

/* primary */
static int activate_primary(struct module_pack *pack);
static int resolve_patch_symbols(struct module_pack *pack);
static int procfile_read(char *buffer, char **buffer_location, off_t offset,
			 int buffer_length, int *eof, void *data);
static int procfile_write(struct file *file, const char *buffer,
			  unsigned long count, void *data);
static int __apply_patches(void *packptr);
static int __reverse_patches(void *packptr);
static int check_each_task(struct module_pack *pack);
static int check_task(struct module_pack *pack, struct task_struct *t);
static int check_stack(struct module_pack *pack, struct thread_info *tinfo,
		       unsigned long *stack);
static int check_address_for_conflict(struct module_pack *pack,
				      unsigned long addr);
static int valid_stack_ptr(struct thread_info *tinfo, void *p);

#ifdef CONFIG_MODULE_UNLOAD
static int add_dependency_on_address(struct module_pack *pack,
				     unsigned long addr);
static int add_patch_dependencies(struct module_pack *pack);
#ifdef KSPLICE_STANDALONE
static int use_module(struct module *a, struct module *b);
#endif
#endif

/* helper */
static int activate_helper(struct module_pack *pack);
static int search_for_match(struct module_pack *pack,
			    const struct ksplice_size *s);
static int try_addr(struct module_pack *pack, const struct ksplice_size *s,
		    unsigned long run_addr, unsigned long pre_addr);

extern struct proc_dir_entry proc_root;

void cleanup_ksplice_module(struct module_pack *pack)
{
	remove_proc_entry(pack->name, &proc_root);
	clear_debug_buf(pack);
}

static int activate_primary(struct module_pack *pack)
{
	int i, ret;
	struct proc_dir_entry *proc_entry;

	if (process_ksplice_relocs(pack, pack->primary_relocs,
				   pack->primary_relocs_end, 0) != 0)
		return -1;

	if (resolve_patch_symbols(pack) != 0)
		return -1;

#ifdef CONFIG_MODULE_UNLOAD
	if (add_patch_dependencies(pack) != 0)
		return -1;
#endif

	proc_entry = create_proc_entry(pack->name, 0644, NULL);
	if (proc_entry == NULL) {
		print_abort(pack, "primary module: could not create proc "
			    "entry");
		return -1;
	}

	proc_entry->read_proc = procfile_read;
	proc_entry->write_proc = procfile_write;
	proc_entry->data = pack;
	proc_entry->owner = pack->primary;
	proc_entry->mode = S_IFREG | S_IRUSR | S_IWUSR;
	proc_entry->uid = 0;
	proc_entry->gid = 0;
	proc_entry->size = 0;

	for (i = 0; i < 5; i++) {
		bust_spinlocks(1);
		ret = stop_machine_run(__apply_patches, pack, NR_CPUS);
		bust_spinlocks(0);
		if (ret != -EAGAIN)
			break;
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
	}
	if (pack->state != KSPLICE_APPLIED) {
		remove_proc_entry(pack->name, &proc_root);
		if (ret == -EAGAIN)
			print_abort(pack, "stack check: to-be-replaced code is "
				    "busy");
		return -1;
	}

	ksdebug(pack, 0, KERN_INFO "ksplice: Update %s applied successfully\n",
		pack->name);
	return 0;
}

static int resolve_patch_symbols(struct module_pack *pack)
{
	struct ksplice_patch *p;
	int ret;
	LIST_HEAD(vals);

	for (p = pack->patches; p < pack->patches_end; p++) {
		ret = compute_address(pack, p->oldstr, &vals, 0);
		if (ret < 0)
			return ret;

		if (!singular(&vals)) {
			release_vals(&vals);
			failed_to_find(pack, p->oldstr);
			return -1;
		}
		p->oldaddr =
		    list_entry(vals.next, struct candidate_val, list)->val;
		release_vals(&vals);
	}

	return 0;
}

static int procfile_read(char *buffer, char **buffer_location,
			 off_t offset, int buffer_length, int *eof, void *data)
{
	return 0;
}

static int procfile_write(struct file *file, const char *buffer,
			  unsigned long count, void *data)
{
	int i, ret;
	struct module_pack *pack = data;
	ksdebug(pack, 0, KERN_INFO "ksplice: Preparing to reverse %s\n",
		pack->name);

	if (pack->state != KSPLICE_APPLIED)
		return count;

	for (i = 0; i < 5; i++) {
		bust_spinlocks(1);
		ret = stop_machine_run(__reverse_patches, pack, NR_CPUS);
		bust_spinlocks(0);
		if (ret != -EAGAIN)
			break;
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
	}
	if (ret == -EAGAIN)
		print_abort(pack, "stack check: to-be-reversed code is busy");
	else if (ret == 0)
		ksdebug(pack, 0, KERN_INFO "ksplice: Update %s reversed "
			"successfully\n", pack->name);
	else if (ret == -EBUSY)
		ksdebug(pack, 0, KERN_ERR "ksplice: Update module %s is in use "
			"by another module\n", pack->name);

	return count;
}

static int __apply_patches(void *packptr)
{
	struct module_pack *pack = packptr;
	const struct ksplice_patch *p;
	struct safety_record *rec;
	mm_segment_t old_fs;

	list_for_each_entry(rec, pack->safety_records, list) {
		for (p = pack->patches; p < pack->patches_end; p++) {
			if (p->oldaddr == rec->addr)
				rec->care = 1;
		}
	}

	if (check_each_task(pack) < 0)
		return -EAGAIN;

	if (!try_module_get(pack->primary))
		return -ENODEV;

	pack->state = KSPLICE_APPLIED;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	for (p = pack->patches; p < pack->patches_end; p++) {
		memcpy((void *)p->saved, (void *)p->oldaddr, 5);
		*((u8 *) p->oldaddr) = 0xE9;
		*((u32 *) (p->oldaddr + 1)) = p->repladdr - (p->oldaddr + 5);
		flush_icache_range(p->oldaddr, p->oldaddr + 5);
	}
	set_fs(old_fs);
	return 0;
}

static int __reverse_patches(void *packptr)
{
	struct module_pack *pack = packptr;
	const struct ksplice_patch *p;
	mm_segment_t old_fs;

	if (pack->state != KSPLICE_APPLIED)
		return 0;

#ifdef CONFIG_MODULE_UNLOAD
	if (module_refcount(pack->primary) != 2)
		return -EBUSY;
#endif

	if (check_each_task(pack) < 0)
		return -EAGAIN;

	clear_list(pack->safety_records, struct safety_record, list);
	pack->state = KSPLICE_REVERSED;
	module_put(pack->primary);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	for (p = pack->patches; p < pack->patches_end; p++) {
		memcpy((void *)p->oldaddr, (void *)p->saved, 5);
		flush_icache_range(p->oldaddr, p->oldaddr + 5);
	}
	set_fs(old_fs);
	return 0;
}

static int check_each_task(struct module_pack *pack)
{
	struct task_struct *g, *p;
	int status = 0;
	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
		/* do_each_thread is a double loop! */
		if (check_task(pack, p) < 0) {
			if (pack->debug == 1) {
				pack->debug = 2;
				check_task(pack, p);
				pack->debug = 1;
			}
			status = -EAGAIN;
		}
	}
	while_each_thread(g, p);
	read_unlock(&tasklist_lock);
	return status;
}

static int check_task(struct module_pack *pack, struct task_struct *t)
{
	int status, ret;

	ksdebug(pack, 2, KERN_DEBUG "ksplice: stack check: pid %d (%s) eip "
		"%" ADDR " ", t->pid, t->comm, KSPLICE_IP(t));
	status = check_address_for_conflict(pack, KSPLICE_IP(t));
	ksdebug(pack, 2, ": ");

	if (t == current) {
		ret = check_stack(pack, task_thread_info(t),
				  (unsigned long *)__builtin_frame_address(0));
		if (status == 0)
			status = ret;
	} else if (!task_curr(t)) {
		ret = check_stack(pack, task_thread_info(t),
				  (unsigned long *)KSPLICE_SP(t));
		if (status == 0)
			status = ret;
	} else if (strcmp(t->comm, "kstopmachine") != 0) {
		ksdebug(pack, 2, "unexpected running task!");
		status = -ENODEV;
	}
	ksdebug(pack, 2, "\n");
	return status;
}

/* Modified version of Linux's print_context_stack */
static int check_stack(struct module_pack *pack, struct thread_info *tinfo,
		       unsigned long *stack)
{
	int status = 0;
	unsigned long addr;

	while (valid_stack_ptr(tinfo, stack)) {
		addr = *stack++;
		if (__kernel_text_address(addr)) {
			ksdebug(pack, 2, "%" ADDR " ", addr);
			if (check_address_for_conflict(pack, addr) < 0)
				status = -EAGAIN;
		}
	}
	return status;
}

static int check_address_for_conflict(struct module_pack *pack,
				      unsigned long addr)
{
	const struct ksplice_size *s;
	struct safety_record *rec;

	/* It is safe for addr to point to the beginning of a patched
	   function, because that location will be overwritten with a
	   trampoline. */
	list_for_each_entry(rec, pack->safety_records, list) {
		if (rec->care == 1 && addr > rec->addr
		    && addr < rec->addr + rec->size) {
			ksdebug(pack, 2, "[<-- CONFLICT] ");
			return -EAGAIN;
		}
	}
	for (s = pack->primary_sizes; s < pack->primary_sizes_end; s++) {
		if (addr >= s->thismod_addr && addr < s->thismod_addr + s->size) {
			ksdebug(pack, 2, "[<-- CONFLICT] ");
			return -EAGAIN;
		}
	}
	return 0;
}

/* Modified version of Linux's valid_stack_ptr */
static int valid_stack_ptr(struct thread_info *tinfo, void *p)
{
	return p > (void *)tinfo
	    && p <= (void *)tinfo + THREAD_SIZE - sizeof(long);
}

int init_ksplice_module(struct module_pack *pack)
{
	int ret = 0;
	if (init_debug_buf(pack) < 0)
		return -1;

#ifdef KSPLICE_STANDALONE
	if (process_ksplice_relocs(pack, ksplice_init_relocs,
				   ksplice_init_relocs_end, 1) != 0)
		return -1;
	bootstrapped = 1;
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	if (pack->target == NULL) {
		apply_paravirt(pack->primary_parainstructions,
			       pack->primary_parainstructions_end);
		apply_paravirt(pack->helper_parainstructions,
			       pack->helper_parainstructions_end);
	}
#endif
#endif

	ksdebug(pack, 0, KERN_INFO "ksplice_h: Preparing and checking %s\n",
		pack->name);

	if (activate_helper(pack) != 0 || activate_primary(pack) != 0)
		ret = -1;

	clear_list(pack->reloc_namevals, struct reloc_nameval, list);
	clear_list(pack->reloc_addrmaps, struct reloc_addrmap, list);
	if (pack->state == KSPLICE_PREPARING)
		clear_list(pack->safety_records, struct safety_record, list);

	return ret;
}

static int activate_helper(struct module_pack *pack)
{
	const struct ksplice_size *s;
	int i, ret;
	int record_count = pack->helper_sizes_end - pack->helper_sizes;
	char *finished;
	int numfinished, oldfinished = 0;
	int restart_count = 0;

	if (process_ksplice_relocs(pack, pack->helper_relocs,
				   pack->helper_relocs_end, 1) != 0)
		return -1;

	finished = kcalloc(record_count, 1, GFP_KERNEL);
	if (finished == NULL) {
		printk(KERN_ERR "ksplice: out of memory\n");
		return -ENOMEM;
	}

start:
	for (s = pack->helper_sizes; s < pack->helper_sizes_end; s++) {
		i = s - pack->helper_sizes;
		if (s->size == 0)
			finished[i] = 1;
		if (finished[i])
			continue;

		ret = search_for_match(pack, s);
		if (ret < 0) {
			kfree(finished);
			return ret;
		} else if (ret > 0) {
			finished[i] = 1;
		}
	}

	numfinished = 0;
	for (i = 0; i < record_count; i++) {
		if (finished[i])
			numfinished++;
	}
	if (numfinished == record_count) {
		kfree(finished);
		return 0;
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
		return -1;
	}
	oldfinished = numfinished;

	if (restart_count < 20) {
		restart_count++;
		goto start;
	}
	print_abort(pack, "run-pre: restart limit exceeded");
	kfree(finished);
	return -1;
}

static int search_for_match(struct module_pack *pack,
			    const struct ksplice_size *s)
{
	int i, ret;
	unsigned long run_addr;
	LIST_HEAD(vals);
	struct candidate_val *v;

	for (i = 0; i < s->num_sym_addrs; i++) {
		ret = add_candidate_val(&vals, s->sym_addrs[i]);
		if (ret < 0)
			return ret;
	}

	ret = compute_address(pack, s->name, &vals, 1);
	if (ret < 0)
		return ret;

	ksdebug(pack, 3, KERN_DEBUG "ksplice_h: run-pre: starting sect search "
		"for %s\n", s->name);

	list_for_each_entry(v, &vals, list) {
		run_addr = v->val;

		yield();
		ret = try_addr(pack, s, run_addr, s->thismod_addr);
		if (ret != 0) {
			/* we've encountered a match (> 0) or an error (< 0) */
			release_vals(&vals);
			return ret;
		}
	}
	release_vals(&vals);

#ifdef KSPLICE_STANDALONE
	ret = brute_search_all(pack, s);
#endif
	return ret;
}

static int try_addr(struct module_pack *pack, const struct ksplice_size *s,
		    unsigned long run_addr, unsigned long pre_addr)
{
	struct safety_record *tmp;
	struct reloc_nameval *nv;

	if (run_pre_cmp(pack, run_addr, pre_addr, s->size, 0) != 0) {
		set_temp_myst_relocs(pack, NOVAL);
		ksdebug(pack, 1, KERN_DEBUG "ksplice_h: run-pre: sect %s does "
			"not match ", s->name);
		ksdebug(pack, 1, "(r_a=%" ADDR " p_a=%" ADDR " s=%ld)\n",
			run_addr, pre_addr, s->size);
		ksdebug(pack, 1, KERN_DEBUG "ksplice_h: run-pre: ");
		if (pack->debug >= 1) {
			run_pre_cmp(pack, run_addr, pre_addr, s->size, 1);
			set_temp_myst_relocs(pack, NOVAL);
		}
		ksdebug(pack, 1, "\n");
	} else {
		set_temp_myst_relocs(pack, VAL);

		ksdebug(pack, 3, KERN_DEBUG "ksplice_h: run-pre: found sect "
			"%s=%" ADDR "\n", s->name, run_addr);

		tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
		if (tmp == NULL) {
			printk(KERN_ERR "ksplice: out of memory\n");
			return -ENOMEM;
		}
		tmp->addr = run_addr;
		tmp->size = s->size;
		tmp->care = 0;
		list_add(&tmp->list, pack->safety_records);

		nv = find_nameval(pack, s->name, 1);
		if (nv == NULL)
			return -ENOMEM;
		nv->val = run_addr;
		nv->status = VAL;

		return 1;
	}
	return 0;
}

int handle_myst_reloc(struct module_pack *pack, unsigned long pre_addr,
		      unsigned long run_addr, struct reloc_addrmap *map,
		      int rerun)
{
	int offset = (int)(pre_addr - map->addr);
	long run_reloc_val, expected;
	unsigned long run_reloc_addr = run_addr - offset;
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
		return -1;
	}

	if (!rerun)
		ksdebug(pack, 3, "%s=%" ADDR " (A=%" ADDR " *r=%" ADDR ")\n",
			map->nameval->name, map->nameval->val, map->addend,
			run_reloc_val);

	if (!starts_with(map->nameval->name, ".rodata.str")) {
		int ret;
		ret = contains_canary(pack, run_reloc_addr, map->size,
				      map->dst_mask);
		if (ret < 0)
			return ret;
		if (ret == 1)
			return -1;

		expected = run_reloc_val - map->addend;
		if (map->pcrel)
			expected += run_reloc_addr;
		if (map->nameval->status == NOVAL) {
			map->nameval->val = expected;
			map->nameval->status = TEMP;
		} else if (map->nameval->val != expected) {
			if (rerun)
				return -1;
			ksdebug(pack, 0, KERN_DEBUG "ksplice_h: run-pre reloc: "
				"Expected %" ADDR " based on previous %s!\n",
				expected, map->nameval->name);
			return -1;
		}
	}
	return map->size - offset;
}

static int process_ksplice_relocs(struct module_pack *pack,
				  const struct ksplice_reloc *relocs,
				  const struct ksplice_reloc *relocs_end,
				  int pre)
{
	const struct ksplice_reloc *r;
	for (r = relocs; r < relocs_end; r++) {
		if (process_reloc(pack, r, pre) != 0)
			return -1;
	}
	return 0;
}

static int process_reloc(struct module_pack *pack,
			 const struct ksplice_reloc *r, int pre)
{
	int i, ret;
	long off;
	unsigned long sym_addr;
	struct reloc_addrmap *map;
	LIST_HEAD(vals);
#ifdef KSPLICE_STANDALONE
	/* run_pre_reloc: will this reloc be used for run-pre matching? */
	const int run_pre_reloc = pre && bootstrapped;
#ifndef CONFIG_KALLSYMS

	if (bootstrapped)
		goto skip_using_system_map;
#endif /* CONFIG_KALLSYMS */
#endif /* KSPLICE_STANDALONE */

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
		return -1;
	}
	for (i = 0; i < r->num_sym_addrs; i++) {
		ret = add_candidate_val(&vals, r->sym_addrs[i] + off);
		if (ret < 0)
			return ret;
	}
#ifndef CONFIG_KALLSYMS
skip_using_system_map:
#endif

	ret = contains_canary(pack, r->blank_addr, r->size, r->dst_mask);
	if (ret < 0) {
		release_vals(&vals);
		return ret;
	}
	if (ret == 0) {
		ksdebug(pack, 4, KERN_DEBUG "ksplice%s: reloc: skipped %s:%"
			ADDR " (altinstr)\n", (pre ? "_h" : ""), r->sym_name,
			r->blank_offset);
		release_vals(&vals);
		return 0;
	}

	ret = compute_address(pack, r->sym_name, &vals, pre);
	if (ret < 0)
		return ret;
	if (!singular(&vals)) {
		release_vals(&vals);
#ifdef KSPLICE_STANDALONE
		if (!run_pre_reloc) {
#else
		if (!pre) {
#endif
			failed_to_find(pack, r->sym_name);
			return -1;
		}

		ksdebug(pack, 4, KERN_DEBUG "ksplice: reloc: deferred %s:%" ADDR
			" to run-pre\n", r->sym_name, r->blank_offset);

		map = kmalloc(sizeof(*map), GFP_KERNEL);
		if (map == NULL) {
			printk(KERN_ERR "ksplice: out of memory\n");
			return -ENOMEM;
		}
		map->addr = r->blank_addr;
		map->nameval = find_nameval(pack, r->sym_name, 1);
		if (map->nameval == NULL) {
			kfree(map);
			return -ENOMEM;
		}
		map->pcrel = r->pcrel;
		map->addend = r->addend;
		map->size = r->size;
		map->dst_mask = r->dst_mask;
		list_add(&map->list, pack->reloc_addrmaps);
		return 0;
	}
	sym_addr = list_entry(vals.next, struct candidate_val, list)->val;
	release_vals(&vals);

#ifdef CONFIG_MODULE_UNLOAD
	if (!pre) {
		ret = add_dependency_on_address(pack, sym_addr);
		if (ret < 0)
			return ret;
	}
#endif

#ifdef KSPLICE_STANDALONE
	if (r->pcrel && run_pre_reloc) {
#else
	if (r->pcrel && pre) {
#endif
		map = kmalloc(sizeof(*map), GFP_KERNEL);
		if (map == NULL) {
			printk(KERN_ERR "ksplice: out of memory\n");
			return -ENOMEM;
		}
		map->addr = r->blank_addr;
		map->nameval = find_nameval(pack, "ksplice_zero", 1);
		if (map->nameval == NULL) {
			kfree(map);
			return -ENOMEM;
		}
		map->nameval->val = 0;
		map->nameval->status = VAL;
		map->pcrel = r->pcrel;
		map->addend = sym_addr + r->addend;
		map->size = r->size;
		map->dst_mask = r->dst_mask;
		list_add(&map->list, pack->reloc_addrmaps);

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
			return -1;
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
		return -1;
	}
	return 0;
}

#ifdef CONFIG_MODULE_UNLOAD
static int add_dependency_on_address(struct module_pack *pack,
				     unsigned long addr)
{
	struct module *m;
	int ret = 0;
	mutex_lock(&module_mutex);
	m = module_text_address(addr);
	if (m == NULL || starts_with(m->name, pack->name) ||
	    ends_with(m->name, "_helper"))
		ret = 0;
	else if (use_module(pack->primary, m) != 1)
		ret = -EBUSY;
	mutex_unlock(&module_mutex);
	return ret;
}

static int add_patch_dependencies(struct module_pack *pack)
{
	int ret;
	const struct ksplice_patch *p;
	for (p = pack->patches; p < pack->patches_end; p++) {
		ret = add_dependency_on_address(pack, p->oldaddr);
		if (ret < 0)
			return ret;
	}
	return 0;
}

#ifdef KSPLICE_STANDALONE
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
#endif
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
#endif
	return 1;
}
#endif /* KSPLICE_STANDALONE */
#endif /* CONFIG_MODULE_UNLOAD */

static int compute_address(struct module_pack *pack, char *sym_name,
			   struct list_head *vals, int pre)
{
	int i, ret;
	const char *prefix[] = { ".text.", ".bss.", ".data.", NULL };
#ifdef CONFIG_KALLSYMS
	const char *name;
#endif /* CONFIG_KALLSYMS */
#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return 0;
#endif

	if (!pre) {
		struct reloc_nameval *nv = find_nameval(pack, sym_name, 0);
		if (nv != NULL && nv->status != NOVAL) {
			release_vals(vals);
			ret = add_candidate_val(vals, nv->val);
			if (ret < 0)
				return ret;
			ksdebug(pack, 1, KERN_DEBUG "ksplice: using detected "
				"sym %s=%" ADDR "\n", sym_name, nv->val);
			return 0;
		}
	}

	if (starts_with(sym_name, ".rodata"))
		return 0;

#ifdef CONFIG_KALLSYMS
	name = dup_wolabel(sym_name);
	ret = kernel_lookup(name, vals);
	if (ret == 0)
		ret = other_module_lookup(name, vals, pack->name);
	kfree(name);
	if (ret < 0)
		return ret;
#endif

	for (i = 0; prefix[i] != NULL; i++) {
		if (starts_with(sym_name, prefix[i])) {
			ret = compute_address(pack, sym_name +
					      strlen(prefix[i]), vals, pre);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

#ifdef CONFIG_KALLSYMS
static int other_module_lookup(const char *name, struct list_head *vals,
			       const char *ksplice_name)
{
	int ret = 0;
	struct accumulate_struct acc = { name, vals };
	struct module *m;

	if (acc.desired_name == NULL)
		return -ENOMEM;
	mutex_lock(&module_mutex);
	list_for_each_entry(m, &modules, list) {
		if (starts_with(m->name, ksplice_name) ||
		    ends_with(m->name, "_helper"))
			continue;
		ret = module_on_each_symbol(m, accumulate_matching_names, &acc);
		if (ret < 0)
			break;
	}
	mutex_unlock(&module_mutex);

	return ret;
}

static int accumulate_matching_names(void *data, const char *sym_name,
				     unsigned long sym_val)
{
	int ret = 0;
	struct accumulate_struct *acc = data;

	if (strcmp(sym_name, acc->desired_name) == 0)
		ret = add_candidate_val(acc->vals, sym_val);
	return ret;
}
#endif /* CONFIG_KALLSYMS */

#ifdef KSPLICE_STANDALONE
static int brute_search(struct module_pack *pack,
			const struct ksplice_size *s,
			void *start, unsigned long len)
{
	unsigned long addr;
	char run, pre;

	for (addr = (unsigned long)start; addr < (unsigned long)start + len;
	     addr++) {
		if (addr % 100000 == 0)
			yield();

		if (!virtual_address_mapped(addr))
			return 1;

		run = *(unsigned char *)(addr);
		pre = *(unsigned char *)(s->thismod_addr);

		if (run != pre)
			continue;

		if (try_addr(pack, s, addr, s->thismod_addr))
			return 0;
	}

	return 1;
}

static int brute_search_all(struct module_pack *pack,
			    const struct ksplice_size *s)
{
	struct module *m;
	int ret = 0;
	int saved_debug;
	char *where = NULL;

	ksdebug(pack, 2, KERN_DEBUG "ksplice: brute_search: searching for %s\n",
		s->name);
	saved_debug = pack->debug;
	pack->debug = 0;

	mutex_lock(&module_mutex);
	list_for_each_entry(m, &modules, list) {
		if (starts_with(m->name, pack->name) ||
		    ends_with(m->name, "_helper"))
			continue;
		if (brute_search(pack, s, m->module_core, m->core_size) == 0 ||
		    brute_search(pack, s, m->module_init, m->init_size) == 0) {
			ret = 1;
			where = m->name;
			break;
		}
	}
	mutex_unlock(&module_mutex);

	if (ret == 0) {
		if (brute_search(pack, s, (void *)init_mm.start_code,
				 init_mm.end_code - init_mm.start_code) == 0) {
			ret = 1;
			where = "vmlinux";
		}
	}

	pack->debug = saved_debug;
	if (ret == 1)
		ksdebug(pack, 2, KERN_DEBUG "ksplice: brute_search: found %s "
			"in %s\n", s->name, where);

	return ret;
}

#ifdef CONFIG_KALLSYMS
/* Modified version of Linux's kallsyms_lookup_name */
static int kernel_lookup(const char *name, struct list_head *vals)
{
	int ret;
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
			if (ret < 0)
				return ret;
		}
	}
#else /* LINUX_VERSION_CODE */
	char *knames;

	for (i = 0, knames = kallsyms_names; i < kallsyms_num_syms; i++) {
		unsigned prefix = *knames++;

		strlcpy(namebuf + prefix, knames, KSYM_NAME_LEN - prefix);

		if (strcmp(namebuf, name) == 0) {
			ret = add_candidate_val(vals, kallsyms_addresses[i]);
			if (ret < 0)
				return ret;
		}

		knames += strlen(knames) + 1;
	}
#endif /* LINUX_VERSION_CODE */

	return 0;
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

static int module_on_each_symbol(struct module *mod,
				 int (*fn) (void *, const char *,
					    unsigned long), void *data)
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
#else /* KSPLICE_STANDALONE */
EXPORT_SYMBOL_GPL(init_ksplice_module);
EXPORT_SYMBOL_GPL(cleanup_ksplice_module);

int init_module(void)
{
	return 0;
}

void cleanup_module(void)
{
}

static int kernel_lookup(const char *name, struct list_head *vals)
{
	int ret;
	struct accumulate_struct acc = { name, vals };
	if (acc.desired_name == NULL)
		return -ENOMEM;
	ret = kallsyms_on_each_symbol(accumulate_matching_names, &acc);
	if (ret < 0)
		return ret;
	return 0;
}
#endif /* KSPLICE_STANDALONE */

static int add_candidate_val(struct list_head *vals, unsigned long val)
{
	struct candidate_val *tmp, *new;

	list_for_each_entry(tmp, vals, list) {
		if (tmp->val == val)
			return 0;
	}
	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (new == NULL) {
		printk(KERN_ERR "ksplice: out of memory\n");
		return -ENOMEM;
	}
	new->val = val;
	list_add(&new->list, vals);
	return 0;
}

static void release_vals(struct list_head *vals)
{
	clear_list(vals, struct candidate_val, list);
}

struct reloc_nameval *find_nameval(struct module_pack *pack, char *name,
				   int create)
{
	struct reloc_nameval *nv, *new;
	char *newname;
	list_for_each_entry(nv, pack->reloc_namevals, list) {
		newname = nv->name;
		if (starts_with(newname, ".text."))
			newname += 6;
		if (strcmp(newname, name) == 0)
			return nv;
	}
	if (!create)
		return NULL;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (new == NULL) {
		printk(KERN_ERR "ksplice: out of memory\n");
		return NULL;
	}
	new->name = name;
	new->val = 0;
	new->status = NOVAL;
	list_add(&new->list, pack->reloc_namevals);
	return new;
}

struct reloc_addrmap *find_addrmap(struct module_pack *pack, unsigned long addr)
{
	struct reloc_addrmap *map;
	list_for_each_entry(map, pack->reloc_addrmaps, list) {
		if (addr >= map->addr && addr < map->addr + map->size)
			return map;
	}
	return NULL;
}

static void set_temp_myst_relocs(struct module_pack *pack, int status_val)
{
	struct reloc_nameval *nv;
	list_for_each_entry(nv, pack->reloc_namevals, list) {
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

#ifdef CONFIG_KALLSYMS
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

static const char *dup_wolabel(const char *sym_name)
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
	if (newstr == NULL) {
		printk(KERN_ERR "ksplice: out of memory\n");
		return NULL;
	}
	memcpy(newstr, sym_name, new_strlen);
	newstr[new_strlen] = 0;
	return newstr;
}
#endif

#ifdef CONFIG_DEBUG_FS
#ifdef KSPLICE_STANDALONE
/* Old kernels don't have debugfs_create_blob */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
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
#endif
#endif

void clear_debug_buf(struct module_pack *pack)
{
	debugfs_remove(pack->debugfs_dentry);
	pack->debug_blob.size = 0;
	kfree(pack->debug_blob.data);
	pack->debug_blob.data = NULL;
}

int init_debug_buf(struct module_pack *pack)
{
	pack->debug_blob.size = roundup_pow_of_two(1);
	pack->debug_blob.data = kmalloc(pack->debug_blob.size, GFP_KERNEL);
	if (pack->debug_blob.data == NULL)
		return -ENOMEM;
	pack->debugfs_dentry = debugfs_create_blob(pack->name, 700, NULL,
						   &pack->debug_blob);
	if (pack->debugfs_dentry == NULL) {
		kfree(pack->debug_blob.data);
		return -ENOMEM;
	}
	return 0;
}

int ksdebug(struct module_pack *pack, int level, const char *fmt, ...)
{
	va_list args;
	int size, old_size, new_size;

	if (pack->debug < level)
		return 0;

	va_start(args, fmt);
	/* size includes the trailing '\0' */
	size = 1 + vsnprintf(pack->debug_blob.data, 0, fmt, args);
	va_end(args);
	old_size = roundup_pow_of_two(pack->debug_blob.size);
	new_size = roundup_pow_of_two(size + pack->debug_blob.size);
	if (new_size > old_size) {
		char *tmp = pack->debug_blob.data;
#ifndef KSPLICE_STANDALONE
		pack->debug_blob.data = krealloc(pack->debug_blob.data,
						 new_size, GFP_KERNEL);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
		pack->debug_blob.data = krealloc(pack->debug_blob.data,
						 new_size, GFP_KERNEL);
#else
		/* We cannot use our own function with the same
		 * arguments as krealloc, because doing so requires
		 * ksize, which was first exported in 2.6.24-rc5.
		 */
		pack->debug_blob.data = kmalloc(new_size, GFP_KERNEL);
		if (pack->debug_blob.data != NULL) {
			memcpy(pack->debug_blob.data, tmp,
			       pack->debug_blob.size);
			kfree(tmp);
		}
#endif
#endif
		if (pack->debug_blob.data == NULL) {
			kfree(tmp);
			return -ENOMEM;
		}
	}
	va_start(args, fmt);
	pack->debug_blob.size += vsnprintf(pack->debug_blob.data +
					   pack->debug_blob.size,
					   size, fmt, args);
	va_end(args);

	return 0;
}
#endif /* CONFIG_DEBUG_FS */

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jeffrey Brian Arnold <jbarnold@mit.edu>");
