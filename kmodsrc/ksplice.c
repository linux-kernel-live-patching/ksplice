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
#include <asm/uaccess.h>
#include "ksplice.h"
#include "ksplice-run-pre.h"
#else
#include <linux/uaccess.h>
#include "ksplice.h"
#include <asm/ksplice-run-pre.h>
#endif

#ifdef KSPLICE_STANDALONE

/* Old kernels do not have kcalloc */
#define kcalloc ksplice_kcalloc
static inline void *ksplice_kcalloc(size_t n, size_t size,
				    typeof(GFP_KERNEL) flags);

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
#define KSPLICE_IP(x) thread_return
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
extern struct ksplice_reloc ksplice_init_relocs;

/* Obtained via System.map */
extern struct list_head modules;
extern struct mutex module_mutex;

#else /* KSPLICE_STANDALONE */
#define KSPLICE_IP(x) ((x)->thread.ip)
#define KSPLICE_SP(x) ((x)->thread.sp)
#endif /* KSPLICE_STANDALONE */

static int debug;
module_param(debug, int, 0600);

void cleanup_ksplice_module(struct module_pack *pack)
{
	remove_proc_entry(pack->name, &proc_root);
}

int activate_primary(struct module_pack *pack)
{
	int i, ret;
	struct proc_dir_entry *proc_entry;

	if (process_ksplice_relocs(pack, pack->primary_relocs, 0) != 0)
		return -1;

	if (resolve_patch_symbols(pack) != 0)
		return -1;

#ifdef CONFIG_MODULE_UNLOAD
	if (add_patch_dependencies(pack) != 0)
		return -1;
#endif

	proc_entry = create_proc_entry(pack->name, 0644, NULL);
	if (proc_entry == NULL) {
		print_abort("primary module: could not create proc entry");
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
			print_abort("stack check: to-be-replaced code is busy");
		return -1;
	}

	printk(KERN_INFO "ksplice: Update %s applied successfully\n",
	       pack->name);
	return 0;
}

int resolve_patch_symbols(struct module_pack *pack)
{
	struct ksplice_patch *p;
	int ret;
	LIST_HEAD(vals);

	for (p = pack->patches; p->oldstr; p++) {
		p->saved = kmalloc(5, GFP_KERNEL);
		if (p->saved == NULL) {
			print_abort("out of memory");
			return -ENOMEM;
		}

		ret = compute_address(pack, p->oldstr, &vals, 0);
		if (ret < 0)
			return ret;

		if (!singular(&vals)) {
			release_vals(&vals);
			failed_to_find(p->oldstr);
			return -1;
		}
		p->oldaddr =
		    list_entry(vals.next, struct candidate_val, list)->val;
		release_vals(&vals);
	}

	return 0;
}

int procfile_read(char *buffer, char **buffer_location,
		  off_t offset, int buffer_length, int *eof, void *data)
{
	return 0;
}

int procfile_write(struct file *file, const char *buffer, unsigned long count,
		   void *data)
{
	int i, ret;
	struct module_pack *pack = data;
	printk(KERN_INFO "ksplice: Preparing to reverse %s\n", pack->name);

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
		print_abort("stack check: to-be-reversed code is busy");
	else if (ret == 0)
		printk(KERN_INFO "ksplice: Update %s reversed successfully\n",
		       pack->name);
	else if (ret == -EBUSY)
		printk(KERN_ERR "ksplice: Update module %s is in use by "
		       "another module\n", pack->name);

	return count;
}

int __apply_patches(void *packptr)
{
	struct module_pack *pack = packptr;
	struct ksplice_patch *p;
	struct safety_record *rec;
	mm_segment_t old_fs;

	list_for_each_entry(rec, pack->safety_records, list) {
		for (p = pack->patches; p->oldstr; p++) {
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
	for (p = pack->patches; p->oldstr; p++) {
		memcpy((void *)p->saved, (void *)p->oldaddr, 5);
		*((u8 *) p->oldaddr) = 0xE9;
		*((u32 *) (p->oldaddr + 1)) = p->repladdr - (p->oldaddr + 5);
		flush_icache_range((unsigned long)p->oldaddr,
				   (unsigned long)(p->oldaddr + 5));
	}
	set_fs(old_fs);
	return 0;
}

int __reverse_patches(void *packptr)
{
	struct module_pack *pack = packptr;
	struct ksplice_patch *p;
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
	for (p = pack->patches; p->oldstr; p++) {
		memcpy((void *)p->oldaddr, (void *)p->saved, 5);
		kfree(p->saved);
		flush_icache_range((unsigned long)p->oldaddr,
				   (unsigned long)(p->oldaddr + 5));
	}
	set_fs(old_fs);
	return 0;
}

int check_each_task(struct module_pack *pack)
{
	struct task_struct *g, *p;
	int status = 0;
	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
		/* do_each_thread is a double loop! */
		if (check_task(pack, p) < 0) {
			if (debug == 1) {
				debug = 2;
				check_task(pack, p);
				debug = 1;
			}
			status = -EAGAIN;
		}
	}
	while_each_thread(g, p);
	read_unlock(&tasklist_lock);
	return status;
}

int check_task(struct module_pack *pack, struct task_struct *t)
{
	int status, ret;

	ksplice_debug(2, KERN_DEBUG "ksplice: stack check: pid %d (%s) eip "
		      "%08lx ", t->pid, t->comm, KSPLICE_IP(t));
	status = check_address_for_conflict(pack, KSPLICE_IP(t));
	ksplice_debug(2, ": ");

	if (t == current) {
		ret = check_stack(pack, task_thread_info(t),
				  (long *)__builtin_frame_address(0));
		if (status == 0)
			status = ret;
	} else if (!task_curr(t)) {
		ret = check_stack(pack, task_thread_info(t),
				  (long *)KSPLICE_SP(t));
		if (status == 0)
			status = ret;
	} else if (strcmp(t->comm, "kstopmachine") != 0) {
		ksplice_debug(2, "unexpected running task!");
		status = -ENODEV;
	}
	ksplice_debug(2, "\n");
	return status;
}

/* Modified version of Linux's print_context_stack */
int check_stack(struct module_pack *pack, struct thread_info *tinfo,
		long *stack)
{
	int status = 0;
	long addr;

	while (valid_stack_ptr(tinfo, stack)) {
		addr = *stack++;
		if (__kernel_text_address(addr)) {
			ksplice_debug(2, "%08lx ", addr);
			if (check_address_for_conflict(pack, addr) < 0)
				status = -EAGAIN;
		}
	}
	return status;
}

int check_address_for_conflict(struct module_pack *pack, long addr)
{
	struct ksplice_size *s = pack->primary_sizes;
	struct safety_record *rec;

	/* It is safe for addr to point to the beginning of a patched
	   function, because that location will be overwritten with a
	   trampoline. */
	list_for_each_entry(rec, pack->safety_records, list) {
		if (rec->care == 1 && addr > rec->addr
		    && addr < rec->addr + rec->size) {
			ksplice_debug(2, "[<-- CONFLICT] ");
			return -EAGAIN;
		}
	}
	for (; s->name != NULL; s++) {
		if (addr >= s->thismod_addr
		    && addr < s->thismod_addr + s->size) {
			ksplice_debug(2, "[<-- CONFLICT] ");
			return -EAGAIN;
		}
	}
	return 0;
}

/* Modified version of Linux's valid_stack_ptr */
int valid_stack_ptr(struct thread_info *tinfo, void *p)
{
	return p > (void *)tinfo
	    && p <= (void *)tinfo + THREAD_SIZE - sizeof(long);
}

int init_ksplice_module(struct module_pack *pack)
{
	int ret = 0;
#ifdef KSPLICE_STANDALONE
	if (process_ksplice_relocs(pack, &ksplice_init_relocs, 1) != 0)
		return -1;
	bootstrapped = 1;
#endif

	printk(KERN_INFO "ksplice_h: Preparing and checking %s\n", pack->name);

	if (activate_helper(pack) != 0 || activate_primary(pack) != 0)
		ret = -1;

	clear_list(pack->reloc_namevals, struct reloc_nameval, list);
	clear_list(pack->reloc_addrmaps, struct reloc_addrmap, list);
	if (pack->state == KSPLICE_PREPARING)
		clear_list(pack->safety_records, struct safety_record, list);

	return ret;
}

int activate_helper(struct module_pack *pack)
{
	struct ksplice_size *s;
	int i, record_count = 0, ret;
	char *finished;
	int numfinished, oldfinished = 0;
	int restart_count = 0;

	if (process_ksplice_relocs(pack, pack->helper_relocs, 1) != 0)
		return -1;

	for (s = pack->helper_sizes; s->name != NULL; s++)
		record_count++;

	finished = kcalloc(record_count, 1, GFP_KERNEL);
	if (finished == NULL) {
		print_abort("out of memory");
		return -ENOMEM;
	}

start:
	for (s = pack->helper_sizes, i = 0; s->name != NULL; s++, i++) {
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
		for (s = pack->helper_sizes, i = 0; s->name != NULL; s++, i++) {
			if (finished[i] == 0)
				ksplice_debug(2, KERN_DEBUG "ksplice: run-pre: "
					      "could not match section %s\n",
					      s->name);
		}
		print_abort("run-pre: could not match some sections");
		kfree(finished);
		return -1;
	}
	oldfinished = numfinished;

	if (restart_count < 20) {
		restart_count++;
		goto start;
	}
	print_abort("run-pre: restart limit exceeded");
	kfree(finished);
	return -1;
}

int search_for_match(struct module_pack *pack, struct ksplice_size *s)
{
	int i, ret;
	long run_addr;
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

	ksplice_debug(3, KERN_DEBUG "ksplice_h: run-pre: starting sect search "
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

int try_addr(struct module_pack *pack, struct ksplice_size *s, long run_addr,
	     long pre_addr)
{
	struct safety_record *tmp;
	struct reloc_nameval *nv;

	if (run_pre_cmp(pack, run_addr, pre_addr, s->size, 0) != 0) {
		set_temp_myst_relocs(pack, NOVAL);
		ksplice_debug(1, KERN_DEBUG "ksplice_h: run-pre: sect %s does "
			      "not match ", s->name);
		ksplice_debug(1, "(r_a=%08lx p_a=%08lx s=%ld)\n",
			      run_addr, pre_addr, s->size);
		ksplice_debug(1, "ksplice_h: run-pre: ");
		if (debug >= 1)
			run_pre_cmp(pack, run_addr, pre_addr, s->size, 1);
		ksplice_debug(1, "\n");
	} else {
		set_temp_myst_relocs(pack, VAL);

		ksplice_debug(3, KERN_DEBUG "ksplice_h: run-pre: found sect "
			      "%s=%08lx\n", s->name, run_addr);

		tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
		if (tmp == NULL) {
			print_abort("out of memory");
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

int handle_myst_reloc(long pre_addr, int *pre_o, long run_addr,
		      int *run_o, struct reloc_addrmap *map, int rerun)
{
	int expected;
	int offset = (int)(pre_addr + *pre_o - map->addr);
	long run_reloc = 0;
	long run_reloc_addr;
	run_reloc_addr = run_addr + *run_o - offset;
	if (map->size == 4)
		run_reloc = *(int *)run_reloc_addr;
	else if (map->size == 8)
		run_reloc = *(long long *)run_reloc_addr;
	else
		BUG();

	if (debug >= 3 && !rerun) {
		printk(KERN_DEBUG "ksplice_h: run-pre: reloc at r_a=%08lx "
		       "p_o=%08x: ", run_addr, *pre_o);
		printk("%s=%08lx (A=%08lx *r=%08lx)\n",
		       map->nameval->name, map->nameval->val,
		       map->addend, run_reloc);
	}

	if (!starts_with(map->nameval->name, ".rodata.str")) {
		expected = run_reloc - map->addend;
		if ((int)run_reloc == 0x77777777)
			return 1;
		if (map->pcrel)
			expected += run_reloc_addr;
		if (map->nameval->status == NOVAL) {
			map->nameval->val = expected;
			map->nameval->status = TEMP;
		} else if (map->nameval->val != expected) {
			if (rerun)
				return 1;
			printk(KERN_DEBUG "ksplice_h: pre-run reloc: Expected "
			       "%s=%08x!\n", map->nameval->name, expected);
			return 1;
		}
	}

	*pre_o += map->size - offset;
	*run_o += map->size - offset;
	return 0;
}

int process_ksplice_relocs(struct module_pack *pack,
			   struct ksplice_reloc *relocs, int pre)
{
	struct ksplice_reloc *r;
	for (r = relocs; r->sym_name != NULL; r++) {
		if (process_reloc(pack, r, pre) != 0)
			return -1;
	}
	return 0;
}

int process_reloc(struct module_pack *pack, struct ksplice_reloc *r, int pre)
{
	int i, ret;
	long off, sym_addr;
	struct reloc_addrmap *map;
	const long blank_addr = r->blank_sect_addr + r->blank_offset;
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
	off = (long)printk - pack->map_printk;
	if (off & 0xfffff) {
		print_abort("System.map does not match kernel");
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

	if ((r->size == 4 && *(int *)blank_addr != 0x77777777)
	    || (r->size == 8 &&
		*(long long *)blank_addr != 0x7777777777777777ll)) {
		ksplice_debug(4, KERN_DEBUG "ksplice%s: reloc: skipped %s:%08lx"
			      " (altinstr)\n", (pre ? "_h" : ""),
			      r->sym_name, r->blank_offset);
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
			failed_to_find(r->sym_name);
			return -1;
		}

		ksplice_debug(4, KERN_DEBUG "ksplice: reloc: deferred %s:%08lx "
			      "to run-pre\n", r->sym_name, r->blank_offset);

		map = kmalloc(sizeof(*map), GFP_KERNEL);
		if (map == NULL) {
			print_abort("out of memory");
			return -ENOMEM;
		}
		map->addr = blank_addr;
		map->nameval = find_nameval(pack, r->sym_name, 1);
		if (map->nameval == NULL)
			return -ENOMEM;
		map->addend = r->addend;
		map->pcrel = r->pcrel;
		map->size = r->size;
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
			print_abort("out of memory");
			return -ENOMEM;
		}
		map->addr = blank_addr;
		map->nameval = find_nameval(pack, "ksplice_zero", 1);
		if (map->nameval == NULL)
			return -ENOMEM;
		map->nameval->val = 0;
		map->nameval->status = VAL;
		map->addend = sym_addr + r->addend;
		map->size = r->size;
		map->pcrel = r->pcrel;
		list_add(&map->list, pack->reloc_addrmaps);

	} else {
		long val;
		if (r->pcrel)
			val = sym_addr + r->addend - blank_addr;
		else
			val = sym_addr + r->addend;
		if (r->size == 4)
			*(int *)blank_addr = val;
		else if (r->size == 8)
			*(long long *)blank_addr = val;
		else
			BUG();
	}

	ksplice_debug(4, KERN_DEBUG "ksplice%s: reloc: %s:%08lx ",
		      (pre ? "_h" : ""), r->sym_name, r->blank_offset);
	ksplice_debug(4, "(S=%08lx A=%08lx ", sym_addr, r->addend);
	if (r->size == 4)
		ksplice_debug(4, "aft=%08x)\n", *(int *)blank_addr);
	else if (r->size == 8)
		ksplice_debug(4, "aft=%016llx)\n", *(long long *)blank_addr);
	else
		BUG();
	return 0;
}

#ifdef CONFIG_MODULE_UNLOAD
int add_dependency_on_address(struct module_pack *pack, long addr)
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

int add_patch_dependencies(struct module_pack *pack)
{
	int ret;
	struct ksplice_patch *p;
	for (p = pack->patches; p->oldstr; p++) {
		ret = add_dependency_on_address(pack, p->oldaddr);
		if (ret < 0)
			return ret;
	}
	return 0;
}

#ifdef KSPLICE_STANDALONE
/* Essentially, code from module.c; we use directly use_module and module_text_address */
struct module *module_text_address(unsigned long addr)
{
	struct module *m;
	list_for_each_entry(m, &modules, list) {
		if ((addr >= (unsigned long)m->module_core &&
		     addr < (unsigned long)m->module_core + m->core_size) ||
		    (addr >= (unsigned long)m->module_init &&
		     addr < (unsigned long)m->module_init + m->init_size))
			return m;
	}
	return NULL;
}

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
int use_module(struct module *a, struct module *b)
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

	ksplice_debug(4, "Allocating new usage for %s.\n", a->name);
	use = kmalloc(sizeof(*use), GFP_ATOMIC);
	if (!use) {
		printk("%s: out of memory adding dependencies\n", a->name);
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

int compute_address(struct module_pack *pack, char *sym_name,
		    struct list_head *vals, int pre)
{
	int i, ret;
	const char *prefix[] = { ".text.", ".bss.", ".data.", NULL };
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
			ksplice_debug(1, KERN_DEBUG "ksplice: using detected "
				      "sym %s=%08lx\n", sym_name, nv->val);
			return 0;
		}
	}

	if (starts_with(sym_name, ".rodata"))
		return 0;

#ifdef CONFIG_KALLSYMS
	ret = kernel_lookup(sym_name, vals);
	if (ret < 0)
		return ret;
	ret = other_module_lookup(sym_name, vals, pack->name);
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
int other_module_lookup(const char *name_wlabel, struct list_head *vals,
			const char *ksplice_name)
{
	int ret = 0;
	struct accumulate_struct acc = { dup_wolabel(name_wlabel), vals };
	struct module *m;

	if (acc.desired_name == NULL)
		return -ENOMEM;
	mutex_lock(&module_mutex);
	list_for_each_entry(m, &modules, list) {
		if (!starts_with(m->name, ksplice_name)
		    && !ends_with(m->name, "_helper")) {
			ret = module_on_each_symbol(m,
						    accumulate_matching_names,
						    &acc);
			if (ret < 0)
				break;
		}
	}
	mutex_unlock(&module_mutex);

	kfree(acc.desired_name);
	return ret;
}
#endif /* CONFIG_KALLSYMS */

int accumulate_matching_names(void *data, const char *sym_name, long sym_val)
{
	int ret = 0;
	struct accumulate_struct *acc = data;

	if (strncmp(sym_name, acc->desired_name, strlen(acc->desired_name)) !=
	    0)
		return 0;

	sym_name = dup_wolabel(sym_name);
	if (sym_name == NULL)
		return -ENOMEM;
	/* TODO: possibly remove "&& sym_val != 0" */
	if (strcmp(sym_name, acc->desired_name) == 0 && sym_val != 0)
		ret = add_candidate_val(acc->vals, sym_val);
	kfree(sym_name);
	return ret;
}

#ifdef KSPLICE_STANDALONE
int brute_search_all(struct module_pack *pack, struct ksplice_size *s)
{
	struct module *m;
	int ret = 0;
	int saved_debug;
	char *where = NULL;

	ksplice_debug(2, KERN_DEBUG "ksplice: brute_search: searching for %s\n",
		      s->name);
	saved_debug = debug;
	debug = 0;

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

	if (ret == 1 && saved_debug >= 2)
		printk(KERN_DEBUG "ksplice: brute_search: found %s in %s\n",
		       s->name, where);

	debug = saved_debug;
	return ret;
}

/* old kernels do not have kcalloc */
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

#ifdef CONFIG_KALLSYMS
/* Modified version of Linux's kallsyms_lookup_name */
int kernel_lookup(const char *name_wlabel, struct list_head *vals)
{
	int ret;
	char namebuf[KSYM_NAME_LEN + 1];
	unsigned long i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	unsigned long off;
#endif /* LINUX_VERSION_CODE */

	const char *name = dup_wolabel(name_wlabel);
	if (name == NULL)
		return -ENOMEM;

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

	kfree(name);
	return 0;
}

/*  kallsyms compression was added by 5648d78927ca65e74aadc88a2b1d6431e55e78ec
 *  2.6.10 was the first release after this commit
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
extern u8 kallsyms_token_table[];
extern u16 kallsyms_token_index[];
/* Modified version of Linux's kallsyms_expand_symbol */
long ksplice_kallsyms_expand_symbol(unsigned long off, char *result)
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

int module_on_each_symbol(struct module *mod,
			  int (*fn) (void *, const char *, long), void *data)
{
	unsigned int i;
	int ret;

	/* TODO: possibly remove this if statement */
	if (strlen(mod->name) <= 1)
		return 0;

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

int kernel_lookup(const char *name_wlabel, struct list_head *vals)
{
	int ret;
	struct accumulate_struct acc = { dup_wolabel(name_wlabel), vals };
	if (acc.desired_name == NULL)
		return -ENOMEM;
	ret = kallsyms_on_each_symbol(accumulate_matching_names, &acc);
	if (ret < 0)
		return ret;
	kfree(acc.desired_name);
	return 0;
}
#endif /* KSPLICE_STANDALONE */

int add_candidate_val(struct list_head *vals, long val)
{
	struct candidate_val *tmp, *new;

	list_for_each_entry(tmp, vals, list) {
		if (tmp->val == val)
			return 0;
	}
	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (new == NULL) {
		print_abort("out of memory");
		return -ENOMEM;
	}
	new->val = val;
	list_add(&new->list, vals);
	return 0;
}

void release_vals(struct list_head *vals)
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
		print_abort("out of memory");
		return NULL;
	}
	new->name = name;
	new->val = 0;
	new->status = NOVAL;
	list_add(&new->list, pack->reloc_namevals);
	return new;
}

struct reloc_addrmap *find_addrmap(struct module_pack *pack, long addr)
{
	struct reloc_addrmap *map;
	list_for_each_entry(map, pack->reloc_addrmaps, list) {
		if (addr >= map->addr && addr < map->addr + map->size)
			return map;
	}
	return NULL;
}

void set_temp_myst_relocs(struct module_pack *pack, int status_val)
{
	struct reloc_nameval *nv;
	list_for_each_entry(nv, pack->reloc_namevals, list) {
		if (nv->status == TEMP)
			nv->status = status_val;
	}
}

int starts_with(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

int ends_with(const char *str, const char *suffix)
{
	return strlen(str) >= strlen(suffix) &&
	    strcmp(&str[strlen(str) - strlen(suffix)], suffix) == 0;
}

int label_offset(const char *sym_name)
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

const char *dup_wolabel(const char *sym_name)
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
		print_abort("out of memory");
		return NULL;
	}
	memcpy(newstr, sym_name, new_strlen);
	newstr[new_strlen] = 0;
	return newstr;
}

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jeffrey Brian Arnold <jbarnold@mit.edu>");
