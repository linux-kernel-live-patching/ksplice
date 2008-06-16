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
#include <linux/kallsyms.h>
#include <linux/kthread.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/stop_machine.h>
#include <linux/time.h>
#include <asm/uaccess.h>
#include "ksplice.h"
#ifdef KSPLICE_STANDALONE
#include <linux/version.h>
#include "ksplice-run-pre.h"
#else
#include <asm/ksplice-run-pre.h>
#endif

#ifdef KSPLICE_STANDALONE

#ifndef task_thread_info
#define task_thread_info(task) (task)->thread_info
#endif /* task_thread_info */

#ifdef __ASM_X86_PROCESSOR_H
#define KSPLICE_EIP(x) ((x)->thread.ip)
#define KSPLICE_ESP(x) ((x)->thread.sp)
#elif BITS_PER_LONG == 32
#define KSPLICE_EIP(x) ((x)->thread.eip)
#define KSPLICE_ESP(x) ((x)->thread.esp)
#elif BITS_PER_LONG == 64
#define KSPLICE_EIP(x) (KSTK_EIP(x))
#define KSPLICE_ESP(x) ((x)->thread.rsp)
#endif /* __ASM_X86_PROCESSOR_H */

#ifdef CONFIG_KALLSYMS
#define CONFIG_KALLSYMS_VAL 1
extern unsigned long kallsyms_addresses[], kallsyms_num_syms;
extern u8 kallsyms_names[];
#else /* CONFIG_KALLSYMS */
#define CONFIG_KALLSYMS_VAL 0
#endif /* CONFIG_KALLSYMS */

/* defined by ksplice-create */
extern struct ksplice_reloc ksplice_init_relocs;

static int safe = 0;

#else /* KSPLICE_STANDALONE */
#define safe 1			/* TODO: remove this line */
#define KSPLICE_EIP(x) ((x)->thread.ip)
#define KSPLICE_ESP(x) ((x)->thread.sp)
#endif /* KSPLICE_STANDALONE */

static int debug;
module_param(debug, int, 0600);

#ifndef KSPLICE_STANDALONE
/* THIS_MODULE everywhere is wrong! */

int init_module(void)
{
	return 0;
}

void cleanup_module(void)
{
}
#endif

void cleanup_ksplice_module(struct module_pack *pack)
{
	remove_proc_entry(pack->name, &proc_root);
}

#ifndef KSPLICE_STANDALONE
EXPORT_SYMBOL_GPL(cleanup_ksplice_module);
#endif

int activate_primary(struct module_pack *pack)
{
	int i;
	struct proc_dir_entry *proc_entry;

	pack->helper = 0;

	if (process_ksplice_relocs(pack, pack->primary_relocs) != 0)
		return -1;

	if (resolve_patch_symbols(pack) != 0)
		return -1;

	proc_entry = create_proc_entry(pack->name, 0644, NULL);
	if (proc_entry == NULL) {
		remove_proc_entry(pack->name, &proc_root);
		print_abort("primary module: could not create proc entry");
		return -1;
	}

	proc_entry->read_proc = procfile_read;
	proc_entry->write_proc = procfile_write;
	proc_entry->data = pack;
	proc_entry->owner = THIS_MODULE;
	proc_entry->mode = S_IFREG | S_IRUSR | S_IWUSR;
	proc_entry->uid = 0;
	proc_entry->gid = 0;
	proc_entry->size = 0;

	for (i = 0; pack->state != KSPLICE_APPLIED && i < 5; i++) {
		bust_spinlocks(1);
		stop_machine_run(__apply_patches, pack, NR_CPUS);
		bust_spinlocks(0);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
	}
	if (pack->state != KSPLICE_APPLIED) {
		remove_proc_entry(pack->name, &proc_root);
		print_abort("stack check: to-be-replaced code is busy");
		return -1;
	}

	printk("ksplice: Update %s applied successfully\n", pack->name);
	return 0;
}

int resolve_patch_symbols(struct module_pack *pack)
{
	struct ksplice_patch *p;
	LIST_HEAD(vals);

	for (p = pack->patches; p->oldstr; p++) {
		p->saved = kmalloc(5, GFP_KERNEL);

		if (p->oldaddr != 0)
			add_candidate_val(&vals, p->oldaddr);

		compute_address(pack, p->oldstr, &vals);
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
	int i;
	struct module_pack *pack = data;
	printk("ksplice: Preparing to reverse %s\n", pack->name);

	for (i = 0; pack->state == KSPLICE_APPLIED && i < 5; i++) {
		bust_spinlocks(1);
		stop_machine_run(__reverse_patches, pack, NR_CPUS);
		bust_spinlocks(0);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
	}
	if (pack->state == KSPLICE_APPLIED)
		print_abort("stack check: to-be-reversed code is busy");

	return count;
}

int __apply_patches(void *packptr)
{
	struct module_pack *pack = packptr;
	struct ksplice_patch *p;
	struct safety_record *rec;

	list_for_each_entry(rec, pack->safety_records, list) {
		for (p = pack->patches; p->oldstr; p++) {
			if (p->oldaddr == rec->addr) {
				rec->care = 1;
			}
		}
	}

	if (check_each_task(pack) != 0)
		return 0;

	if (!try_module_get(THIS_MODULE))
		return 0;

	pack->state = KSPLICE_APPLIED;

	for (p = pack->patches; p->oldstr; p++) {
		memcpy((void *)p->saved, (void *)p->oldaddr, 5);
		*((u8 *) p->oldaddr) = 0xE9;
		*((u32 *) (p->oldaddr + 1)) = p->repladdr - (p->oldaddr + 5);
	}
	return 0;
}

int __reverse_patches(void *packptr)
{
	struct module_pack *pack = packptr;
	struct ksplice_patch *p;

	if (pack->state != KSPLICE_APPLIED)
		return 0;

	if (check_each_task(pack) != 0)
		return 0;

	clear_list(pack->safety_records, struct safety_record, list);
	pack->state = KSPLICE_REVERSED;
	module_put(THIS_MODULE);

	p = pack->patches;
	for (; p->oldstr; p++) {
		memcpy((void *)p->oldaddr, (void *)p->saved, 5);
		kfree(p->saved);
		*((u8 *) p->repladdr) = 0xE9;
		*((u32 *) (p->repladdr + 1)) = p->oldaddr - (p->repladdr + 5);
	}

	printk("ksplice: Update %s reversed successfully\n", pack->name);
	return 0;
}

int check_each_task(struct module_pack *pack)
{
	struct task_struct *g, *p;
	int status = 0;
	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
		/* do_each_thread is a double loop! */
		if (check_task(pack, p) != 0) {
			if (debug == 1) {
				debug = 2;
				check_task(pack, p);
				debug = 1;
			}
			status = -1;
		}
	}
	while_each_thread(g, p);
	read_unlock(&tasklist_lock);
	return status;
}

int check_task(struct module_pack *pack, struct task_struct *t)
{
	int status;
	long addr = KSPLICE_EIP(t);
	int conflict = check_address_for_conflict(pack, addr);
	if (debug >= 2) {
		printk("ksplice: stack check: pid %d (%s) eip %08lx",
		       t->pid, t->comm, KSPLICE_EIP(t));
		if (conflict)
			printk(" [<-- CONFLICT]: ");
		else
			printk(": ");
	}
	if (t == current) {
		status =
		    check_stack(pack, task_thread_info(t),
				(long *)__builtin_frame_address(0));
	} else if (!task_curr(t)) {
		status =
		    check_stack(pack, task_thread_info(t),
				(long *)KSPLICE_ESP(t));
	} else if (strcmp(t->comm, "kstopmachine") == 0) {
		if (debug >= 2)
			printk("\n");
		return 0;
	} else {
		if (debug >= 2)
			printk("unexpected running task!\n");
		return -1;
	}

	if (conflict)
		status = -1;
	return status;
}

/* Modified version of Linux's print_context_stack */
int check_stack(struct module_pack *pack, struct thread_info *tinfo,
		long *stack)
{
	int conflict, status = 0;
	long addr;

	while (valid_stack_ptr(tinfo, stack)) {
		addr = *stack++;
		if (__kernel_text_address(addr)) {
			conflict = check_address_for_conflict(pack, addr);
			if (conflict)
				status = -1;
			if (debug >= 2) {
				printk("%08lx ", addr);
				if (conflict)
					printk("[<-- CONFLICT] ");
			}
		}
	}
	if (debug >= 2)
		printk("\n");

	return status;
}

int check_address_for_conflict(struct module_pack *pack, long addr)
{
	struct ksplice_size *s = pack->primary_sizes;
	struct safety_record *rec;

	list_for_each_entry(rec, pack->safety_records, list) {
		if (rec->care == 1 && addr > rec->addr
		    && addr <= (rec->addr + rec->size)) {
			return -1;
		}
	}
	for (; s->name != NULL; s++) {
		if (addr > s->thismod_addr
		    && addr <= (s->thismod_addr + s->size)) {
			return -1;
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

#undef max
#define max(a, b) ((a) > (b) ? (a) : (b))

int init_ksplice_module(struct module_pack *pack)
{
	int ret = 0;

#ifdef KSPLICE_STANDALONE
	if (process_ksplice_relocs(pack, &ksplice_init_relocs) != 0)
		return -1;
	safe = 1;
#endif

	printk("ksplice_h: Preparing and checking %s\n", pack->name);

	if (activate_helper(pack) != 0 || activate_primary(pack) != 0)
		ret = -1;

	clear_list(pack->reloc_namevals, struct reloc_nameval, list);
	clear_list(pack->reloc_addrmaps, struct reloc_addrmap, list);
	if (pack->state == KSPLICE_PREPARING)
		clear_list(pack->safety_records, struct safety_record, list);

	return ret;
}

#ifndef KSPLICE_STANDALONE
EXPORT_SYMBOL_GPL(init_ksplice_module);
#endif

/* old kernels do not have kcalloc */
#ifdef KSPLICE_STANDALONE
#define kcalloc(n, size, flags) ksplice_kcalloc(n)
#endif

int activate_helper(struct module_pack *pack)
{
	struct ksplice_size *s;
	int i, record_count = 0, ret;
	char *finished;
	int numfinished, oldfinished = 0;
	int restart_count = 0;

	pack->helper = 1;

	if (process_ksplice_relocs(pack, pack->helper_relocs) != 0)
		return -1;

	for (s = pack->helper_sizes; s->name != NULL; s++) {
		record_count++;
	}

	finished = kcalloc(record_count, 1, GFP_KERNEL);

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
		} else if (ret == 0) {
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

#ifdef KSPLICE_STANDALONE
/* old kernels do not have kcalloc */
void *ksplice_kcalloc(int size)
{
	char *mem = kmalloc(size, GFP_KERNEL);
	int i;
	for (i = 0; i < size; i++) {
		mem[i] = 0;
	}
	return mem;
}
#endif

int search_for_match(struct module_pack *pack, struct ksplice_size *s)
{
	int i;
#ifdef KSPLICE_STANDALONE
	int saved_debug;
#endif
	long run_addr;
	LIST_HEAD(vals);
	struct candidate_val *v;

	for (i = 0; i < s->num_sym_addrs; i++) {
		add_candidate_val(&vals, s->sym_addrs[i]);
	}

	compute_address(pack, s->name, &vals);

	if (debug >= 3) {
		printk("ksplice_h: run-pre: starting sect search for %s\n",
		       s->name);
	}

	list_for_each_entry(v, &vals, list) {
		run_addr = v->val;

		yield();
		if (try_addr
		    (pack, s, run_addr, s->thismod_addr, !singular(&vals))) {
			release_vals(&vals);
			return 0;
		}
	}
	release_vals(&vals);

#ifdef KSPLICE_STANDALONE
	saved_debug = debug;
	debug = 0;
	brute_search_all_mods(pack, s);
	debug = saved_debug;
#endif
	return 1;
}

int try_addr(struct module_pack *pack, struct ksplice_size *s, long run_addr,
	     long pre_addr, int create_nameval)
{
	struct safety_record *tmp;

	if (run_pre_cmp(pack, run_addr, pre_addr, s->size, 0) != 0) {
		set_temp_myst_relocs(pack, NOVAL);
		if (debug >= 1) {
			printk("ksplice_h: run-pre: sect %s does not match ",
			       s->name);
			printk("(r_a=%08lx p_a=%08lx s=%ld)\n",
			       run_addr, pre_addr, s->size);
			printk("ksplice_h: run-pre: ");
			run_pre_cmp(pack, run_addr, pre_addr, s->size, 1);
			printk("\n");
		}
	} else {
		set_temp_myst_relocs(pack, VAL);

		if (debug >= 3) {
			printk("ksplice_h: run-pre: found sect %s=%08lx\n",
			       s->name, run_addr);
		}

		tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
		tmp->addr = run_addr;
		tmp->size = s->size;
		tmp->care = 0;
		list_add(&tmp->list, pack->safety_records);

		if (create_nameval) {
			struct reloc_nameval *nv =
			    find_nameval(pack, s->name, 1);
			nv->val = run_addr;
			nv->status = VAL;
		}

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
	if (map->size == 4) {
		run_reloc = *(int *)run_reloc_addr;
	} else if (map->size == 8) {
		run_reloc = *(long long *)run_reloc_addr;
	} else {
		BUG();
	}

	if (debug >= 3 && !rerun) {
		printk("ksplice_h: run-pre: reloc at r_a=%08lx p_o=%08x: ",
		       run_addr, *pre_o);
		printk("%s=%08lx (A=%08lx *r=%08lx)\n",
		       map->nameval->name, map->nameval->val,
		       map->addend, run_reloc);
	}

	if (!starts_with(map->nameval->name, ".rodata.str")) {
		expected = run_reloc - map->addend;
		if ((int)run_reloc == 0x77777777)
			return 1;
		if (map->flags & PCREL)
			expected += run_reloc_addr;
		if (map->nameval->status == NOVAL) {
			map->nameval->val = expected;
			map->nameval->status = TEMP;
		} else if (map->nameval->val != expected) {
			if (rerun)
				return 1;
			printk("ksplice_h: pre-run reloc: Expected %s=%08x!\n",
			       map->nameval->name, expected);
			return 1;
		}
	}

	*pre_o += map->size - offset;
	*run_o += map->size - offset;
	return 0;
}

#ifdef KSPLICE_STANDALONE
void brute_search_all_mods(struct module_pack *pack, struct ksplice_size *s)
{
	struct module *m;
	list_for_each_entry(m, &(THIS_MODULE->list), list) {
		if (!starts_with(m->name, pack->name)
		    && !ends_with(m->name, "_helper")) {
			if (brute_search(pack, s, m->module_core, m->core_size)
			    == 0)
				return;
			if (brute_search(pack, s, m->module_init, m->init_size)
			    == 0)
				return;
		}
	}
}
#endif

int process_ksplice_relocs(struct module_pack *pack,
			   struct ksplice_reloc *relocs)
{
	struct ksplice_reloc *r;
	for (r = relocs; r->sym_name != NULL; r++) {
		if (process_reloc(pack, r) != 0)
			return -1;
	}
	return 0;
}

int process_reloc(struct module_pack *pack, struct ksplice_reloc *r)
{
	int i;
	long sym_addr;
	struct reloc_addrmap *map;

#define blank_addr (r->blank_sect_addr+r->blank_offset)

	LIST_HEAD(vals);
	if (CONFIG_KALLSYMS_VAL || !safe) {
		int adjustment = (long)printk - pack->map_printk;
		if (adjustment & 0xfffff) {
			print_abort("System.map does not match kernel");
			return -1;
		}
		for (i = 0; i < r->num_sym_addrs; i++) {
			add_candidate_val(&vals, r->sym_addrs[i] + adjustment);
		}
	}

	if ((r->size == 4 && *(int *)blank_addr == 0x77777777)
	    || (r->size == 8 &&
		*(long long *)blank_addr == 0x7777777777777777ll)) {
		r->flags |= SAFE;
	}
	if (!(r->flags & SAFE)) {
		if (debug >= 4) {
			printk
			    ("ksplice%s: reloc: skipped %s:%08lx (altinstr)\n",
			     (pack->helper ? "_h" : ""), r->sym_name,
			     r->blank_offset);
		}
		release_vals(&vals);
		return 0;
	}

	compute_address(pack, r->sym_name, &vals);
	if (!singular(&vals)) {
		release_vals(&vals);
		if (!(pack->helper && safe)) {
			failed_to_find(r->sym_name);
			return -1;
		}

		if (debug >= 4) {
			printk("ksplice: reloc: deferred %s:%08lx to run-pre\n",
			       r->sym_name, r->blank_offset);
		}

		map = kmalloc(sizeof(*map), GFP_KERNEL);
		map->addr = blank_addr;
		map->nameval = find_nameval(pack, r->sym_name, 1);
		map->addend = r->addend;
		map->flags = r->flags;
		map->size = r->size;
		list_add(&map->list, pack->reloc_addrmaps);
		return 0;
	}
	sym_addr = list_entry(vals.next, struct candidate_val, list)->val;
	release_vals(&vals);

	if (debug >= 4) {
		printk("ksplice%s: reloc: %s:%08lx ",
		       (pack->helper ? "_h" : ""), r->sym_name,
		       r->blank_offset);
		printk("(S=%08lx A=%08lx ", sym_addr, r->addend);
	}

	if ((r->flags & PCREL) && (pack->helper && safe)) {
		map = kmalloc(sizeof(*map), GFP_KERNEL);
		map->addr = blank_addr;
		map->nameval = find_nameval(pack, "ksplice_zero", 1);
		map->nameval->val = 0;
		map->nameval->status = VAL;
		map->addend = sym_addr + r->addend;
		map->size = r->size;
		map->flags = r->flags;
		list_add(&map->list, pack->reloc_addrmaps);

	} else {
		long val;
		if (r->flags & PCREL) {
			val = sym_addr + r->addend - (unsigned long)blank_addr;
		} else {
			val = sym_addr + r->addend;
		}
		if (r->size == 4) {
			*(int *)blank_addr = val;
		} else if (r->size == 8) {
			*(long long *)blank_addr = val;
		} else {
			BUG();
		}
	}
	if (debug >= 4) {
		if (r->size == 4) {
			printk("aft=%08x)\n", *(int *)blank_addr);
		} else if (r->size == 8) {
			printk("aft=%016llx)\n", *(long long *)blank_addr);
		} else {
			BUG();
		}
	}
	return 0;
}

void compute_address(struct module_pack *pack, char *sym_name,
		     struct list_head *vals)
{
	int i, have_added_val = 0;
	const char *prefix[] = { ".text.", ".bss.", ".data.", NULL };

	if (!safe)
		return;

	if (!pack->helper) {
		struct reloc_nameval *nv = find_nameval(pack, sym_name, 0);
		if (nv != NULL && nv->status != NOVAL) {
			if (!have_added_val)
				release_vals(vals);
			have_added_val = 1;
			add_candidate_val(vals, nv->val);

			if (debug >= 1) {
				printk("ksplice: using detected sym %s=%08lx\n",
				       sym_name, nv->val);
			}
		}
	}
	if (have_added_val)
		return;

	if (starts_with(sym_name, ".rodata"))
		return;

#ifdef CONFIG_KALLSYMS
	kernel_lookup(sym_name, vals);
	other_module_lookup(sym_name, vals, pack->name);
#endif

	for (i = 0; prefix[i] != NULL; i++) {
		if (starts_with(sym_name, prefix[i])) {
			compute_address(pack, sym_name + strlen(prefix[i]),
					vals);
		}
	}
}

#ifdef KSPLICE_STANDALONE
#ifdef CONFIG_KALLSYMS
/* Modified version of Linux's kallsyms_lookup_name */
void kernel_lookup(const char *name_wlabel, struct list_head *vals)
{
	char namebuf[KSYM_NAME_LEN + 1];
	unsigned long i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	unsigned long off;
#endif /* LINUX_VERSION_CODE */

	const char *name = dup_wolabel(name_wlabel);

/*  kallsyms compression was added by 5648d78927ca65e74aadc88a2b1d6431e55e78ec
 *  2.6.10 was the first release after this commit
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	for (i = 0, off = 0; i < kallsyms_num_syms; i++) {
		off = ksplice_kallsyms_expand_symbol(off, namebuf);

		if (strcmp(namebuf, name) == 0) {
			add_candidate_val(vals, kallsyms_addresses[i]);
		}
	}
#else /* LINUX_VERSION_CODE */
	char *knames;

	for (i = 0, knames = kallsyms_names; i < kallsyms_num_syms; i++) {
		unsigned prefix = *knames++;

		strlcpy(namebuf + prefix, knames, KSYM_NAME_LEN - prefix);

		if (strcmp(namebuf, name) == 0) {
			add_candidate_val(vals, kallsyms_addresses[i]);
		}

		knames += strlen(knames) + 1;
	}
#endif /* LINUX_VERSION_CODE */

	kfree(name);
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

void other_module_lookup(const char *name_wlabel, struct list_head *vals,
			 const char *ksplice_name)
{
	struct module *m;
	const char *name = dup_wolabel(name_wlabel);

	list_for_each_entry(m, &(THIS_MODULE->list), list) {
		if (!starts_with(m->name, ksplice_name)
		    && !ends_with(m->name, "_helper")) {
			ksplice_mod_find_sym(m, name, vals);
		}
	}

	kfree(name);
}

/* Modified version of Linux's mod_find_symname */
void
ksplice_mod_find_sym(struct module *m, const char *name, struct list_head *vals)
{
	int i;
	if (strlen(m->name) <= 1)
		return;

	for (i = 0; i < m->num_symtab; i++) {
		const char *cursym_name = m->strtab + m->symtab[i].st_name;
		if (strncmp(cursym_name, name, strlen(name)) != 0)
			continue;

		cursym_name = dup_wolabel(cursym_name);
		if (strcmp(cursym_name, name) == 0 &&
		    m->symtab[i].st_value != 0) {

			add_candidate_val(vals, m->symtab[i].st_value);
		}
		kfree(cursym_name);
	}
}
#endif /* CONFIG_KALLSYMS */
#else /* KSPLICE_STANDALONE */
struct accumulate_struct {
	const char *desired_name;
	struct list_head *vals;
};

void accumulate_matching_names(void *data, const char *sym_name, long sym_val)
{
	struct accumulate_struct *acc = data;

	if (strncmp(sym_name, acc->desired_name, strlen(acc->desired_name)) !=
	    0)
		return;

	sym_name = dup_wolabel(sym_name);
	/* TODO: possibly remove "&& sym_val != 0" */
	if (strcmp(sym_name, acc->desired_name) == 0 && sym_val != 0) {
		add_candidate_val(acc->vals, sym_val);
	}
	kfree(sym_name);
}

void kernel_lookup(const char *name_wlabel, struct list_head *vals)
{
	struct accumulate_struct acc = { dup_wolabel(name_wlabel), vals };
	kallsyms_on_each_symbol(accumulate_matching_names, &acc);
	kfree(acc.desired_name);
}

void other_module_lookup(const char *name_wlabel, struct list_head *vals,
			 const char *ksplice_name)
{
	struct accumulate_struct acc = { dup_wolabel(name_wlabel), vals };
	struct module *m;

	list_for_each_entry(m, &(THIS_MODULE->list), list) {
		if (!starts_with(m->name, ksplice_name)
		    && !ends_with(m->name, "_helper")) {
			module_on_each_symbol(m, accumulate_matching_names,
					      &acc);
		}
	}

	kfree(acc.desired_name);
}
#endif /* KSPLICE_STANDALONE */

void add_candidate_val(struct list_head *vals, long val)
{
	struct candidate_val *tmp, *new;

	list_for_each_entry(tmp, vals, list) {
		if (tmp->val == val)
			return;
	}
	new = kmalloc(sizeof(*new), GFP_KERNEL);
	new->val = val;
	list_add(&new->list, vals);
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
		if (starts_with(newname, ".text.")) {
			newname += 6;
		}
		if (strcmp(newname, name) == 0) {
			return nv;
		}
	}
	if (!create)
		return NULL;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
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
		if (addr >= map->addr && addr < map->addr + map->size) {
			return map;
		}
	}
	return NULL;
}

void set_temp_myst_relocs(struct module_pack *pack, int status_val)
{
	struct reloc_nameval *nv;
	list_for_each_entry(nv, pack->reloc_namevals, list) {
		if (nv->status == TEMP) {
			nv->status = status_val;
		}
	}
}

int starts_with(const char *str, const char *prefix)
{
	return !strncmp(str, prefix, strlen(prefix));
}

int ends_with(const char *str, const char *suffix)
{
	return (strlen(str) > strlen(suffix)
		&& !strcmp(&str[strlen(str) - strlen(suffix)], suffix));
}

int label_offset(const char *sym_name)
{
	int i;
	for (i = 0;
	     sym_name[i] != 0 && sym_name[i + 1] != 0 && sym_name[i + 2] != 0
	     && sym_name[i + 3] != 0; i++) {
		if (sym_name[i] == '_' && sym_name[i + 1] == '_'
		    && sym_name[i + 2] == '_' && sym_name[i + 3] == '_') {
			return i + 4;
		}
	}
	return -1;
}

const char *dup_wolabel(const char *sym_name)
{
	int offset, entire_strlen, label_strlen, new_strlen;
	char *newstr;

	offset = label_offset(sym_name);
	if (offset == -1) {
		label_strlen = 0;
	} else {
		label_strlen = strlen(&sym_name[offset]) + strlen("____");
	}

	entire_strlen = strlen(sym_name);
	new_strlen = entire_strlen - label_strlen;
	newstr = kmalloc(new_strlen + 1, GFP_KERNEL);
	memcpy(newstr, sym_name, new_strlen);
	newstr[new_strlen] = 0;
	return newstr;
}

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jeffrey Brian Arnold <jbarnold@mit.edu>");
