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

#include "modcommon.h"
#include "primary.h"
#include <linux/kthread.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/stop_machine.h>
#include <linux/time.h>
#include <asm/uaccess.h>

#ifndef task_thread_info
#define task_thread_info(task) (task)->thread_info
#endif

/* Probably wrong. */
#ifdef __ASM_X86_PROCESSOR_H
#define KSPLICE_EIP(x) ((x)->thread.ip)
#define KSPLICE_ESP(x) ((x)->thread.sp)
#elif BITS_PER_LONG == 32
#define KSPLICE_EIP(x) ((x)->thread.eip)
#define KSPLICE_ESP(x) ((x)->thread.esp)
#elif BITS_PER_LONG == 64
#define KSPLICE_EIP(x) (KSTK_EIP(x))
#define KSPLICE_ESP(x) ((x)->thread.rsp)
#endif

/* defined by modcommon.c */
extern int debug;

/* defined by ksplice-create */
extern struct ksplice_patch ksplice_patches;
extern struct ksplice_size ksplice_sizes;

LIST_HEAD(reloc_addrmaps);
LIST_HEAD(reloc_namevals);
LIST_HEAD(safety_records);
EXPORT_SYMBOL(reloc_addrmaps);
EXPORT_SYMBOL(reloc_namevals);
EXPORT_SYMBOL(safety_records);

enum ksplice_state_enum ksplice_state = KSPLICE_PREPARING;
EXPORT_SYMBOL(ksplice_state);

int init_module(void)
{
	return 0;
}

void cleanup_module(void)
{
	remove_proc_entry(ksplice_name, &proc_root);
}

int activate_primary(void)
{
	int i;
	struct proc_dir_entry *proc_entry;

	if (process_ksplice_relocs(0) != 0)
		return -1;

	if (resolve_patch_symbols() != 0)
		return -1;

	proc_entry = create_proc_entry(ksplice_name, 0644, NULL);
	if (proc_entry == NULL) {
		remove_proc_entry(ksplice_name, &proc_root);
		print_abort("primary module: could not create proc entry");
		return -1;
	}

	proc_entry->read_proc = procfile_read;
	proc_entry->write_proc = procfile_write;
	proc_entry->owner = THIS_MODULE;
	proc_entry->mode = S_IFREG | S_IRUSR | S_IWUSR;
	proc_entry->uid = 0;
	proc_entry->gid = 0;
	proc_entry->size = 0;

	for (i = 0; ksplice_state != KSPLICE_APPLIED && i < 5; i++) {
		bust_spinlocks(1);
		stop_machine_run(__apply_patches, NULL, NR_CPUS);
		bust_spinlocks(0);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
	}
	if (ksplice_state != KSPLICE_APPLIED) {
		remove_proc_entry(ksplice_name, &proc_root);
		print_abort("stack check: to-be-replaced code is busy");
		return -1;
	}

	printk("ksplice: Update %s applied successfully\n", ksplice_name);
	return 0;
}

EXPORT_SYMBOL(activate_primary);

int resolve_patch_symbols(void)
{
	struct ksplice_patch *p;
	LIST_HEAD(vals);

	for (p = &ksplice_patches; p->oldstr; p++) {
		p->saved = kmalloc(5, GFP_KERNEL);

		if (p->oldaddr != 0)
			add_candidate_val(&vals, p->oldaddr);

		compute_address(p->oldstr, &vals);
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

int
procfile_read(char *buffer,
	      char **buffer_location,
	      off_t offset, int buffer_length, int *eof, void *data)
{
	return 0;
}

int
procfile_write(struct file *file, const char *buffer, unsigned long count,
	       void *data)
{
	int i;
	printk("ksplice: Preparing to reverse %s\n", ksplice_name);

	for (i = 0; ksplice_state == KSPLICE_APPLIED && i < 5; i++) {
		bust_spinlocks(1);
		stop_machine_run(__reverse_patches, NULL, NR_CPUS);
		bust_spinlocks(0);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
	}
	if (ksplice_state == KSPLICE_APPLIED)
		print_abort("stack check: to-be-reversed code is busy");

	return count;
}

int __apply_patches(void *unused)
{
	struct ksplice_patch *p;
	struct list_head *pos;
	struct safety_record *rec;

	list_for_each(pos, &safety_records) {
		rec = list_entry(pos, struct safety_record, list);
		for (p = &ksplice_patches; p->oldstr; p++) {
			if (p->oldaddr == rec->addr) {
				rec->care = 1;
			}
		}
	}

	if (check_each_task() != 0)
		return 0;

	if (!try_module_get(THIS_MODULE))
		return 0;

	ksplice_state = KSPLICE_APPLIED;

	for (p = &ksplice_patches; p->oldstr; p++) {
		memcpy((void *)p->saved, (void *)p->oldaddr, 5);
		*((u8 *) p->oldaddr) = 0xE9;
		*((u32 *) (p->oldaddr + 1)) = p->repladdr - (p->oldaddr + 5);
	}
	return 0;
}

int __reverse_patches(void *unused)
{
	struct ksplice_patch *p;
	struct list_head *pos, *n;

	if (ksplice_state != KSPLICE_APPLIED)
		return 0;

	if (check_each_task() != 0)
		return 0;

	clear_list(&safety_records, struct safety_record, list);
	ksplice_state = KSPLICE_REVERSED;
	module_put(THIS_MODULE);

	p = &ksplice_patches;
	for (; p->oldstr; p++) {
		memcpy((void *)p->oldaddr, (void *)p->saved, 5);
		kfree(p->saved);
		*((u8 *) p->repladdr) = 0xE9;
		*((u32 *) (p->repladdr + 1)) = p->oldaddr - (p->repladdr + 5);
	}

	printk("ksplice: Update %s reversed successfully\n", ksplice_name);
	return 0;
}

int check_each_task(void)
{
	struct task_struct *g, *p;
	int status = 0;
	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
		/* do_each_thread is a double loop! */
		if (check_task(p) != 0) {
			if (debug == 1) {
				debug = 2;
				check_task(p);
				debug = 1;
			}
			status = -1;
		}
	}
	while_each_thread(g, p);
	read_unlock(&tasklist_lock);
	return status;
}

int check_task(struct task_struct *t)
{
	int status;
	long addr = KSPLICE_EIP(t);
	int conflict = check_address_for_conflict(addr);
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
		    check_stack(task_thread_info(t),
				(long *)__builtin_frame_address(0));
	} else if (!task_curr(t)) {
		status =
		    check_stack(task_thread_info(t), (long *)KSPLICE_ESP(t));
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
int check_stack(struct thread_info *tinfo, long *stack)
{
	int conflict, status = 0;
	long addr;

	while (valid_stack_ptr(tinfo, stack)) {
		addr = *stack++;
		if (__kernel_text_address(addr)) {
			conflict = check_address_for_conflict(addr);
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

int check_address_for_conflict(long addr)
{
	struct ksplice_size *s = &ksplice_sizes;
	struct list_head *pos;
	struct safety_record *rec;

	list_for_each(pos, &safety_records) {
		rec = list_entry(pos, struct safety_record, list);
		if (rec->care == 1 && addr > rec->addr
		    && addr <= (rec->addr + rec->size)) {
			return -1;
		}
	}
	for (; ksplice_state == KSPLICE_APPLIED && s->name != NULL; s++) {
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
