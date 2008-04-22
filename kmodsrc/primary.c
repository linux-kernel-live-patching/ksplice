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
#include <linux/stop_machine.h>
#include <linux/proc_fs.h>
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

struct reloc_addrmap *reloc_addrmaps = NULL;
struct reloc_nameval *reloc_namevals = NULL;
struct safety_record *safety_records = NULL;
EXPORT_SYMBOL(reloc_addrmaps);
EXPORT_SYMBOL(reloc_namevals);
EXPORT_SYMBOL(safety_records);

static int applied = 0;
static struct safety_record *local_safety;

int
init_module(void)
{
	return 0;
}

void
cleanup_module(void)
{
	remove_proc_entry(ksplice_name, &proc_root);
}

int
ksplice_do_primary(void)
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

	local_safety = safety_records;

	for (i = 0; !applied && i < 10; i++) {
		stop_machine_run(__apply_patches, NULL, NR_CPUS);
	}
	if (!applied) {
		remove_proc_entry(ksplice_name, &proc_root);
		print_abort("stack check: to-be-replaced code is busy");
		return -1;
	}

	printk("ksplice: Update %s applied successfully\n", ksplice_name);
	return 0;
}

EXPORT_SYMBOL(ksplice_do_primary);

int
resolve_patch_symbols(void)
{
	struct ksplice_patch *p;
	struct ansglob *glob = NULL;

	for (p = &ksplice_patches; p->oldstr; p++) {
		p->saved = kmalloc(5, GFP_KERNEL);

		if (p->oldaddr != 0)
			add2glob(&glob, p->oldaddr);

		compute_address(p->oldstr, &glob);
		if (!singular(glob)) {
			release(&glob);
			failed_to_find(p->oldstr);
			return -1;
		}
		p->oldaddr = glob->val;
		release(&glob);
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

	for (i = 0; applied && i < 10; i++) {
		stop_machine_run(__reverse_patches, NULL, NR_CPUS);
	}
	if (applied)
		print_abort("stack check: to-be-reversed code is busy");

	return count;
}

int
__apply_patches(void *unused)
{
	struct ksplice_patch *p;

	struct safety_record *r = local_safety;
	for (; r != NULL; r = r->next) {
		for (p = &ksplice_patches; p->oldstr; p++) {
			if (p->oldaddr == r->addr) {
				r->care = 1;
			}
		}
	}

	if (ksplice_on_each_task(check_task, NULL) != 0)
		return 0;

	if (!try_module_get(THIS_MODULE))
		return 0;

	applied = 1;
	safety_records = NULL;

	for (p = &ksplice_patches; p->oldstr; p++) {
		memcpy((void *) p->saved, (void *) p->oldaddr, 5);
		*((u8 *) p->oldaddr) = 0xE9;
		*((u32 *) (p->oldaddr + 1)) = p->repladdr - (p->oldaddr + 5);
	}
	return 0;
}

int
__reverse_patches(void *unused)
{
	struct ksplice_patch *p;

	if (!applied)
		return 0;

	if (ksplice_on_each_task(check_task, NULL) != 0)
		return 0;

	release_list((struct starts_with_next *) local_safety);
	applied = 0;
	module_put(THIS_MODULE);

	p = &ksplice_patches;
	for (; p->oldstr; p++) {
		memcpy((void *) p->oldaddr, (void *) p->saved, 5);
		kfree(p->saved);
		*((u8 *) p->repladdr) = 0xE9;
		*((u32 *) (p->repladdr + 1)) = p->oldaddr - (p->repladdr + 5);
	}

	printk("ksplice: Update %s reversed successfully\n", ksplice_name);
	return 0;
}

/* Modified version of proposed Linux function on_each_task */
int
ksplice_on_each_task(int (*func) (struct task_struct * t, void *d), void *data)
{
	struct task_struct *g, *p;
	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
		/* do_each_thread is a double loop! */
		if (func(p, data) != 0) {
			read_unlock(&tasklist_lock);
			return -1;
		}
	}
	while_each_thread(g, p);
	read_unlock(&tasklist_lock);
	return 0;
}

int
check_task(struct task_struct *t, void *d)
{
	long addr = KSPLICE_EIP(t);
	int conflict = check_address_for_conflict(&addr);
	if (debug >= 2) {
		printk("ksplice: stack check: pid %d eip %08lx",
		       t->pid, KSPLICE_EIP(t));
		if (conflict)
			printk(" [<-- CONFLICT]: ");
		else
			printk(": ");
	}
	if (conflict)
		return -1;

	return check_stack(task_thread_info(t), (long *) KSPLICE_ESP(t));
}

/* Modified version of Linux's print_context_stack */
int
check_stack(struct thread_info *tinfo, long *stack)
{
	int conflict;
	long *addr = kmalloc(sizeof (*addr), GFP_KERNEL);

	while (valid_stack_ptr(tinfo, stack)) {
		*addr = *stack++;
		if (__kernel_text_address(*addr)) {
			conflict = check_address_for_conflict(addr);
			if (debug >= 2) {
				printk("%08lx ", *addr);
				if (conflict)
					printk("[<-- CONFLICT]\n");
			}
			if (conflict) {
				kfree(addr);
				return -1;
			}
		}
	}
	if (debug >= 2)
		printk("ok\n");

	kfree(addr);
	return 0;
}

int
check_address_for_conflict(long *addr)
{
	struct safety_record *r = local_safety;
	struct ksplice_size *s = &ksplice_sizes;

	for (; r != NULL; r = r->next) {
		if (r->care == 1 && *addr > r->addr
		    && *addr <= (r->addr + r->size)) {
			return -1;
		}
	}
	for (; applied && s->name != NULL; s++) {
		if (*addr > s->thismod_addr
		    && *addr <= (s->thismod_addr + s->size)) {
			return -1;
		}
	}

	return 0;
}

/* Modified version of Linux's valid_stack_ptr */
int
valid_stack_ptr(struct thread_info *tinfo, void *p)
{
	return p > (void *) tinfo && p < (void *) tinfo + THREAD_SIZE - 3;
}
