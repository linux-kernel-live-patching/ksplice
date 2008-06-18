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
#include <linux/kallsyms.h>
#include <linux/stop_machine.h>

#ifdef CONFIG_KALLSYMS
static const int CONFIG_KALLSYMS_VAL = 1;
extern unsigned long kallsyms_addresses[], kallsyms_num_syms;
extern u8 kallsyms_names[];
#else
static const int CONFIG_KALLSYMS_VAL = 0;
#endif

/* defined by ksplice-create */
extern struct ksplice_reloc ksplice_init_relocs, ksplice_relocs;

static int safe = 0, helper = 0;
int debug;
module_param(debug, int, 0600);

int process_ksplice_relocs(int caller_is_helper)
{
	struct ksplice_reloc *r;
	helper = caller_is_helper;
	for (r = &ksplice_init_relocs; r->sym_name != NULL; r++) {
		if (process_reloc(r) != 0)
			return -1;
	}
	safe = 1;
	for (r = &ksplice_relocs; r->sym_name != NULL; r++) {
		if (process_reloc(r) != 0)
			return -1;
	}
	return 0;
}

int process_reloc(struct ksplice_reloc *r)
{
	int i;
	long sym_addr;
	struct reloc_addrmap *map;

#define blank_addr (r->blank_sect_addr+r->blank_offset)

	LIST_HEAD(vals);
	if (CONFIG_KALLSYMS_VAL || !safe) {
		for (i = 0; i < r->num_sym_addrs; i++) {
			int adjustment = (long)printk - map_printk;
			if (adjustment & 0xfffff) {
				print_abort("System.map does not match kernel");
				return -1;
			}
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
			     (helper ? "_h" : ""), r->sym_name,
			     r->blank_offset);
		}
		release_vals(&vals);
		return 0;
	}

	compute_address(r->sym_name, &vals);
	if (!singular(&vals)) {
		release_vals(&vals);
		if (!(helper && safe)) {
			failed_to_find(r->sym_name);
			return -1;
		}

		if (debug >= 4) {
			printk("ksplice: reloc: deferred %s:%08lx to run-pre\n",
			       r->sym_name, r->blank_offset);
		}

		map = kmalloc(sizeof(*map), GFP_KERNEL);
		map->addr = blank_addr;
		map->nameval = find_nameval(r->sym_name, 1);
		map->addend = r->addend;
		map->flags = r->flags;
		map->size = r->size;
		list_add(&map->list, &reloc_addrmaps);
		return 0;
	}
	sym_addr = list_entry(vals.next, struct candidate_val, list)->val;
	release_vals(&vals);

	if (debug >= 4) {
		printk("ksplice%s: reloc: %s:%08lx ",
		       (helper ? "_h" : ""), r->sym_name, r->blank_offset);
		printk("(S=%08lx A=%08lx ", sym_addr, r->addend);
	}

	if ((r->flags & PCREL) && (helper && safe)) {
		map = kmalloc(sizeof(*map), GFP_KERNEL);
		map->addr = blank_addr;
		map->nameval = find_nameval("ksplice_zero", 1);
		map->nameval->val = 0;
		map->nameval->status = VAL;
		map->addend = sym_addr + r->addend;
		map->flags = r->flags;
		map->size = r->size;
		list_add(&map->list, &reloc_addrmaps);

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

void compute_address(char *sym_name, struct list_head *vals)
{
	int i, have_added_val = 0;
	const char *prefix[] = { ".text.", ".bss.", ".data.", NULL };

	if (!safe)
		return;

	if (!(helper && safe)) {
		struct reloc_nameval *nv = find_nameval(sym_name, 0);
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
	other_module_lookup(sym_name, vals);
#endif

	for (i = 0; prefix[i] != NULL; i++) {
		if (starts_with(sym_name, prefix[i])) {
			compute_address(sym_name + strlen(prefix[i]), vals);
		}
	}
}

#ifdef CONFIG_KALLSYMS
/* Modified version of Linux's kallsyms_lookup_name */
void kernel_lookup(const char *name_wlabel, struct list_head *vals)
{
	char namebuf[KSYM_NAME_LEN + 1];
	unsigned long i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	unsigned long off;
#endif

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
#else
	char *knames;

	for (i = 0, knames = kallsyms_names; i < kallsyms_num_syms; i++) {
		unsigned prefix = *knames++;

		strlcpy(namebuf + prefix, knames, KSYM_NAME_LEN - prefix);

		if (strcmp(namebuf, name) == 0) {
			add_candidate_val(vals, kallsyms_addresses[i]);
		}

		knames += strlen(knames) + 1;
	}
#endif

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

void other_module_lookup(const char *name_wlabel, struct list_head *vals)
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

struct reloc_nameval *find_nameval(char *name, int create)
{
	struct list_head *pos;
	struct reloc_nameval *nv, *new;
	char *newname;
	list_for_each(pos, &reloc_namevals) {
		nv = list_entry(pos, struct reloc_nameval, list);
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
	list_add(&new->list, &reloc_namevals);
	return new;
}

struct reloc_addrmap *find_addrmap(long addr)
{
	struct list_head *pos;
	struct reloc_addrmap *map;
	list_for_each(pos, &reloc_addrmaps) {
		map = list_entry(pos, struct reloc_addrmap, list);
		if (addr >= map->addr && addr < map->addr + map->size) {
			return map;
		}
	}
	return NULL;
}

void set_temp_myst_relocs(int status_val)
{
	struct list_head *pos;
	struct reloc_nameval *nv;
	list_for_each(pos, &reloc_namevals) {
		nv = list_entry(pos, struct reloc_nameval, list);
		if (nv->status == TEMP) {
			nv->status = status_val;
		}
	}
}
