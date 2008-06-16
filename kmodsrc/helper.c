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
#include "helper.h"
#include "jumps.h"
#include "nops.h"
#include <linux/kthread.h>

/* defined by modcommon.c */
extern int safe, debug;

/* defined by ksplice-create */
extern struct ksplice_reloc ksplice_init_relocs, ksplice_relocs;
extern struct ksplice_size ksplice_sizes;

#undef max
#define max(a, b) ((a) > (b) ? (a) : (b))

int init_module(void)
{
	int ret = 0;
	struct module_pack *pack = &KSPLICE_UNIQ(pack);

	pack->helper_relocs = &ksplice_relocs;
	pack->helper_sizes = &ksplice_sizes;

	if (process_ksplice_relocs(pack, &ksplice_init_relocs) != 0)
		return -1;
	safe = 1;

	printk("ksplice_h: Preparing and checking %s\n", pack->name);

	if (activate_helper(pack) != 0 || pack->activate_primary(pack) != 0)
		ret = -1;

	clear_list(pack->reloc_namevals, struct reloc_nameval, list);
	clear_list(pack->reloc_addrmaps, struct reloc_addrmap, list);
	if (pack->state == KSPLICE_PREPARING)
		clear_list(pack->safety_records, struct safety_record, list);

	return ret;
}

void cleanup_module(void)
{
}

/* old kernels do not have kcalloc */
#define kcalloc(n, size, flags) ksplice_kcalloc(n)

int activate_helper(struct module_pack *pack)
{
	struct ksplice_size *s;
	int i, record_count = 0, ret;
	char *finished;
	int numfinished, oldfinished = 0;
	int restart_count = 0, stage = 1;

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

		ret = search_for_match(pack, s, &stage);
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
		if (stage < 3) {
			stage++;
			goto start;
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

int search_for_match(struct module_pack *pack, struct ksplice_size *s,
		     int *stage)
{
	int i, saved_debug;
	long run_addr;
	LIST_HEAD(vals);
	struct candidate_val *v;

	for (i = 0; i < s->num_sym_addrs; i++) {
		add_candidate_val(&vals, s->sym_addrs[i]);
	}

	compute_address(pack, s->name, &vals);
	if (*stage <= 1 && !singular(&vals)) {
		release_vals(&vals);
		return 1;
	}

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

	if (*stage <= 2)
		return 1;

	saved_debug = debug;
	debug = 0;
	brute_search_all_mods(pack, s);
	debug = saved_debug;
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

int run_pre_cmp(struct module_pack *pack, long run_addr, long pre_addr,
		 int size, int rerun)
{
	int run_o = 0, pre_o = 0, lenient = 0, prev_c3 = 0, recent_5b = 0;
	unsigned char run, pre;
	struct reloc_addrmap *map;

	if (size == 0)
		return 1;

	while (run_o < size && pre_o < size) {
		if (lenient > 0)
			lenient--;
		if (prev_c3 > 0)
			prev_c3--;
		if (recent_5b > 0)
			recent_5b--;

		if (!virtual_address_mapped(run_addr + run_o))
			return 1;

		if ((map = find_addrmap(pack, pre_addr + pre_o)) != NULL) {
			if (handle_myst_reloc
			    (pre_addr, &pre_o, run_addr, &run_o, map,
			     rerun) == 1)
				return 1;
			continue;
		}

		if (match_nop(run_addr, &run_o) || match_nop(pre_addr, &pre_o))
			continue;

		run = *(unsigned char *)(run_addr + run_o);
		pre = *(unsigned char *)(pre_addr + pre_o);

		if (rerun)
			printk("%02x/%02x ", run, pre);

		if (run == pre) {
			if (pre == 0xc3)
				prev_c3 = 1 + 1;
			if (pre == 0x5b)
				recent_5b = 10 + 1;
			if (jumplen[pre])
				lenient = max(jumplen[pre] + 1, lenient);
			pre_o++, run_o++;
			continue;
		}

		if (prev_c3 && recent_5b)
			return 0;
		if (jumplen[run] && jumplen[pre]) {
			run_o += 1 + jumplen[run];
			pre_o += 1 + jumplen[pre];
			continue;
		}
		if (lenient) {
			pre_o++, run_o++;
			continue;
		}
		if (rerun) {
			printk("[p_o=%08x] ! %02x/%02x %02x/%02x",
			       pre_o,
			       *(unsigned char *)(run_addr + run_o + 1),
			       *(unsigned char *)(pre_addr + pre_o + 1),
			       *(unsigned char *)(run_addr + run_o + 2),
			       *(unsigned char *)(pre_addr + pre_o + 2));
		}
		return 1;
	}
	return 0;
}

int
handle_myst_reloc(long pre_addr, int *pre_o, long run_addr,
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

int match_nop(long addr, int *o)
{
	int i, j;
	struct insn *nop;
	for (i = NUM_NOPS - 1; i >= 0; i--) {
		nop = &nops[i];
		for (j = 0; j < nop->len; j++) {
			if (!virtual_address_mapped(addr + *o + j))
				break;
			if (*(unsigned char *)(addr + *o + j) != nop->data[j])
				break;
		}
		if (j == nop->len) {
			*o += j;
			return 1;
		}

	}
	return 0;
}

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
