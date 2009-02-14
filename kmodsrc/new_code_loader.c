/*  Copyright (C) 2007-2009  Ksplice, Inc.
 *  Authors: Jeff Arnold, Anders Kaseorg, Tim Abbott
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

#ifdef KSPLICE_STANDALONE
#include "ksplice.h"
#else
#include <linux/ksplice.h>
#endif

extern struct ksplice_reloc ksplice_relocs[], ksplice_relocs_end[];
extern struct ksplice_section ksplice_sections[], ksplice_sections_end[];
extern struct ksplice_symbol ksplice_symbols[], ksplice_symbols_end[];
extern struct ksplice_patch ksplice_patches[], ksplice_patches_end[];
extern const typeof(int (*)(void)) ksplice_call_pre_apply[],
    ksplice_call_pre_apply_end[], ksplice_call_check_apply[],
    ksplice_call_check_apply_end[];
extern const typeof(void (*)(void)) ksplice_call_apply[],
    ksplice_call_apply_end[], ksplice_call_post_apply[],
    ksplice_call_post_apply_end[], ksplice_call_fail_apply[],
    ksplice_call_fail_apply_end[];
extern const typeof(int (*)(void)) ksplice_call_pre_reverse[],
    ksplice_call_pre_reverse_end[], ksplice_call_check_reverse[],
    ksplice_call_check_reverse_end[];
extern const typeof(void (*)(void)) ksplice_call_reverse[],
    ksplice_call_reverse_end[], ksplice_call_post_reverse[],
    ksplice_call_post_reverse_end[], ksplice_call_fail_reverse[],
    ksplice_call_fail_reverse_end[];

#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
extern struct paravirt_patch_site parainstructions[], parainstructions_end[];
#endif
#ifdef KSPLICE_STANDALONE
extern struct ksplice_system_map ksplice_system_map[], ksplice_system_map_end[];
#endif /* KSPLICE_STANDALONE */

#define change KSPLICE_UNIQ(change)
struct ksplice_mod_change change = {
	.name = "ksplice_" __stringify(KSPLICE_MID),
	.kid = __stringify(KSPLICE_KID),
	.target_name = __stringify(KSPLICE_TARGET),
#ifdef KSPLICE_STANDALONE
	.map_printk = MAP_PRINTK,
#endif /* KSPLICE_STANDALONE */
	.new_code_mod = THIS_MODULE,
	.new_code = {
		.relocs = ksplice_relocs,
		.relocs_end = ksplice_relocs_end,
		.sections = ksplice_sections,
		.sections_end = ksplice_sections_end,
		.symbols = ksplice_symbols,
		.symbols_end = ksplice_symbols_end,
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
		.parainstructions = parainstructions,
		.parainstructions_end = parainstructions_end,
#endif
#ifdef KSPLICE_STANDALONE
		.system_map = ksplice_system_map,
		.system_map_end = ksplice_system_map_end,
#endif /* KSPLICE_STANDALONE */
	},
	.patches = ksplice_patches,
	.patches_end = ksplice_patches_end,
	.pre_apply = ksplice_call_pre_apply,
	.pre_apply_end = ksplice_call_pre_apply_end,
	.check_apply = ksplice_call_check_apply,
	.check_apply_end = ksplice_call_check_apply_end,
	.apply = ksplice_call_apply,
	.apply_end = ksplice_call_apply_end,
	.post_apply = ksplice_call_post_apply,
	.post_apply_end = ksplice_call_post_apply_end,
	.fail_apply = ksplice_call_fail_apply,
	.fail_apply_end = ksplice_call_fail_apply_end,
	.pre_reverse = ksplice_call_pre_reverse,
	.pre_reverse_end = ksplice_call_pre_reverse_end,
	.check_reverse = ksplice_call_check_reverse,
	.check_reverse_end = ksplice_call_check_reverse_end,
	.reverse = ksplice_call_reverse,
	.reverse_end = ksplice_call_reverse_end,
	.post_reverse = ksplice_call_post_reverse,
	.post_reverse_end = ksplice_call_post_reverse_end,
	.fail_reverse = ksplice_call_fail_reverse,
	.fail_reverse_end = ksplice_call_fail_reverse_end,
};
EXPORT_SYMBOL_GPL(change);

static int init_primary(void)
{
	return 0;
}

static void cleanup_primary(void)
{
	cleanup_ksplice_mod_change(&change);
}

module_init(init_primary);
module_exit(cleanup_primary);

MODULE_AUTHOR("Ksplice, Inc.");
MODULE_DESCRIPTION("Ksplice rebootless update primary module");
#ifdef KSPLICE_VERSION
MODULE_VERSION(KSPLICE_VERSION);
#endif
MODULE_LICENSE("GPL v2");
