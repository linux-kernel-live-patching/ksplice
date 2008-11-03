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

#ifdef KSPLICE_STANDALONE
#include "ksplice.h"
#else
#include <linux/ksplice.h>
#endif

extern struct ksplice_reloc ksplice_relocs[], ksplice_relocs_end[];
extern const struct ksplice_section ksplice_sections[], ksplice_sections_end[];
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
extern struct ksplice_system_map ksplice_system_map[],
    ksplice_system_map_end[];
#endif /* KSPLICE_STANDALONE */

#define pack KSPLICE_UNIQ(pack)
struct ksplice_pack pack = {
	.name = "ksplice_" __stringify(KSPLICE_MID),
	.kid = __stringify(KSPLICE_KID),
	.target_name = __stringify(KSPLICE_TARGET),
#ifdef KSPLICE_STANDALONE
	.map_printk = MAP_PRINTK,
#endif /* KSPLICE_STANDALONE */
	.primary = THIS_MODULE,
	.primary_relocs = ksplice_relocs,
	.primary_relocs_end = ksplice_relocs_end,
	.primary_sections = ksplice_sections,
	.primary_sections_end = ksplice_sections_end,
	.primary_symbols = ksplice_symbols,
	.primary_symbols_end = ksplice_symbols_end,
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
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	.primary_parainstructions = parainstructions,
	.primary_parainstructions_end = parainstructions_end,
#endif
#ifdef KSPLICE_STANDALONE
	.primary_system_map = ksplice_system_map,
	.primary_system_map_end = ksplice_system_map_end,
#endif /* KSPLICE_STANDALONE */
};
EXPORT_SYMBOL_GPL(pack);

static int init_primary(void)
{
	return 0;
}

static void cleanup_primary(void)
{
	cleanup_ksplice_pack(&pack);
}

module_init(init_primary);
module_exit(cleanup_primary);

MODULE_AUTHOR("Jeffrey Brian Arnold <jbarnold@mit.edu>");
MODULE_DESCRIPTION("Ksplice rebootless update primary module");
#ifdef KSPLICE_VERSION
MODULE_VERSION(KSPLICE_VERSION);
#endif
MODULE_LICENSE("GPL v2");
