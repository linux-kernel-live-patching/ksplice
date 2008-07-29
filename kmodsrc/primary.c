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

#ifdef KSPLICE_STANDALONE
#include "ksplice.h"
#else
#include <linux/ksplice.h>
#endif

#undef _STR
#define _STR(x) #x
#undef STR
#define STR(x) _STR(x)

extern const struct ksplice_reloc ksplice_relocs[], ksplice_relocs_end[];
extern const struct ksplice_size ksplice_sizes[], ksplice_sizes_end[];
extern struct ksplice_patch ksplice_patches[], ksplice_patches_end[];
extern const char ksplice_source_diff[], ksplice_source_diff_end[];
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
extern struct paravirt_patch_site parainstructions[], parainstructions_end[];
#endif

LIST_HEAD(reloc_addrmaps);
LIST_HEAD(reloc_namevals);
LIST_HEAD(safety_records);

static int debug;
module_param(debug, int, 0600);
MODULE_PARM_DESC(debug, "Debug level");

#define pack KSPLICE_UNIQ(pack)
struct module_pack pack = {
	.name = "ksplice_" STR(KSPLICE_MID),
	.kid = STR(KSPLICE_KID),
#ifdef KSPLICE_TARGET
	.target_name = STR(KSPLICE_TARGET),
#else
	.target_name = NULL,
#endif
	.target = NULL,
	.map_printk = MAP_PRINTK,
	.primary = THIS_MODULE,
	.primary_relocs = ksplice_relocs,
	.primary_relocs_end = ksplice_relocs_end,
	.primary_sizes = ksplice_sizes,
	.primary_sizes_end = ksplice_sizes_end,
	.patches = ksplice_patches,
	.patches_end = ksplice_patches_end,
	.source_diff = ksplice_source_diff,
	.source_diff_end = ksplice_source_diff_end,
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	.primary_parainstructions = parainstructions,
	.primary_parainstructions_end = parainstructions_end,
#endif
	.reloc_addrmaps = &reloc_addrmaps,
	.reloc_namevals = &reloc_namevals,
	.safety_records = &safety_records,
};
EXPORT_SYMBOL_GPL(pack);

static int init_primary(void)
{
	pack.debug = &debug;
	return 0;
}

static void cleanup_primary(void)
{
	cleanup_ksplice_module(&pack);
}

#define helper_init_module KSPLICE_UNIQ(helper_init_module)
int helper_init_module(void)
{
	return init_ksplice_module(&pack);
}
EXPORT_SYMBOL_GPL(helper_init_module);

module_init(init_primary);
module_exit(cleanup_primary);

MODULE_AUTHOR("Jeffrey Brian Arnold <jbarnold@mit.edu>");
MODULE_DESCRIPTION("Ksplice rebootless update primary module");
#ifdef KSPLICE_VERSION
MODULE_VERSION(KSPLICE_VERSION);
#endif
MODULE_LICENSE("GPL v2");
