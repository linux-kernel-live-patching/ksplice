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

#include "ksplice.h"

MODULE_LICENSE("GPL v2");

#define _STR(x) #x
#define STR(x) _STR(x)

#define _PASTE(x, y) x##y
#define PASTE(x, y) _PASTE(x, y)
#define KSPLICE_UNIQ(s) PASTE(s##_, KSPLICE_ID)

extern const struct ksplice_reloc ksplice_relocs[], ksplice_relocs_end[];
extern const struct ksplice_size ksplice_sizes[], ksplice_sizes_end[];
extern struct ksplice_patch ksplice_patches[], ksplice_patches_end[];
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
extern struct paravirt_patch_site parainstructions[], parainstructions_end[];
#endif

LIST_HEAD(reloc_addrmaps);
LIST_HEAD(reloc_namevals);
LIST_HEAD(safety_records);

#define pack KSPLICE_UNIQ(pack)
struct module_pack pack = {
	.name = "ksplice_" STR(KSPLICE_ID),
#ifdef KSPLICE_TARGET
	.target = STR(KSPLICE_TARGET),
#else
	.target = NULL,
#endif
	.map_printk = MAP_PRINTK,
	.primary = THIS_MODULE,
	.primary_relocs = ksplice_relocs,
	.primary_relocs_end = ksplice_relocs_end,
	.primary_sizes = ksplice_sizes,
	.primary_sizes_end = ksplice_sizes_end,
	.patches = ksplice_patches,
	.patches_end = ksplice_patches_end,
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	.primary_parainstructions = parainstructions,
	.primary_parainstructions_end = parainstructions_end,
#endif
	.reloc_addrmaps = &reloc_addrmaps,
	.reloc_namevals = &reloc_namevals,
	.safety_records = &safety_records,
};
EXPORT_SYMBOL_GPL(pack);

int init_module(void)
{
	return 0;
}

void cleanup_module(void)
{
	cleanup_ksplice_module(&pack);
}

#define helper_init_module KSPLICE_UNIQ(helper_init_module)
int helper_init_module(void)
{
	return init_ksplice_module(&pack);
}
EXPORT_SYMBOL_GPL(helper_init_module);
