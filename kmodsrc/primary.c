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

#define _PASTE(x,y) x##y
#define PASTE(x,y) _PASTE(x,y)
#define KSPLICE_UNIQ(s) PASTE(s##_,KSPLICE_ID)

extern struct ksplice_reloc ksplice_relocs;
extern struct ksplice_size ksplice_sizes;
extern struct ksplice_patch ksplice_patches;

LIST_HEAD(reloc_addrmaps);
LIST_HEAD(reloc_namevals);
LIST_HEAD(safety_records);

#define primary_pack KSPLICE_UNIQ(primary_pack)

struct module_pack pack = {
	.name = "ksplice_" STR(KSPLICE_ID),
	.map_printk = MAP_PRINTK,
	.primary_relocs = &ksplice_relocs,
	.primary_sizes = &ksplice_sizes,
	.patches = &ksplice_patches,
	.reloc_addrmaps = &reloc_addrmaps,
	.reloc_namevals = &reloc_namevals,
	.safety_records = &safety_records,
	.activate_primary = &activate_primary,
};

int init_module(void)
{
	return 0;
}

void cleanup_module(void)
{
	cleanup_ksplice_module(&pack);
}

int KSPLICE_UNIQ(helper_init_module) (struct ksplice_reloc * helper_relocs,
				      struct ksplice_size * helper_sizes) {
	pack.helper_relocs = helper_relocs;
	pack.helper_sizes = helper_sizes;
	return init_ksplice_module(&pack);
}

EXPORT_SYMBOL_GPL(KSPLICE_UNIQ(helper_init_module));
