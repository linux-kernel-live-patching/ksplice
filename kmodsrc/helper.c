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

#define _PASTE(x, y) x##y
#define PASTE(x, y) _PASTE(x, y)
#define KSPLICE_UNIQ(s) PASTE(s##_, KSPLICE_ID)

extern const struct ksplice_reloc ksplice_relocs[], ksplice_relocs_end[];
extern const struct ksplice_size ksplice_sizes[], ksplice_sizes_end[];
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
extern struct paravirt_patch_site parainstructions[], parainstructions_end[];
#endif

/* Defined in primary.c */
#define pack KSPLICE_UNIQ(pack)
extern struct module_pack pack;
#define helper_init_module KSPLICE_UNIQ(helper_init_module)
extern int helper_init_module(void);

static int init_helper(void)
{
	pack.helper_relocs = ksplice_relocs;
	pack.helper_relocs_end = ksplice_relocs_end;
	pack.helper_sizes = ksplice_sizes;
	pack.helper_sizes_end = ksplice_sizes_end;
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	pack.helper_parainstructions = parainstructions;
	pack.helper_parainstructions_end = parainstructions_end;
#endif
	return helper_init_module();
}

static void cleanup_helper(void)
{
}

module_init(init_helper);
module_exit(cleanup_helper);

MODULE_AUTHOR("Jeffrey Brian Arnold <jbarnold@mit.edu>");
MODULE_DESCRIPTION("Ksplice rebootless update helper module");
#ifdef KSPLICE_VERSION
MODULE_VERSION(KSPLICE_VERSION);
#endif
MODULE_LICENSE("GPL v2");
