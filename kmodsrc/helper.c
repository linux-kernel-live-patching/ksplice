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
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
extern struct paravirt_patch_site parainstructions[], parainstructions_end[];
#endif
#ifdef KSPLICE_STANDALONE
extern struct ksplice_system_map ksplice_system_map[],
    ksplice_system_map_end[];
#endif /* KSPLICE_STANDALONE */

/* Defined in primary.c */
#define change KSPLICE_UNIQ(change)
extern struct ksplice_mod_change change;

#define PTR(p) ({ static const volatile typeof(&*p) p##_ptr = p; p##_ptr; })

static int init_helper(void)
{
	change.helper_relocs = PTR(ksplice_relocs);
	change.helper_relocs_end = PTR(ksplice_relocs_end);
	change.helper_sections = PTR(ksplice_sections);
	change.helper_sections_end = PTR(ksplice_sections_end);
	change.helper_symbols = PTR(ksplice_symbols);
	change.helper_symbols_end = PTR(ksplice_symbols_end);
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	change.helper_parainstructions = PTR(parainstructions);
	change.helper_parainstructions_end = PTR(parainstructions_end);
#endif
#ifdef KSPLICE_STANDALONE
	change.helper_system_map = PTR(ksplice_system_map);
	change.helper_system_map_end = PTR(ksplice_system_map_end);
#endif /* KSPLICE_STANDALONE */
	return init_ksplice_mod_change(&change);
}

static void cleanup_helper(void)
{
	cleanup_ksplice_mod_change(&change);
}

module_init(init_helper);
module_exit(cleanup_helper);

MODULE_AUTHOR("Ksplice, Inc.");
MODULE_DESCRIPTION("Ksplice rebootless update helper module");
#ifdef KSPLICE_VERSION
MODULE_VERSION(KSPLICE_VERSION);
#endif
MODULE_LICENSE("GPL v2");
