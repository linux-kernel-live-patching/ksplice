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
#define pack KSPLICE_UNIQ(pack)
extern struct ksplice_pack pack;

#define PTR(p) ({ static const volatile typeof(&*p) p##_ptr = p; p##_ptr; })

static int init_helper(void)
{
	pack.helper_relocs = PTR(ksplice_relocs);
	pack.helper_relocs_end = PTR(ksplice_relocs_end);
	pack.helper_sections = PTR(ksplice_sections);
	pack.helper_sections_end = PTR(ksplice_sections_end);
	pack.helper_symbols = PTR(ksplice_symbols);
	pack.helper_symbols_end = PTR(ksplice_symbols_end);
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	pack.helper_parainstructions = PTR(parainstructions);
	pack.helper_parainstructions_end = PTR(parainstructions_end);
#endif
#ifdef KSPLICE_STANDALONE
	pack.helper_system_map = PTR(ksplice_system_map);
	pack.helper_system_map_end = PTR(ksplice_system_map_end);
#endif /* KSPLICE_STANDALONE */
	return init_ksplice_pack(&pack);
}

static void cleanup_helper(void)
{
	cleanup_ksplice_pack(&pack);
}

module_init(init_helper);
module_exit(cleanup_helper);

MODULE_AUTHOR("Jeffrey Brian Arnold <jbarnold@mit.edu>");
MODULE_DESCRIPTION("Ksplice rebootless update helper module");
#ifdef KSPLICE_VERSION
MODULE_VERSION(KSPLICE_VERSION);
#endif
MODULE_LICENSE("GPL v2");
