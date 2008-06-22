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

#define _PASTE(x, y) x##y
#define PASTE(x, y) _PASTE(x, y)
#define KSPLICE_UNIQ(s) PASTE(s##_, KSPLICE_ID)

extern struct ksplice_reloc ksplice_relocs;
extern struct ksplice_size ksplice_sizes;

/* Defined in primary.c */
extern int KSPLICE_UNIQ(helper_init_module) (struct ksplice_reloc *,
					     struct ksplice_size *);

int init_module(void)
{
	return KSPLICE_UNIQ(helper_init_module) (&ksplice_relocs,
						 &ksplice_sizes);
}

void cleanup_module(void)
{
}
