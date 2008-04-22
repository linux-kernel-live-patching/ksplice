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

#include "objcommon.h"

long
get_syms(bfd * abfd, asymbol *** syms_ptr)
{
	long storage_needed = bfd_get_symtab_upper_bound(abfd);
	if (storage_needed == 0)
		return 0;
	assert(storage_needed >= 0);

	*syms_ptr = (asymbol **) malloc(storage_needed);
	long num_syms = bfd_canonicalize_symtab(abfd, *syms_ptr);
	assert(num_syms >= 0);

	return num_syms;
}

struct supersect *
fetch_supersect(bfd * abfd, asection * sect, asymbol ** sympp)
{
	static struct supersect *supersects = NULL;

	struct supersect *ss;
	for (ss = supersects; ss != NULL; ss = ss->next) {
		if (strcmp(sect->name, ss->name) == 0 && ss->parent == abfd) {
			return ss;
		}
	}

	struct supersect *new = malloc(sizeof (*new));
	new->parent = abfd;
	new->name = malloc(strlen(sect->name) + 1);
	strcpy(new->name, sect->name);
	new->next = supersects;
	supersects = new;

	new->contents_size = bfd_get_section_size(sect);
	new->contents = (void *) malloc(align(new->contents_size, 4));
	assert(bfd_get_section_contents
	       (abfd, sect, new->contents, 0, new->contents_size));

	int relsize = bfd_get_reloc_upper_bound(abfd, sect);
	new->relocs = (void *) malloc(relsize);
	new->num_relocs =
	    bfd_canonicalize_reloc(abfd, sect, new->relocs, sympp);
	assert(new->num_relocs >= 0);

	return new;
}
