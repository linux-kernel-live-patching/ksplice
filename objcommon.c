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

long get_syms(bfd *abfd, asymbol ***syms_ptr)
{
	long storage_needed = bfd_get_symtab_upper_bound(abfd);
	if (storage_needed == 0)
		return 0;
	assert(storage_needed >= 0);

	*syms_ptr = (asymbol **)malloc(storage_needed);
	long num_syms = bfd_canonicalize_symtab(abfd, *syms_ptr);
	assert(num_syms >= 0);

	return num_syms;
}

struct supersect *fetch_supersect(bfd *abfd, asection *sect, asymbol **sympp)
{
	static struct supersect *supersects = NULL;

	struct supersect *ss;
	for (ss = supersects; ss != NULL; ss = ss->next) {
		if (strcmp(sect->name, ss->name) == 0 && ss->parent == abfd)
			return ss;
	}

	struct supersect *new = malloc(sizeof(*new));
	new->parent = abfd;
	new->name = malloc(strlen(sect->name) + 1);
	strcpy(new->name, sect->name);
	new->next = supersects;
	supersects = new;

	new->contents_size = bfd_get_section_size(sect);
	new->contents = (void *)malloc(align(new->contents_size, 4));
	assert(bfd_get_section_contents
	       (abfd, sect, new->contents, 0, new->contents_size));

	int relsize = bfd_get_reloc_upper_bound(abfd, sect);
	new->relocs = (void *)malloc(relsize);
	new->num_relocs =
	    bfd_canonicalize_reloc(abfd, sect, new->relocs, sympp);
	assert(new->num_relocs >= 0);

	return new;
}

int label_offset(const char *sym_name)
{
	int i;
	for (i = 0;
	     sym_name[i] != 0 && sym_name[i + 1] != 0 && sym_name[i + 2] != 0
	     && sym_name[i + 3] != 0; i++) {
		if (sym_name[i] == '_' && sym_name[i + 1] == '_'
		    && sym_name[i + 2] == '_' && sym_name[i + 3] == '_')
			return i + 4;
	}
	return -1;
}

const char *only_label(const char *sym_name)
{
	int offset = label_offset(sym_name);
	if (offset == -1)
		return NULL;
	return &sym_name[offset];
}

const char *dup_wolabel(const char *sym_name)
{
	int offset, entire_strlen, label_strlen, new_strlen;
	char *newstr;

	offset = label_offset(sym_name);
	if (offset == -1)
		label_strlen = 0;
	else
		label_strlen = strlen(&sym_name[offset]) + strlen("____");

	entire_strlen = strlen(sym_name);
	new_strlen = entire_strlen - label_strlen;
	newstr = malloc(new_strlen + 1);
	memcpy(newstr, sym_name, new_strlen);
	newstr[new_strlen] = 0;
	return newstr;
}
