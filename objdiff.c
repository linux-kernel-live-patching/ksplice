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

/*
 * "objdiff old.o new.o" prints two lists to STDOUT, one per line:
 * (1) the names of the ELF sections in new.o that either
 *     (a) do not appear in old.o, or
 *     (b) have different contents in old.o and new.o
 * (2) the names of the "entry point" ELF symbols in new.o
 *     corresponding to the ELF sections in list (1)
 *
 * Before printing these two lists, objdiff prints the number of bits
 * per address on the target architecture.
 */

#include "objcommon.h"
#include "objdiff.h"

#define symbol_init(sym) *(sym) = (asymbol *)NULL
DEFINE_HASH_TYPE(asymbol *, symbol_hash, symbol_hash_init, symbol_hash_free,
		 symbol_hash_lookup, symbol_init);

bfd *newbfd;
struct asymbolp_vec new_syms, old_syms;

int main(int argc, char *argv[])
{
	bfd_init();
	bfd *oldbfd = bfd_openr(argv[1], NULL);
	assert(oldbfd != NULL);
	newbfd = bfd_openr(argv[2], NULL);
	assert(newbfd != NULL);

	char **matching;
	assert(bfd_check_format_matches(oldbfd, bfd_object, &matching));
	assert(bfd_check_format_matches(newbfd, bfd_object, &matching));

	get_syms(newbfd, &new_syms);
	get_syms(oldbfd, &old_syms);

	printf("%d\n", bfd_arch_bits_per_address(oldbfd));
	foreach_nonmatching(oldbfd, newbfd, print_newbfd_section_name);
	printf("\n");
	foreach_nonmatching(oldbfd, newbfd, print_newbfd_entry_symbols);
	printf("\n");
	compare_symbols(oldbfd, newbfd, BSF_GLOBAL);
	printf("\n");

	assert(bfd_close(oldbfd));
	assert(bfd_close(newbfd));
	return EXIT_SUCCESS;
}

void compare_symbols(bfd *oldbfd, bfd *newbfd, flagword flags)
{
	asymbol **old, **new, **tmp;
	struct symbol_hash old_hash;
	symbol_hash_init(&old_hash);
	for (old = old_syms.data; old < old_syms.data + old_syms.size; old++) {
		if (((*old)->flags & flags) == 0 ||
		    ((*old)->flags & BSF_DEBUGGING) != 0)
			continue;
		tmp = symbol_hash_lookup(&old_hash, (*old)->name, TRUE);
		if (*tmp != NULL) {
			fprintf(stderr, "Two global symbols named %s!\n",
				(*old)->name);
			DIE;
		}
		*tmp = *old;
	}
	for (new = new_syms.data; new < new_syms.data + new_syms.size; new++) {
		if (((*new)->flags & flags) == 0 ||
		    ((*new)->flags & BSF_DEBUGGING) != 0)
			continue;
		tmp = symbol_hash_lookup(&old_hash, (*new)->name, FALSE);
		if (tmp == NULL)
			printf("%s ", (*new)->name);
	}
	symbol_hash_free(&old_hash);
}

void foreach_nonmatching(bfd *oldbfd, bfd *newbfd, section_fn s_fn)
{
	asection *newp, *oldp;
	for (newp = newbfd->sections; newp != NULL; newp = newp->next) {
		if (!starts_with(newp->name, ".text"))
			continue;
		oldp = bfd_get_section_by_name(oldbfd, newp->name);
		if (oldp == NULL) {
			if (s_fn == print_newbfd_section_name)
				s_fn(newp);
			continue;
		}
		int newsize = bfd_get_section_size(newp);
		int oldsize = bfd_get_section_size(oldp);
		if (newsize == oldsize) {
			void *newmem = malloc(newsize);
			void *oldmem = malloc(oldsize);
			assert(bfd_get_section_contents
			       (oldbfd, oldp, oldmem, 0, oldsize));
			assert(bfd_get_section_contents
			       (newbfd, newp, newmem, 0, newsize));
			if (memcmp(newmem, oldmem, newsize) == 0 &&
			    reloc_cmp(oldbfd, oldp, newbfd, newp) == 0)
				continue;
		}
		s_fn(newp);
	}
}

/*
 * reloc_cmp checks to see whether the old section and the new section
 * reference different read-only data in their relocations -- if a hard-coded
 * string has been changed between the old file and the new file, reloc_cmp
 * will detect the difference.
 */
int reloc_cmp(bfd *oldbfd, asection *oldp, bfd *newbfd, asection *newp)
{
	int i;
	struct supersect *old_ss, *new_ss;

	old_ss = fetch_supersect(oldbfd, oldp, &old_syms);
	new_ss = fetch_supersect(newbfd, newp, &new_syms);

	if (old_ss->relocs.size != new_ss->relocs.size)
		return -1;

	for (i = 0; i < old_ss->relocs.size; i++) {
		struct supersect *ro_old_ss, *ro_new_ss;

		asection *ro_oldp =
		    (*old_ss->relocs.data[i]->sym_ptr_ptr)->section;
		asection *ro_newp =
		    (*new_ss->relocs.data[i]->sym_ptr_ptr)->section;

		ro_old_ss = fetch_supersect(oldbfd, ro_oldp, &old_syms);
		ro_new_ss = fetch_supersect(newbfd, ro_newp, &new_syms);

		if (!starts_with(ro_old_ss->name, ".rodata"))
			continue;

		if (strcmp(ro_old_ss->name, ro_new_ss->name) != 0)
			return -1;

		bfd_vma old_offset = get_reloc_offset(old_ss,
						      old_ss->relocs.data[i],
						      1);
		bfd_vma new_offset = get_reloc_offset(new_ss,
						      new_ss->relocs.data[i],
						      1);

		if (starts_with(ro_old_ss->name, ".rodata.str")) {
			if (strcmp
			    (ro_old_ss->contents.data + old_offset,
			     ro_new_ss->contents.data + new_offset) != 0)
				return -1;
			continue;
		}

		if (ro_old_ss->contents.size != ro_new_ss->contents.size)
			return -1;

		if (memcmp(ro_old_ss->contents.data, ro_new_ss->contents.data,
			   ro_old_ss->contents.size) != 0)
			return -1;
	}

	return 0;
}

void print_newbfd_section_name(asection *sect)
{
	printf("%s ", sect->name);
}

void print_newbfd_entry_symbols(asection *sect)
{
	asymbol **symp;
	for (symp = new_syms.data; symp < new_syms.data + new_syms.size;
	     symp++) {
		asymbol *sym = *symp;
		if (sym->section != sect || sym->name[0] == '\0' ||
		    starts_with(sym->name, ".text"))
			continue;
		if (sym->value != 0) {
			fprintf(stderr,
				"Symbol %s [%x] has nonzero value %lx\n",
				sym->name, sym->flags, sym->value);
			DIE;
		}
		printf("%s ", sym->name);
	}
}
