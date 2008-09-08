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

#define symbol_init(sym) *(sym) = (asymbol *)NULL
DEFINE_HASH_TYPE(asymbol *, symbol_hash, symbol_hash_init, symbol_hash_free,
		 symbol_hash_lookup, symbol_init);

struct export {
	const char *name;
	asection *sect;
};
DECLARE_VEC_TYPE(struct export, export_vec);

void foreach_nonmatching(struct superbfd *oldsbfd, struct superbfd *newsbfd,
			 void (*s_fn)(struct supersect *));
struct export_vec *get_export_syms(struct superbfd *sbfd);
void compare_exported_symbols(struct superbfd *oldsbfd,
			      struct superbfd *newsbfd, char *addstr);
int reloc_cmp(struct superbfd *oldsbfd, asection *oldp,
	      struct superbfd *newsbfd, asection *newp);
static void print_newbfd_section_name(struct supersect *ss);
void print_new_sections(struct superbfd *oldsbfd, struct superbfd *newsbfd);
void print_deleted_section_labels(struct superbfd *oldsbfd,
				  struct superbfd *newsbfd);

int main(int argc, char *argv[])
{
	bfd_init();
	bfd *oldbfd = bfd_openr(argv[1], NULL);
	assert(oldbfd != NULL);
	bfd *newbfd = bfd_openr(argv[2], NULL);
	assert(newbfd != NULL);

	char **matching;
	assert(bfd_check_format_matches(oldbfd, bfd_object, &matching));
	assert(bfd_check_format_matches(newbfd, bfd_object, &matching));

	struct superbfd *oldsbfd = fetch_superbfd(oldbfd);
	struct superbfd *newsbfd = fetch_superbfd(newbfd);

	foreach_nonmatching(oldsbfd, newsbfd, print_newbfd_section_name);
	printf("\n");
	print_new_sections(oldsbfd, newsbfd);
	printf("\n");
	print_deleted_section_labels(oldsbfd, newsbfd);
	compare_exported_symbols(oldsbfd, newsbfd, "");
	compare_exported_symbols(newsbfd, oldsbfd, "del_");
	printf("\n");

	assert(bfd_close(oldbfd));
	assert(bfd_close(newbfd));
	return EXIT_SUCCESS;
}

struct export_vec *get_export_syms(struct superbfd *sbfd)
{
	asection *sect;
	struct export_vec *exports;
	exports = malloc(sizeof(*exports));
	assert(exports != NULL);
	vec_init(exports);

	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		if (!starts_with(sect->name, "__ksymtab") ||
		    ends_with(sect->name, "_strings"))
			continue;
		struct supersect *ss = fetch_supersect(sbfd, sect);
		struct kernel_symbol *sym;
		assert(ss->contents.size * 2 == ss->relocs.size *
		       sizeof(struct kernel_symbol));
		for (sym = ss->contents.data;
		     (void *)sym < ss->contents.data + ss->contents.size;
		     sym++) {
			struct export *exp = vec_grow(exports, 1);
			exp->name =
			    read_string(ss, (const char *const *)&sym->name);
			exp->sect = sect;
		}
	}
	return exports;
}

void compare_exported_symbols(struct superbfd *oldsbfd,
			      struct superbfd *newsbfd, char *addstr)
{
	struct export_vec *new_exports, *old_exports;
	new_exports = get_export_syms(newsbfd);
	if (new_exports == NULL)
		return;
	old_exports = get_export_syms(oldsbfd);
	struct export *old, *new;
	int found;
	asection *last_sect = NULL;
	for (new = new_exports->data; new < new_exports->data +
	     new_exports->size; new++) {
		found = 0;
		if (old_exports != NULL) {
			for (old = old_exports->data; old < old_exports->data +
			     old_exports->size; old++) {
				if (strcmp(new->name, old->name) == 0 &&
				    strcmp(new->sect->name, old->sect->name)
				    == 0) {
					found = 1;
					break;
				}
			}
		}
		if (found == 0) {
			if (last_sect != new->sect) {
				last_sect = new->sect;
				printf("\n%s%s", addstr, new->sect->name);
			}
			printf(" %s", new->name);
		}
	}
}

void print_new_sections(struct superbfd *oldsbfd, struct superbfd *newsbfd)
{
	asection *sect;
	for (sect = newsbfd->abfd->sections; sect != NULL; sect = sect->next) {
		if (bfd_get_section_by_name(oldsbfd->abfd, sect->name) == NULL)
			printf("%s ", sect->name);
	}
}

void print_deleted_section_labels(struct superbfd *oldsbfd,
				  struct superbfd *newsbfd)
{
	asection *sect;
	for (sect = oldsbfd->abfd->sections; sect != NULL; sect = sect->next) {
		if (bfd_get_section_by_name(newsbfd->abfd, sect->name) == NULL)
			printf("%s ", symbol_label(oldsbfd, sect->symbol));
	}
}

void foreach_nonmatching(struct superbfd *oldsbfd, struct superbfd *newsbfd,
			 void (*s_fn)(struct supersect *))
{
	asection *newp, *oldp;
	struct supersect *old_ss, *new_ss;
	for (newp = newsbfd->abfd->sections; newp != NULL; newp = newp->next) {
		if (!starts_with(newp->name, ".text"))
			continue;
		new_ss = fetch_supersect(newsbfd, newp);
		oldp = bfd_get_section_by_name(oldsbfd->abfd, newp->name);
		if (oldp == NULL)
			continue;
		old_ss = fetch_supersect(oldsbfd, oldp);
		if (new_ss->contents.size == old_ss->contents.size &&
		    memcmp(new_ss->contents.data, old_ss->contents.data,
			   new_ss->contents.size) == 0 &&
		    reloc_cmp(oldsbfd, oldp, newsbfd, newp) == 0)
			continue;
		s_fn(new_ss);
	}
}

/*
 * reloc_cmp checks to see whether the old section and the new section
 * reference different read-only data in their relocations -- if a hard-coded
 * string has been changed between the old file and the new file, reloc_cmp
 * will detect the difference.
 */
int reloc_cmp(struct superbfd *oldsbfd, asection *oldp,
	      struct superbfd *newsbfd, asection *newp)
{
	int i;
	struct supersect *old_ss, *new_ss;

	old_ss = fetch_supersect(oldsbfd, oldp);
	new_ss = fetch_supersect(newsbfd, newp);

	if (old_ss->relocs.size != new_ss->relocs.size)
		return -1;

	for (i = 0; i < old_ss->relocs.size; i++) {
		struct supersect *ro_old_ss, *ro_new_ss;

		asymbol *old_sym = *old_ss->relocs.data[i]->sym_ptr_ptr;
		asymbol *new_sym = *new_ss->relocs.data[i]->sym_ptr_ptr;

		ro_old_ss = fetch_supersect(oldsbfd, old_sym->section);
		ro_new_ss = fetch_supersect(newsbfd, new_sym->section);

		bfd_vma old_offset =
		    get_reloc_offset(old_ss, old_ss->relocs.data[i], 1);
		bfd_vma new_offset =
		    get_reloc_offset(new_ss, new_ss->relocs.data[i], 1);

		if (strcmp(ro_old_ss->name, ro_new_ss->name) != 0)
			return -1;

		if (!starts_with(ro_old_ss->name, ".rodata")) {
			/* for non-rodata, we just compare that the two
			   relocations are to the same offset within the same
			   section. */
			if (old_sym->value + old_offset !=
			    new_sym->value + new_offset)
				return -1;
			continue;
		}

		if (starts_with(ro_old_ss->name, ".rodata.str") &&
		    /* check it's not an out-of-range relocation to a string;
		       we'll just compare entire sections for them */
		    !(old_offset >= ro_old_ss->contents.size ||
		      new_offset >= ro_new_ss->contents.size)) {
			if (strcmp
			    (ro_old_ss->contents.data + old_sym->value +
			     old_offset,
			     ro_new_ss->contents.data + new_sym->value +
			     new_offset) != 0)
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

void print_newbfd_section_name(struct supersect *ss)
{
	printf("%s ", ss->name);
}
