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
void compare_symbols(struct superbfd *oldsbfd, struct superbfd *newsbfd,
		     flagword flags);
struct export_vec *get_export_syms(struct superbfd *sbfd);
void compare_exported_symbols(struct superbfd *oldsbfd,
			      struct superbfd *newsbfd, char *addstr);
int reloc_cmp(struct superbfd *oldsbfd, asection *oldp,
	      struct superbfd *newsbfd, asection *newp);
static void print_newbfd_section_name(struct supersect *ss);
static void print_newbfd_entry_symbols(struct supersect *ss);

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
	foreach_nonmatching(oldsbfd, newsbfd, print_newbfd_entry_symbols);
	printf("\n");
	compare_symbols(oldsbfd, newsbfd, BSF_GLOBAL);
	printf("\n");
	compare_symbols(oldsbfd, newsbfd, ~0);
	printf("\n");
	compare_symbols(newsbfd, oldsbfd, BSF_FUNCTION);
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
		/* last_sect can go away once we make objdiff | objmanip */
		if (last_sect != new->sect) {
			last_sect = new->sect;
			printf("\n%s%s", addstr, new->sect->name);
		}
		if (found == 0)
			printf(" %s", new->name);
	}
}

void compare_symbols(struct superbfd *oldsbfd, struct superbfd *newsbfd,
		     flagword flags)
{
	asymbol **old, **new, **tmp;
	struct symbol_hash old_hash;
	symbol_hash_init(&old_hash);
	for (old = oldsbfd->syms.data; old < oldsbfd->syms.data +
		 oldsbfd->syms.size; old++) {
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
	for (new = newsbfd->syms.data; new < newsbfd->syms.data +
		 newsbfd->syms.size; new++) {
		if (((*new)->flags & flags) == 0 ||
		    ((*new)->flags & BSF_DEBUGGING) != 0)
			continue;
		tmp = symbol_hash_lookup(&old_hash, (*new)->name, FALSE);
		if (tmp == NULL)
			printf("%s ", (*new)->name);
	}
	symbol_hash_free(&old_hash);
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
		if (oldp == NULL) {
			if (s_fn == print_newbfd_section_name)
				s_fn(new_ss);
			continue;
		}
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

		asection *ro_oldp =
		    (*old_ss->relocs.data[i]->sym_ptr_ptr)->section;
		asection *ro_newp =
		    (*new_ss->relocs.data[i]->sym_ptr_ptr)->section;

		ro_old_ss = fetch_supersect(oldsbfd, ro_oldp);
		ro_new_ss = fetch_supersect(newsbfd, ro_newp);

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

void print_newbfd_section_name(struct supersect *ss)
{
	printf("%s ", ss->name);
}

void print_newbfd_entry_symbols(struct supersect *ss)
{
	struct asymbolp_vec new_syms = ss->parent->syms;
	asymbol **symp;
	for (symp = new_syms.data; symp < new_syms.data + new_syms.size;
	     symp++) {
		asymbol *sym = *symp;
		struct supersect *sym_ss = fetch_supersect(ss->parent,
							   sym->section);
		if (sym_ss != ss || sym->name[0] == '\0' ||
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
