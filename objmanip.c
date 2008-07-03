/*  This file is based in part on objcopy.c from GNU Binutils v2.17.
 *
 *  Copyright (C) 1991-2006  Free Software Foundation, Inc.
 *  Copyright (C) 2008  Jeffrey Brian Arnold <jbarnold@mit.edu>
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

/* objmanip performs various object file manipulations for Ksplice.  Its first
 * argument is always an object file, which is modified in-place during
 * objmanip's execution.  (objmanip's code is similar to objcopy from GNU
 * binutils because every manipulation that objmanip performs is essentially a
 * "copy" operation with certain changes which make the new version different
 * from the old version).  objmanip has four modes of operation:
 *
 * (1) keep mode
 *
 * This mode is the first objmanip step in processing the target object files.
 *
 * This mode can be broken down into two submodes, called "keep-primary" (which
 * is used to prepare the primary kernel module) and "keep-helper" (which is
 * used to prepare the helper kernel module):
 *
 * (a) keep-primary: "objmanip file.o keep-primary ADDSTR sect_1 ... sect_n"
 *
 * In this submode, only certain sections are kept; all other sections are
 * discarded.  Specifically, the following sections are kept: the listed
 * sections (sect_1 ... sect_n), certain sections referenced by the listed
 * sections, and certain special sections.  The sections that are kept have
 * ADDSTR added to the end of their names.
 *
 * The sections that are kept have most of their ELF relocations removed.
 * (Relocations that point to sections that are being kept are not removed; all
 * other relocations are removed).  Information about each of the removed ELF
 * relocations is printed to STDOUT (ksplice-create will save this information
 * into Ksplice-specific ELF sections for the primary kernel module to use
 * later).
 *
 * Each line of the STDOUT output represents a single place within the ELF
 * object file at which a relocation has been removed.  Each line contains the
 * following fields, separated by spaces: an ELF symbol name, the name of a
 * section previously containing a relocation pointing to that symbol, the
 * offset (within that section) of the former relocation to that symbol, a bit
 * representing whether that ELF relocation is PC-relative, and the ELF addend
 * value for that relocation.
 *
 * (b) keep-helper: "objmanip file.o keep-helper ADDSTR"
 *
 * In this submode, essentially all sections are kept and have ADDSTR added to
 * the end of their names.
 *
 * The sections that are kept have all of their ELF relocations removed.
 * Information about each of the removed ELF relocations is printed to STDOUT
 * (ksplice-create will save this information into Ksplice-specific ELF
 * sections for the helper kernel module to use later).
 *
 * The fields of the STDOUT output are the same as with keep-primary.
 *
 * (2) globalize mode: "objmanip file.o globalize GLOBALIZESTR"
 *
 * This mode is the second objmanip step in processing the target object files.
 * In this mode, all symbols whose names end in GLOBALIZESTR will be
 * duplicated, with the duplicate symbols differing slightly from the original
 * symbols.  The duplicate symbols will have the string "_global" added to the
 * end of their symbol names, and they will be global ELF symbols, regardless
 * of whether the corresponding original symbol was global.
 *
 * (3) sizelist mode: "objmanip file.o sizelist"
 *
 * After the target object files have been linked into a single collection
 * object file, this mode is used in order to obtain a list of all of the
 * functions in the collection object file.  Each line of the STDOUT output
 * contains an ELF section name and that section's size, as presented by BFD's
 * bfd_print_symbol function.
 *
 * (4) rmsyms mode: "objmanip file.o rmsyms sym_1 ... sym_n"
 *
 * This mode is the final objmanip step in preparing the Ksplice kernel
 * modules.  In this mode, any ELF relocations involving the listed symbols
 * (sym_1 ...  sym_n) are removed, and information about each of the removed
 * relocations is printed to STDOUT.
 *
 * The fields of the STDOUT output are the same as with keep-primary.
 */

#include "objcommon.h"
#include "objmanip.h"
#include <stdint.h>

asymbol **isympp = NULL;
long symcount;

char **varargs;
int varargs_count;
char *modestr, *addstr_all = "", *addstr_sect = "", *globalizestr;

struct wsect *wanted_sections = NULL;

struct specsect special_sections[] = {
	{".altinstructions", 1, ".altinstr_replacement",
	 2 * sizeof(void *) + 4},
	{".smp_locks", 0, NULL, sizeof(void *)},
	{".parainstructions", 0, NULL, sizeof(void *) + 4},
}, *const end_special_sections = *(&special_sections + 1);

#define mode(str) starts_with(modestr, str)

int main(int argc, char **argv)
{
	char *debug_name = malloc(strlen(argv[1]) + 4 + strlen(argv[2]) + 1);
	sprintf(debug_name, "%s.pre%s", argv[1], argv[2]);
	rename(argv[1], debug_name);

	bfd_init();
	bfd *ibfd = bfd_openr(debug_name, NULL);
	assert(ibfd);

	char **matching;
	assert(bfd_check_format_matches(ibfd, bfd_object, &matching));

	const char *output_target = bfd_get_target(ibfd);
	bfd *obfd = bfd_openw(argv[1], output_target);
	assert(obfd);

	symcount = get_syms(ibfd, &isympp);

	modestr = argv[2];
	if (mode("keep")) {
		addstr_all = argv[3];
		addstr_sect = argv[4];
		varargs = &argv[5];
		varargs_count = argc - 5;
	} else if (mode("globalize")) {
		globalizestr = argv[3];
		varargs = &argv[4];
		varargs_count = argc - 4;
	} else {
		varargs = &argv[3];
		varargs_count = argc - 3;
	}

	if (mode("keep")) {
		while (1) {
			struct wsect *tmp = wanted_sections;
			bfd_map_over_sections(ibfd, mark_wanted_if_referenced,
					      NULL);
			if (tmp == wanted_sections)
				break;
		}
	}

	int i;
	for (i = 0; mode("sizelist") && i < symcount; i++) {
		if ((isympp[i]->flags & BSF_FUNCTION)
		    && isympp[i]->value == 0 && !(isympp[i]->flags & BSF_WEAK)) {
			/* We call bfd_print_symbol in order to get access to
			 * the size associated with the function symbol, which
			 * is not otherwise available through the BFD API
			 */
			bfd_print_symbol(ibfd, stdout, isympp[i],
					 bfd_print_symbol_all);
			printf("\n");
		}
	}

	asection *p;
	for (p = ibfd->sections; p != NULL; p = p->next) {
		if (is_special(p->name))
			continue;
		if (want_section(p->name, NULL) || mode("rmsyms"))
			rm_some_relocs(ibfd, p);
	}

	struct specsect *ss;
	if (mode("keep")) {
		for (ss = special_sections; ss != end_special_sections; ss++)
			rm_from_special(ibfd, ss);
	}

	copy_object(ibfd, obfd);
	assert(bfd_close(obfd));
	assert(bfd_close(ibfd));
	return EXIT_SUCCESS;
}

void rm_some_relocs(bfd *ibfd, asection *isection)
{
	struct supersect *ss = fetch_supersect(ibfd, isection, isympp);
	struct arelentp_vec orig_relocs;
	vec_move(&orig_relocs, &ss->relocs);

	arelent **relocp;
	for (relocp = orig_relocs.data;
	     relocp < orig_relocs.data + orig_relocs.size; ++relocp) {
		int rm_reloc = 0;
		asymbol *sym_ptr = *(*relocp)->sym_ptr_ptr;

		if (mode("rmsyms") && match_varargs(sym_ptr->name))
			rm_reloc = 1;

		if (mode("keep"))
			rm_reloc = 1;

		if (mode("keep-primary") && want_section(sym_ptr->name, NULL))
			rm_reloc = 0;

		if (rm_reloc)
			print_reloc(ibfd, isection, *relocp, ss);
		else
			*vec_grow(&ss->relocs, 1) = *relocp;
	}
}

void print_reloc(bfd *ibfd, asection *isection, arelent *orig_reloc,
		 struct supersect *ss)
{
	asymbol *sym_ptr = *orig_reloc->sym_ptr_ptr;

	char *new_sectname = strdup(isection->name);
	if (mode("keep"))
		want_section(isection->name, &new_sectname);

	char *new_symname = strdup(sym_ptr->name);
	if (mode("keep-primary"))
		want_section(sym_ptr->name, &new_symname);

	int addend = orig_reloc->addend;
	reloc_howto_type *howto = orig_reloc->howto;
	int size = bfd_get_reloc_size(howto);
	int addend2 = blot_section(ibfd, isection, orig_reloc->address, size);
	assert(addend == 0 || addend2 == 0);
	if (addend == 0)
		addend = addend2;

	printf("%s%s ", new_symname, addstr_all);
	printf("%s%s%s ", canonical_sym(new_sectname), addstr_all, addstr_sect);
	printf("%08x ", (int)orig_reloc->address);
	printf("%d %08x %d\n", howto->pc_relative, addend, size);
}

int blot_section(bfd *abfd, asection *sect, int offset, int size)
{
	struct supersect *ss = fetch_supersect(abfd, sect, isympp);
	void *address = ss->contents.data + offset;
	int tmp;
	if (size == 4) {
		tmp = *(int *)address;
		*((int *)address) = 0x77777777;
	} else if (size == 8) {
		tmp = *(long long *)address;
		*((long long *)address) = 0x7777777777777777ll;
	} else {
		fprintf(stderr, "ksplice: Unsupported size %d\n", size);
		DIE;
	}
	return tmp;
}

const char *canonical_sym(const char *sect_wlabel)
{
	const char *sect = sect_wlabel;
	if (!mode("sizelist"))
		sect = dup_wolabel(sect_wlabel);

	if (starts_with(sect, ".rodata"))
		return sect;

	int i;
	for (i = 0; i < symcount; i++) {
		const char *cur_sectname = isympp[i]->section->name;
		if (!mode("sizelist"))
			cur_sectname = dup_wolabel(cur_sectname);

		if (strlen(isympp[i]->name) != 0 &&
		    !starts_with(isympp[i]->name, ".text") &&
		    strcmp(cur_sectname, sect) == 0 && isympp[i]->value == 0)
			return isympp[i]->name;
	}
	printf("ksplice: Failed to canonicalize %s\n", sect);
	DIE;
}

void rm_from_special(bfd *ibfd, struct specsect *s)
{
	asection *isection = bfd_get_section_by_name(ibfd, s->sectname);
	if (isection == NULL)
		return;

	struct supersect *ss = fetch_supersect(ibfd, isection, isympp);
	struct void_vec orig_contents;
	vec_move(&orig_contents, &ss->contents);
	size_t pad = align(orig_contents.size, ss->alignment) -
	    orig_contents.size;
	memset(vec_grow(&orig_contents, pad), 0, pad);
	struct arelentp_vec orig_relocs;
	vec_move(&orig_relocs, &ss->relocs);

	int entry_size = align(s->entry_size, ss->alignment);
	int relocs_per_entry = s->odd_relocs ? 2 : 1;
	assert((orig_contents.size / entry_size) * relocs_per_entry ==
	       orig_relocs.size);

	void *orig_entry;
	arelent **relocp;
	for (orig_entry = orig_contents.data, relocp = orig_relocs.data;
	     orig_entry < orig_contents.data + orig_contents.size;
	     orig_entry += entry_size, relocp += relocs_per_entry) {
		asymbol *sym = *(*relocp)->sym_ptr_ptr;
		if (s->odd_relocs) {
			asymbol *odd_sym = *(*(relocp + 1))->sym_ptr_ptr;
			assert(strcmp(odd_sym->name, s->odd_relocname) == 0);
		}
		asection *p;
		for (p = ibfd->sections; p != NULL; p = p->next) {
			if (strcmp(sym->name, p->name) == 0
			    && !is_special(p->name)
			    && !want_section(p->name, NULL))
				break;
		}
		if (p != NULL)
			continue;

		void *new_entry = vec_grow(&ss->contents, entry_size);
		memcpy(new_entry, orig_entry, entry_size);
		int modifier = (new_entry - ss->contents.data) -
		    (orig_entry - orig_contents.data);
		arelent **new_relocp = vec_grow(&ss->relocs, 1);
		*new_relocp = *relocp;
		(*new_relocp)->address += modifier;
		if (s->odd_relocs) {
			new_relocp = vec_grow(&ss->relocs, 1);
			*new_relocp = *(relocp + 1);
			(*new_relocp)->address += modifier;
		}
	}
}

void mark_wanted_if_referenced(bfd *abfd, asection *sect, void *ignored)
{
	if (want_section(sect->name, NULL))
		return;
	if (!starts_with(sect->name, ".text")
	    && !starts_with(sect->name, ".rodata"))
		return;

	bfd_map_over_sections(abfd, check_for_ref_to_section, sect);
}

void check_for_ref_to_section(bfd *abfd, asection *looking_at,
			      void *looking_for)
{
	if (!want_section(looking_at->name, NULL))
		return;

	struct supersect *ss = fetch_supersect(abfd, looking_at, isympp);
	arelent **relocp;
	for (relocp = ss->relocs.data;
	     relocp != ss->relocs.data + ss->relocs.size; ++relocp) {
		asymbol *sym = *(*relocp)->sym_ptr_ptr;
		if (sym->section == (asection *)looking_for) {
			struct wsect *w = malloc(sizeof(*w));
			w->name = strdup(((asection *)looking_for)->name);
			w->next = wanted_sections;
			wanted_sections = w;
		}
	}
}

/* Modified function from GNU Binutils objcopy.c */
bfd_boolean copy_object(bfd *ibfd, bfd *obfd)
{
	assert(bfd_set_format(obfd, bfd_get_format(ibfd)));

	bfd_vma start = bfd_get_start_address(ibfd);

	flagword flags = bfd_get_file_flags(ibfd);
	flags &= bfd_applicable_file_flags(obfd);

	assert(bfd_set_start_address(obfd, start)
	       && bfd_set_file_flags(obfd, flags));

	enum bfd_architecture iarch = bfd_get_arch(ibfd);
	unsigned int imach = bfd_get_mach(ibfd);
	assert(bfd_set_arch_mach(obfd, iarch, imach));
	assert(bfd_set_format(obfd, bfd_get_format(ibfd)));

	/* BFD mandates that all output sections be created and sizes set before
	   any output is done.  Thus, we traverse all sections multiple times.  */
	bfd_map_over_sections(ibfd, setup_section, obfd);

	assert(bfd_count_sections(obfd));

	/* Mark symbols used in output relocations so that they
	   are kept, even if they are local labels or static symbols.

	   Note we iterate over the input sections examining their
	   relocations since the relocations for the output sections
	   haven't been set yet.  mark_symbols_used_in_relocations will
	   ignore input sections which have no corresponding output
	   section.  */

	bfd_map_over_sections(ibfd, mark_symbols_used_in_relocations, isympp);
	asymbol **osympp = (void *)malloc((2 * symcount + 1) * sizeof(*osympp));
	symcount = filter_symbols(ibfd, obfd, osympp, isympp, symcount);

	bfd_set_symtab(obfd, osympp, symcount);

	/* This has to happen after the symbol table has been set.  */
	bfd_map_over_sections(ibfd, copy_section, obfd);

	/* Allow the BFD backend to copy any private data it understands
	   from the input BFD to the output BFD.  This is done last to
	   permit the routine to look at the filtered symbol table, which is
	   important for the ECOFF code at least.  */
	assert(bfd_copy_private_bfd_data(ibfd, obfd));

	return TRUE;
}

/* Modified function from GNU Binutils objcopy.c */
void setup_section(bfd *ibfd, asection *isection, void *obfdarg)
{
	bfd *obfd = obfdarg;
	bfd_vma vma;

	char *name = strdup(isection->name);
	if (!want_section(isection->name, &name))
		return;

	asection *osection = bfd_make_section_anyway(obfd, name);
	assert(osection != NULL);

	flagword flags = bfd_get_section_flags(ibfd, isection);
	bfd_set_section_flags(obfd, osection, flags);

	struct supersect *ss = fetch_supersect(ibfd, isection, isympp);
	assert(bfd_set_section_size(obfd, osection, ss->contents.size));

	vma = bfd_section_vma(ibfd, isection);
	assert(bfd_set_section_vma(obfd, osection, vma));

	osection->lma = isection->lma;
	assert(bfd_set_section_alignment(obfd,
					 osection,
					 bfd_section_alignment(ibfd,
							       isection)));
	osection->entsize = isection->entsize;
	isection->output_section = osection;
	isection->output_offset = 0;
	return;
}

/* Modified function from GNU Binutils objcopy.c */
void copy_section(bfd *ibfd, asection *isection, void *obfdarg)
{
	bfd *obfd = obfdarg;

	char *name = strdup(isection->name);
	if (!want_section(isection->name, &name))
		return;

	flagword flags = bfd_get_section_flags(ibfd, isection);
	if ((flags & SEC_GROUP) != 0)
		return;

	struct supersect *ss = fetch_supersect(ibfd, isection, isympp);
	asection *osection = isection->output_section;
	if (ss->contents.size == 0 || osection == 0)
		return;

	bfd_set_reloc(obfd, osection,
		      ss->relocs.size == 0 ? NULL : ss->relocs.data,
		      ss->relocs.size);

	if (bfd_get_section_flags(ibfd, isection) & SEC_HAS_CONTENTS
	    && bfd_get_section_flags(obfd, osection) & SEC_HAS_CONTENTS)
		assert(bfd_set_section_contents
		       (obfd, osection, ss->contents.data, 0,
			ss->contents.size));
}

/* Modified function from GNU Binutils objcopy.c
 *
 * Mark all the symbols which will be used in output relocations with
 * the BSF_KEEP flag so that those symbols will not be stripped.
 *
 * Ignore relocations which will not appear in the output file.
 */
void mark_symbols_used_in_relocations(bfd *ibfd, asection *isection,
				      void *symbolsarg)
{
	if (isection->output_section == NULL)
		return;

	struct supersect *ss = fetch_supersect(ibfd, isection, isympp);

	/* Examine each symbol used in a relocation.  If it's not one of the
	   special bfd section symbols, then mark it with BSF_KEEP.  */
	arelent **relocp;
	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		asymbol *sym = *(*relocp)->sym_ptr_ptr;
		if (sym != bfd_com_section_ptr->symbol
		    && sym != bfd_abs_section_ptr->symbol
		    && sym != bfd_und_section_ptr->symbol)
			sym->flags |= BSF_KEEP;
	}
}

/* Modified function from GNU Binutils objcopy.c
 *
 * Choose which symbol entries to copy.
 * We don't copy in place, because that confuses the relocs.
 * Return the number of symbols to print.
 */
unsigned int filter_symbols(bfd *abfd, bfd *obfd, asymbol **osyms,
			    asymbol **isyms, long symcount)
{
	asymbol **from = isyms, **to = osyms;
	long src_count = 0, dst_count = 0;

	for (; src_count < symcount; src_count++) {
		asymbol *sym = from[src_count];
		flagword flags = sym->flags;

		if (mode("keep") && want_section(sym->section->name, NULL)) {
			char *newname =
			    malloc(strlen(sym->name) + strlen(addstr_all) +
				   strlen(addstr_sect) + 1);
			sprintf(newname, "%s%s%s", sym->name, addstr_all,
				addstr_sect);
			sym->name = newname;
		}

		int keep;
		if ((flags & BSF_KEEP) != 0	/* Used in relocation.  */
		    || ((flags & BSF_SECTION_SYM) != 0
			&& ((*(sym->section)->symbol_ptr_ptr)->flags
			    & BSF_KEEP) != 0))
			keep = 1;
		else if ((flags & (BSF_GLOBAL | BSF_WEAK)) != 0)
			keep = 1;
		else if (bfd_decode_symclass(sym) == 'I')
			/* Global symbols in $idata sections need to be retained.
			   External users of the  library containing the $idata
			   section may reference these symbols.  */
			keep = 1;
		else if ((flags & BSF_GLOBAL) != 0
			 || (flags & BSF_WEAK) != 0
			 || bfd_is_com_section(sym->section))
			keep = 1;
		else if ((flags & BSF_DEBUGGING) != 0)
			keep = 1;
		else
			keep = !bfd_is_local_label(abfd, sym);

		if (!want_section(sym->section->name, NULL))
			keep = 0;

		if (mode("rmsyms") && match_varargs(sym->name))
			keep = 0;

		if (keep)
			to[dst_count++] = sym;

		if (keep && mode("globalize")
		    && ends_with(sym->name, globalizestr)) {
			asymbol *new = bfd_make_empty_symbol(obfd);
			char *tmp =
			    malloc(strlen(sym->name) + strlen("_global") + 1);
			sprintf(tmp, "%s_global", sym->name);
			new->name = tmp;
			new->value = sym->value;
			new->flags = BSF_GLOBAL;
			new->section = sym->section;
			to[dst_count++] = new;
		}
	}

	asection *p;
	for (p = obfd->sections; mode("keep") && p != NULL; p = p->next) {
		if (starts_with(p->name, ".rodata") &&
		    !exists_sym_with_name(from, symcount, p->name)) {
			asymbol *new = bfd_make_empty_symbol(obfd);
			new->name = p->name;
			new->value = 0x0;
			new->flags = BSF_GLOBAL;
			new->section = p;
			to[dst_count++] = new;
		}
	}

	to[dst_count] = NULL;
	return dst_count;
}

int exists_sym_with_name(asymbol **syms, int symcount, const char *desired)
{
	int i;
	for (i = 0; i < symcount; i++) {
		if (strcmp(bfd_asymbol_name(syms[i]), desired) == 0)
			return 1;
	}
	return 0;
}

int match_varargs(const char *str)
{
	int i;
	for (i = 0; i < varargs_count; i++) {
		if (strcmp(str, varargs[i]) == 0)
			return 1;
		if (starts_with(str, varargs[i]) &&
		    strcmp(str + strlen(varargs[i]), "_global") == 0)
			return 1;
	}
	return 0;
}

int want_section(const char *name, char **newname)
{
	static const char *static_want[] = {
		".altinstructions",
		".altinstr_replacement",
		".smp_locks",
		".parainstructions",
		NULL
	};

	if (!mode("keep"))
		return 1;

	struct wsect *w = wanted_sections;
	for (; w != NULL; w = w->next) {
		if (strcmp(w->name, name) == 0)
			goto success;
	}

	if (starts_with(name, ".ksplice"))
		goto success;
	if (mode("keep-helper") && starts_with(name, ".text"))
		goto success;
	if (match_varargs(name))
		goto success;

	int i;
	for (i = 0; static_want[i] != NULL; i++) {
		if (strcmp(name, static_want[i]) == 0)
			return 1;
	}
	return 0;

success:

	if (newname != NULL) {
		*newname =
		    malloc(strlen(name) + strlen(addstr_all) +
			   strlen(addstr_sect) + 1);
		sprintf(*newname, "%s%s%s", name, addstr_all, addstr_sect);
	}
	return 1;
}

struct specsect *is_special(const char *name)
{
	struct specsect *ss;
	for (ss = special_sections; ss != end_special_sections; ss++) {
		if (strcmp(ss->sectname, name) == 0)
			return ss;
	}
	return NULL;
}
