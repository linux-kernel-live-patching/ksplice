/*  This file is based in part on objcopy.c from GNU Binutils v2.17.
 *
 *  Copyright (C) 1991-2006  Free Software Foundation, Inc.
 *  Copyright (C) 2007-2008  Jeffrey Brian Arnold <jbarnold@mit.edu>
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

#define _GNU_SOURCE
#include "objcommon.h"
#include "kmodsrc/ksplice.h"
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

DECLARE_VEC_TYPE(const char *, str_vec);

struct wsect {
	asection *sect;
	struct wsect *next;
};

struct specsect {
	const char *sectname;
	int entry_size;
};

struct export_desc {
	const char *sectname;
	struct str_vec names;
};
DECLARE_VEC_TYPE(struct export_desc, export_desc_vec);

void rm_some_relocs(struct supersect *ss);
void write_ksplice_reloc(struct supersect *ss, arelent *orig_reloc);
void blot_section(struct supersect *ss, int offset, reloc_howto_type *howto);
void write_ksplice_size(struct superbfd *sbfd, asymbol **symp);
void write_ksplice_patch(struct superbfd *sbfd, const char *symname);
void rm_from_special(struct superbfd *sbfd, const struct specsect *s);
void mark_wanted_if_referenced(bfd *abfd, asection *sect, void *ignored);
void check_for_ref_to_section(bfd *abfd, asection *looking_at,
			      void *looking_for);
bfd_boolean copy_object(bfd *ibfd, bfd *obfd);
void setup_section(bfd *ibfd, asection *isection, void *obfdarg);
static void setup_new_section(bfd *obfd, struct supersect *ss);
static void write_section(bfd *obfd, asection *osection, void *arg);
void mark_symbols_used_in_relocations(bfd *abfd, asection *isection,
				      void *ignored);
static void ss_mark_symbols_used_in_relocations(struct supersect *ss);
void filter_symbols(bfd *ibfd, bfd *obfd, struct asymbolp_vec *osyms,
		    struct asymbolp_vec *isyms);
int match_varargs(const char *str);
void read_str_set(struct str_vec *strs);
int str_in_set(const char *str, const struct str_vec *strs);
int want_section(asection *sect);
const struct specsect *is_special(asection *sect);
struct supersect *make_section(struct superbfd *sbfd, const char *name);
void __attribute__((format(printf, 3, 4)))
write_string(struct supersect *ss, const char **addr, const char *fmt, ...);
void rm_some_exports(struct superbfd *isbfd, const struct export_desc *ed);
void write_ksplice_export(struct superbfd *sbfd, const char *symname,
			  const char *export_type, int del);
void write_reloc(struct supersect *ss, const void *addr, asymbol **symp,
		 bfd_vma offset);
arelent *create_reloc(struct supersect *ss, const void *addr, asymbol **symp,
		      bfd_vma offset);

char **varargs;
int varargs_count;
struct str_vec sections, entrysyms, newsyms, delsyms;
struct export_desc_vec exports;

const char *modestr, *kid;
char *addstr_all;

struct wsect *wanted_sections = NULL;

const struct specsect special_sections[] = {
	{".altinstructions", 2 * sizeof(void *) + 4},
	{".smp_locks", sizeof(void *)},
	{".parainstructions", sizeof(void *) + 4},
}, *const end_special_sections = *(&special_sections + 1);

#define mode(str) starts_with(modestr, str)

DECLARE_VEC_TYPE(unsigned long, addr_vec);
DEFINE_HASH_TYPE(struct addr_vec, addr_vec_hash,
		 addr_vec_hash_init, addr_vec_hash_free, addr_vec_hash_lookup,
		 vec_init);
struct addr_vec_hash system_map;

void load_system_map()
{
	const char *config_dir = getenv("KSPLICE_CONFIG_DIR");
	assert(config_dir);
	char *file;
	assert(asprintf(&file, "%s/System.map", config_dir) >= 0);
	FILE *fp = fopen(file, "r");
	assert(fp);
	addr_vec_hash_init(&system_map);
	unsigned long addr;
	char type;
	char *sym;
	while (fscanf(fp, "%lx %c %as\n", &addr, &type, &sym) == 3)
		*vec_grow(addr_vec_hash_lookup(&system_map, sym, TRUE),
			  1) = addr;
	fclose(fp);
}

int needed_data_section(struct superbfd *sbfd, asection *isection)
{
	struct supersect *ss = fetch_supersect(sbfd, isection);
	if (starts_with(isection->name, ".rodata."))
		return 1;
	if (starts_with(isection->name, ".data.")) {
		/* Ignore .data.percpu sections */
		if (starts_with(isection->name, ".data.percpu"))
			return 0;
		return ss->relocs.size != 0;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	char *debug_name;
	assert(asprintf(&debug_name, "%s.pre%s", argv[1], argv[2]) >= 0);
	rename(argv[1], debug_name);

	bfd_init();
	bfd *ibfd = bfd_openr(debug_name, NULL);
	assert(ibfd);

	char **matching;
	assert(bfd_check_format_matches(ibfd, bfd_object, &matching));

	const char *output_target = bfd_get_target(ibfd);
	bfd *obfd = bfd_openw(argv[1], output_target);
	assert(obfd);

	struct superbfd *isbfd = fetch_superbfd(ibfd);

	modestr = argv[2];
	if (mode("keep")) {
		kid = argv[3];
	} else if (mode("rmsyms")) {
		varargs = &argv[3];
		varargs_count = argc - 3;
	}

	if (mode("keep")) {
		read_str_set(&sections);
		read_str_set(&entrysyms);
		read_str_set(&newsyms);
		read_str_set(&delsyms);
		vec_init(&exports);
		/* https://bugzilla.redhat.com/show_bug.cgi?id=431832 */
		while (ungetc(getc(stdin), stdin) != EOF) {
			char *sectname;
			int ret = scanf("%as", &sectname);
			if (ret == EOF)
				break;
			assert(ret == 1);
			struct export_desc *ed = vec_grow(&exports, 1);
			ed->sectname = sectname;
			read_str_set(&ed->names);
		}
	}

	char *c = strstr(argv[1], ".KSPLICE");
	assert(asprintf(&addstr_all, "<%.*s>",
			(int)(c == NULL ? strlen(argv[1]) : c - argv[1]),
			argv[1]) >= 0);

	if (mode("keep-primary")) {
		/* Create export_desc structures for all export sections */
		asection *sect;
		for (sect = isbfd->abfd->sections; sect != NULL;
		     sect = sect->next) {
			struct export_desc *ed;
			if (!starts_with(sect->name, "__ksymtab") ||
			    ends_with(sect->name, "_strings"))
				continue;
			for (ed = exports.data;
			     ed < exports.data + exports.size; ed++) {
				if (strcmp(ed->sectname, sect->name) == 0)
					break;
			}
			if (ed < exports.data + exports.size)
				continue;
			ed = vec_grow(&exports, 1);
			ed->sectname = sect->name;
			vec_init(&ed->names);
		}
	}

	if (mode("keep") || mode("rmsyms"))
		load_system_map();

	if (mode("keep")) {
		while (1) {
			const struct wsect *tmp = wanted_sections;
			bfd_map_over_sections(ibfd, mark_wanted_if_referenced,
					      NULL);
			if (tmp == wanted_sections)
				break;
		}
	}

	asymbol **symp;
	for (symp = isbfd->syms.data;
	     mode("keep") && symp < isbfd->syms.data + isbfd->syms.size;
	     symp++) {
		asymbol *sym = *symp;
		if (!want_section(sym->section))
			continue;
		if ((sym->flags & BSF_WEAK) != 0)
			continue;
		if ((sym->flags & BSF_DEBUGGING) != 0)
			continue;
		if ((sym->flags & BSF_FUNCTION) && sym->value == 0)
			write_ksplice_size(isbfd, symp);
		if (sym->value == 0 && needed_data_section(isbfd, sym->section))
			write_ksplice_size(isbfd, symp);
	}

	if (mode("keep-primary")) {
		const char **symname;
		for (symname = entrysyms.data;
		     symname < entrysyms.data + entrysyms.size; symname++)
			write_ksplice_patch(isbfd, *symname);

		const struct export_desc *ed;
		for (ed = exports.data; ed < exports.data + exports.size;
		     ed++) {
			if (starts_with(ed->sectname, "del___ksymtab")) {
				const char *export_type =
				    ed->sectname + strlen("del___ksymtab");
				const char **symname;
				for (symname = ed->names.data;
				     symname < ed->names.data + ed->names.size;
				     symname++)
					write_ksplice_export(isbfd, *symname,
							     export_type, 1);
			} else {
				rm_some_exports(isbfd, ed);
			}
		}
	}

	asection *p;
	for (p = ibfd->sections; p != NULL; p = p->next) {
		struct supersect *ss = fetch_supersect(isbfd, p);
		if (is_special(p) || starts_with(p->name, ".ksplice"))
			continue;
		if (want_section(p) || mode("rmsyms"))
			rm_some_relocs(ss);
	}

	const struct specsect *ss;
	if (mode("keep")) {
		for (ss = special_sections; ss != end_special_sections; ss++)
			rm_from_special(isbfd, ss);
	}

	copy_object(ibfd, obfd);
	assert(bfd_close(obfd));
	assert(bfd_close(ibfd));
	return EXIT_SUCCESS;
}

void rm_some_exports(struct superbfd *isbfd, const struct export_desc *ed)
{
	assert(starts_with(ed->sectname, "__ksymtab"));
	const char *export_type = ed->sectname + strlen("__ksymtab");
	asection *sym_sect = bfd_get_section_by_name(isbfd->abfd, ed->sectname);
	assert(sym_sect != NULL);
	char *export_crc_name;
	assert(asprintf(&export_crc_name, "__kcrctab%s", export_type) >= 0);
	asection *crc_sect = bfd_get_section_by_name(isbfd->abfd,
						     export_crc_name);
	struct supersect *ss, *crc_ss = NULL;
	ss = fetch_supersect(isbfd, sym_sect);
	if (crc_sect != NULL)
		crc_ss = fetch_supersect(isbfd, crc_sect);

	if (crc_ss != NULL)
		assert(ss->contents.size * sizeof(unsigned long) ==
		       crc_ss->contents.size * sizeof(struct kernel_symbol));

	struct supersect orig_ss, orig_crc_ss;
	supersect_move(&orig_ss, ss);
	if (crc_ss != NULL)
		supersect_move(&orig_crc_ss, crc_ss);

	struct kernel_symbol *orig_ksym;
	unsigned long *orig_crc;
	for (orig_ksym = orig_ss.contents.data,
	     orig_crc = orig_crc_ss.contents.data;
	     (void *)orig_ksym < orig_ss.contents.data + orig_ss.contents.size;
	     orig_ksym++, orig_crc++) {
		asymbol *sym;
		read_reloc(&orig_ss, &orig_ksym->value,
			   sizeof(orig_ksym->value), &sym);
		if (!str_in_set(sym->name, &ed->names))
			continue;

		struct kernel_symbol *ksym = sect_grow(ss, 1, typeof(*ksym));
		sect_copy(ss, &ksym->value, &orig_ss, &orig_ksym->value, 1);
		/* Replace name with a mangled name */
		write_ksplice_export(ss->parent, sym->name, export_type, 0);
		write_string(ss, (const char **)&ksym->name,
			     "DISABLED_%s_%s", sym->name, kid);

		if (crc_ss != NULL)
			sect_copy(crc_ss,
				  sect_grow(crc_ss, 1, typeof(*orig_crc)),
				  &orig_crc_ss, orig_crc, 1);
	}
}

void rm_some_relocs(struct supersect *ss)
{
	struct arelentp_vec orig_relocs;
	vec_move(&orig_relocs, &ss->relocs);

	arelent **relocp;
	for (relocp = orig_relocs.data;
	     relocp < orig_relocs.data + orig_relocs.size; relocp++) {
		int rm_reloc = 0;
		asymbol *sym_ptr = *(*relocp)->sym_ptr_ptr;

		if (mode("rmsyms") && match_varargs(sym_ptr->name))
			rm_reloc = 1;

		if (mode("keep"))
			rm_reloc = 1;

		if (mode("keep-primary") && want_section(sym_ptr->section) &&
		    (str_in_set(sym_ptr->name, &newsyms) ||
		     bfd_is_und_section(sym_ptr->section) ||
		     (sym_ptr->flags & BSF_FUNCTION) == 0))
			rm_reloc = 0;

		if (mode("finalize") && bfd_is_und_section(sym_ptr->section))
			rm_reloc = 1;

		if (rm_reloc)
			write_ksplice_reloc(ss, *relocp);
		else
			*vec_grow(&ss->relocs, 1) = *relocp;
	}
}

struct supersect *make_section(struct superbfd *sbfd, const char *name)
{
	asection *sect = bfd_get_section_by_name(sbfd->abfd, name);
	if (sect != NULL)
		return fetch_supersect(sbfd, sect);
	else
		return new_supersect(sbfd, name);
}

arelent *create_reloc(struct supersect *ss, const void *addr, asymbol **symp,
		      bfd_vma offset)
{
	bfd_reloc_code_real_type code;
	switch (bfd_arch_bits_per_address(ss->parent->abfd)) {
	case 32:
		code = BFD_RELOC_32;
		break;
	case 64:
		code = BFD_RELOC_64;
		break;
	default:
		DIE;
	}

	arelent *reloc = malloc(sizeof(*reloc));
	reloc->sym_ptr_ptr = symp;
	reloc->address = addr - ss->contents.data;
	reloc->howto = bfd_reloc_type_lookup(ss->parent->abfd, code);
	reloc->addend = offset;
	return reloc;
}

void write_reloc(struct supersect *ss, const void *addr, asymbol **symp,
		 bfd_vma offset)
{
	*vec_grow(&ss->new_relocs, 1) = create_reloc(ss, addr, symp, offset);
}

void write_string(struct supersect *ss, const char **addr, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	struct supersect *str_ss = make_section(ss->parent, ".ksplice_str");
	char *buf = sect_grow(str_ss, len + 1, char);
	va_start(ap, fmt);
	vsnprintf(buf, len + 1, fmt, ap);
	va_end(ap);

	write_reloc(ss, addr, &str_ss->symbol,
		    (void *)buf - str_ss->contents.data);
}

void lookup_system_map(struct addr_vec *addrs, const char *name, long offset)
{
	struct addr_vec *map_addrs =
	    addr_vec_hash_lookup(&system_map, name, FALSE);
	if (map_addrs == NULL)
		return;

	unsigned long *addr, *map_addr;
	for (map_addr = map_addrs->data;
	     map_addr < map_addrs->data + map_addrs->size; map_addr++) {
		for (addr = addrs->data; addr < addrs->data + addrs->size;
		     addr++) {
			if (*addr == *map_addr + offset)
				break;
		}
		if (addr < addrs->data + addrs->size)
			continue;
		*vec_grow(addrs, 1) = *map_addr + offset;
	}
}

void write_system_map_array(struct superbfd *sbfd, struct supersect *ss,
			    const unsigned long **sym_addrs,
			    unsigned long *num_sym_addrs, asymbol *sym)
{
	struct addr_vec addrs;
	vec_init(&addrs);

	if (bfd_is_abs_section(sym->section)) {
		*vec_grow(&addrs, 1) = sym->value;
	} else if (bfd_is_und_section(sym->section)) {
		lookup_system_map(&addrs, sym->name, 0);
	} else if (!bfd_is_const_section(sym->section)) {
		asymbol **gsymp;
		for (gsymp = sbfd->syms.data;
		     gsymp < sbfd->syms.data + sbfd->syms.size; gsymp++) {
			asymbol *gsym = *gsymp;
			if ((gsym->flags & BSF_DEBUGGING) == 0 &&
			    gsym->section == sym->section)
				lookup_system_map(&addrs, gsym->name,
						  sym->value - gsym->value);
		}
	}

	*num_sym_addrs = addrs.size;
	if (addrs.size != 0) {
		struct supersect *array_ss = make_section(sbfd,
							  ".ksplice_array");
		void *buf = sect_grow(array_ss, addrs.size,
				      typeof(*addrs.data));
		memcpy(buf, addrs.data, addrs.size * sizeof(*addrs.data));
		write_reloc(ss, sym_addrs, &array_ss->symbol,
			    buf - array_ss->contents.data);
	} else {
		*sym_addrs = NULL;
	}

	vec_free(&addrs);
}

struct caller_search {
	struct superbfd *sbfd;
	asymbol *sym;
	asection *calling_section;
	int count;
};

void search_for_caller(bfd *abfd, asection *sect, void *searchptr)
{
	struct caller_search *search = searchptr;
	struct superbfd *sbfd = search->sbfd;
	struct supersect *ss = fetch_supersect(sbfd, sect);
	arelent **relocp;

	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		asymbol *rsym = *(*relocp)->sym_ptr_ptr;
		if (rsym->section == search->sym->section &&
		    rsym->value + get_reloc_offset(ss, *relocp, 1) ==
		    search->sym->value) {
			if (search->calling_section != sect)
				search->count++;
			if (search->calling_section == NULL)
				search->calling_section = sect;
		}
	}
}

static const char *find_caller(struct supersect *ss, asymbol *sym)
{
	struct caller_search search = {
		.sym = sym,
		.sbfd = ss->parent,
		.count = 0,
		.calling_section = NULL,
	};

	bfd_map_over_sections(ss->parent->abfd, search_for_caller, &search);
	if (search.count == 1) {
		return search.calling_section->name;
	} else if (search.count == 0) {
		fprintf(stderr, "No callers found in caller search: %s\n",
			sym->name);
		return "no caller";
	} else {
		fprintf(stderr, "Multiple candidates in caller search: %s: "
			"%d\n", sym->name, search.count);
		return "multiple callers";
	}
}

const char *static_local_symbol(struct superbfd *sbfd, asymbol *sym)
{
	struct supersect *ss = fetch_supersect(sbfd, sym->section);
	if ((sym->flags & BSF_LOCAL) == 0 || (sym->flags & BSF_OBJECT) == 0)
		return NULL;
	char *dot = strrchr(sym->name, '.');
	if (dot == NULL || dot[1 + strspn(dot + 1, "0123546789")] != '\0')
		return NULL;
	char *basename = strndup(sym->name, dot - sym->name);
	char *mangled_name;
	if (strcmp(basename, "__func__") == 0 ||
	    strcmp(basename, "__PRETTY_FUNCTION__") == 0)
		assert(asprintf(&mangled_name, "%s<%s>", basename,
				(char *)ss->contents.data + sym->value) >= 0);
	else
		assert(asprintf(&mangled_name, "%s<%s>", basename,
				find_caller(ss, sym)) >= 0);
	return mangled_name;
}

void write_ksplice_symbol(struct supersect *ss,
			  const struct ksplice_symbol *const *addr,
			  asymbol *sym, const char *addstr_sect)
{
	struct supersect *ksymbol_ss = make_section(ss->parent,
						    ".ksplice_symbols");
	struct ksplice_symbol *ksymbol = sect_grow(ksymbol_ss, 1,
						   struct ksplice_symbol);

	if (bfd_is_und_section(sym->section) || (sym->flags & BSF_GLOBAL) != 0) {
		write_string(ksymbol_ss, &ksymbol->name, "%s", sym->name);
		write_string(ksymbol_ss, &ksymbol->label, "%s%s", sym->name,
			     addstr_sect);
	} else if (bfd_is_const_section(sym->section)) {
		ksymbol->name = NULL;
		write_string(ksymbol_ss, &ksymbol->label, "%s%s%s",
			     sym->name, addstr_all, addstr_sect);
	} else {
		const struct asymbolp_vec *syms = &ss->parent->syms;
		asymbol **gsymp;
		asymbol *gsym = NULL;
		for (gsymp = syms->data; gsymp < syms->data + syms->size;
		     gsymp++) {
			asymbol *gsymtemp = *gsymp;
			if ((gsymtemp->flags & BSF_DEBUGGING) != 0 ||
			    sym->section != gsymtemp->section ||
			    sym->value != gsymtemp->value)
				continue;
			if (gsym == NULL || (gsymtemp->flags & BSF_GLOBAL) != 0)
				gsym = gsymtemp;
		}

		if (gsym == NULL)
			ksymbol->name = NULL;
		else
			write_string(ksymbol_ss, &ksymbol->name, "%s",
				     gsym->name);

		if (gsym == NULL)
			write_string(ksymbol_ss, &ksymbol->label, "%s+%lx%s%s",
				     sym->section->name,
				     (unsigned long)sym->value, addstr_all,
				     addstr_sect);
		else if ((gsym->flags & BSF_GLOBAL) != 0)
			write_string(ksymbol_ss, &ksymbol->label, "%s%s",
				     gsym->name, addstr_sect);
		else if (static_local_symbol(ss->parent, gsym))
			write_string(ksymbol_ss, &ksymbol->label, "%s+%lx%s%s",
				     static_local_symbol(ss->parent, gsym),
				     (unsigned long)sym->value,
				     addstr_all, addstr_sect);
		else
			write_string(ksymbol_ss, &ksymbol->label, "%s%s%s",
				     gsym->name, addstr_all, addstr_sect);
	}

	write_system_map_array(ss->parent, ksymbol_ss, &ksymbol->candidates,
			       &ksymbol->nr_candidates, sym);

	write_reloc(ss, addr, &ksymbol_ss->symbol,
		    (void *)ksymbol - ksymbol_ss->contents.data);
}

void write_ksplice_reloc(struct supersect *ss, arelent *orig_reloc)
{
	asymbol *sym_ptr = *orig_reloc->sym_ptr_ptr;

	reloc_howto_type *howto = orig_reloc->howto;

	bfd_vma addend = get_reloc_offset(ss, orig_reloc, 0);
	blot_section(ss, orig_reloc->address, howto);

	struct supersect *kreloc_ss = make_section(ss->parent,
						   mode("rmsyms") ?
						   ".ksplice_init_relocs" :
						   ".ksplice_relocs");
	struct ksplice_reloc *kreloc = sect_grow(kreloc_ss, 1,
						 struct ksplice_reloc);

	write_reloc(kreloc_ss, &kreloc->blank_addr,
		    &ss->symbol, orig_reloc->address);
	kreloc->blank_offset = (unsigned long)orig_reloc->address;
	write_ksplice_symbol(kreloc_ss, &kreloc->symbol, sym_ptr, "");
	kreloc->pcrel = howto->pc_relative;
	kreloc->addend = addend;
	kreloc->size = bfd_get_reloc_size(howto);
	kreloc->dst_mask = howto->dst_mask;
	kreloc->rightshift = howto->rightshift;
	kreloc->signed_addend =
	    (howto->complain_on_overflow == complain_overflow_signed) ||
	    (howto->complain_on_overflow == complain_overflow_bitfield);
}

#define CANARY(x, canary) ((x & ~howto->dst_mask) | (canary & howto->dst_mask))

void blot_section(struct supersect *ss, int offset, reloc_howto_type *howto)
{
	int bits = bfd_get_reloc_size(howto) * 8;
	void *address = ss->contents.data + offset;
	bfd_vma x = bfd_get(bits, ss->parent->abfd, address);
	x = (x & ~howto->dst_mask) |
	    ((bfd_vma)0x7777777777777777LL & howto->dst_mask);
	bfd_put(bits, ss->parent->abfd, x, address);
}

void write_ksplice_size(struct superbfd *sbfd, asymbol **symp)
{
	asymbol *sym = *symp;

	/* We call bfd_print_symbol in order to get access to
	 * the size associated with the function symbol, which
	 * is not otherwise available through the BFD API
	 */
	char *buf = NULL;
	size_t bufsize = 0;
	FILE *fp = open_memstream(&buf, &bufsize);
	bfd_print_symbol(sbfd->abfd, fp, sym, bfd_print_symbol_all);
	fclose(fp);
	assert(buf != NULL);

	unsigned long symsize;
	char *symname;
	int len;
	assert(sscanf(buf, "%*[^\t]\t%lx %as%n", &symsize, &symname, &len) >=
	       2);
	assert(buf[len] == '\0');
	assert(strcmp(symname, sym->name) == 0);
	free(symname);
	free(buf);

	struct supersect *ksize_ss = make_section(sbfd, ".ksplice_sizes");
	struct ksplice_size *ksize = sect_grow(ksize_ss, 1,
					       struct ksplice_size);

	write_ksplice_symbol(ksize_ss, &ksize->symbol, sym,
			     mode("keep-primary") ? "(post)" : "");
	ksize->size = symsize;
	ksize->extended_size = bfd_get_section_size(sym->section);
	ksize->flags = 0;
	if (mode("keep-helper") &&
	    str_in_set(sym->name, &delsyms) && (sym->flags & BSF_FUNCTION))
		ksize->flags |= KSPLICE_SIZE_DELETED;
	if (starts_with(sym->section->name, ".rodata"))
		ksize->flags |= KSPLICE_SIZE_RODATA;
	if (starts_with(sym->section->name, ".data"))
		ksize->flags |= KSPLICE_SIZE_DATA;
	if (starts_with(sym->section->name, ".text") ||
	    starts_with(sym->section->name, ".exit.text"))
		ksize->flags |= KSPLICE_SIZE_TEXT;
	assert(ksize->flags != 0);
	write_reloc(ksize_ss, &ksize->thismod_addr, symp, 0);
}

void write_ksplice_patch(struct superbfd *sbfd, const char *symname)
{
	struct supersect *kpatch_ss = make_section(sbfd, ".ksplice_patches");
	struct ksplice_patch *kpatch = sect_grow(kpatch_ss, 1,
						 struct ksplice_patch);

	asymbol **symp;
	for (symp = sbfd->syms.data; symp < sbfd->syms.data + sbfd->syms.size;
	     symp++) {
		if (strcmp((*symp)->name, symname) == 0)
			break;
	}
	assert(symp < sbfd->syms.data + sbfd->syms.size);

	write_ksplice_symbol(kpatch_ss, &kpatch->symbol, *symp, "");
	write_ksplice_reloc(kpatch_ss, create_reloc(kpatch_ss, &kpatch->oldaddr,
						    symp, 0));
	write_reloc(kpatch_ss, &kpatch->repladdr, symp, 0);
}

void write_ksplice_export(struct superbfd *sbfd, const char *symname,
			  const char *export_type, int del)
{
	struct supersect *export_ss = make_section(sbfd, ".ksplice_exports");
	struct ksplice_export *export = sect_grow(export_ss, 1,
						  struct ksplice_export);

	write_string(export_ss, &export->type, "%s", export_type);
	if (del) {
		write_string(export_ss, &export->name, "%s", symname);
		write_string(export_ss, &export->new_name,
			     "DISABLED_%s_%s", symname, kid);
	} else {
		write_string(export_ss, &export->new_name, "%s", symname);
		write_string(export_ss, &export->name, "DISABLED_%s_%s",
			     symname, kid);
	}
}

void rm_from_special(struct superbfd *sbfd, const struct specsect *s)
{
	asection *isection = bfd_get_section_by_name(sbfd->abfd, s->sectname);
	if (isection == NULL)
		return;

	struct supersect *ss = fetch_supersect(sbfd, isection), orig_ss;
	supersect_move(&orig_ss, ss);

	const void *orig_entry;
	for (orig_entry = orig_ss.contents.data;
	     orig_entry < orig_ss.contents.data + orig_ss.contents.size;
	     orig_entry += align(s->entry_size, 1 << ss->alignment)) {
		asymbol *sym;
		read_reloc(&orig_ss, orig_entry, sizeof(void *), &sym);

		asection *p;
		for (p = sbfd->abfd->sections; p != NULL; p = p->next) {
			if (sym->section == p
			    && !is_special(p) && !want_section(p))
				break;
		}
		if (p != NULL)
			continue;

		sect_copy(ss, sect_do_grow(ss, 1, s->entry_size,
					   1 << ss->alignment),
			  &orig_ss, orig_entry, s->entry_size);
	}
}

void mark_wanted_if_referenced(bfd *abfd, asection *sect, void *ignored)
{
	if (want_section(sect))
		return;
	if (!starts_with(sect->name, ".text")
	    && !starts_with(sect->name, ".exit.text")
	    && !starts_with(sect->name, ".rodata")
	    && !(starts_with(sect->name, ".data") && mode("keep-helper")))
		return;

	if (mode("keep-helper")) {
		struct superbfd *sbfd = fetch_superbfd(abfd);
		asymbol **symp;
		for (symp = sbfd->syms.data;
		     symp < sbfd->syms.data + sbfd->syms.size; symp++) {
			asymbol *sym = *symp;
			if (sym->section == sect &&
			    (sym->flags & BSF_GLOBAL) != 0) {
				struct wsect *w = malloc(sizeof(*w));
				w->sect = sect;
				w->next = wanted_sections;
				wanted_sections = w;
				return;
			}
		}
	}

	bfd_map_over_sections(abfd, check_for_ref_to_section, sect);
}

void check_for_ref_to_section(bfd *abfd, asection *looking_at,
			      void *looking_for)
{
	if (!want_section(looking_at) || is_special(looking_at))
		return;

	struct superbfd *sbfd = fetch_superbfd(abfd);
	struct supersect *ss = fetch_supersect(sbfd, looking_at);
	arelent **relocp;
	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		asymbol *sym = *(*relocp)->sym_ptr_ptr;
		if (sym->section == (asection *)looking_for &&
		    (!starts_with(sym->section->name, ".text") ||
		     get_reloc_offset(ss, *relocp, 1) != 0)) {
			struct wsect *w = malloc(sizeof(*w));
			w->sect = looking_for;
			w->next = wanted_sections;
			wanted_sections = w;
			break;
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

	struct supersect *new_supersects = fetch_superbfd(ibfd)->new_supersects;
	struct supersect *ss;
	for (ss = new_supersects; ss != NULL; ss = ss->next)
		setup_new_section(obfd, ss);

	/* Mark symbols used in output relocations so that they
	   are kept, even if they are local labels or static symbols.

	   Note we iterate over the input sections examining their
	   relocations since the relocations for the output sections
	   haven't been set yet.  mark_symbols_used_in_relocations will
	   ignore input sections which have no corresponding output
	   section.  */

	bfd_map_over_sections(ibfd, mark_symbols_used_in_relocations, NULL);
	for (ss = new_supersects; ss != NULL; ss = ss->next)
		ss_mark_symbols_used_in_relocations(ss);
	struct asymbolp_vec osyms;
	vec_init(&osyms);
	filter_symbols(ibfd, obfd, &osyms, &fetch_superbfd(ibfd)->syms);

	bfd_set_symtab(obfd, osyms.data, osyms.size);

	/* This has to happen after the symbol table has been set.  */
	bfd_map_over_sections(obfd, write_section, NULL);

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

	if (!want_section(isection))
		return;

	asection *osection = bfd_make_section_anyway(obfd, isection->name);
	assert(osection != NULL);

	struct superbfd *isbfd = fetch_superbfd(ibfd);
	struct supersect *ss = fetch_supersect(isbfd, isection);
	osection->userdata = ss;
	bfd_set_section_flags(obfd, osection, ss->flags);
	ss->symbol = osection->symbol;
	assert(bfd_set_section_size(obfd, osection, ss->contents.size));

	vma = bfd_section_vma(ibfd, isection);
	assert(bfd_set_section_vma(obfd, osection, vma));

	osection->lma = isection->lma;
	assert(bfd_set_section_alignment(obfd, osection, ss->alignment));
	osection->entsize = isection->entsize;
	osection->output_section = osection;
	osection->output_offset = 0;
	isection->output_section = osection;
	isection->output_offset = 0;
	return;
}

void setup_new_section(bfd *obfd, struct supersect *ss)
{
	asection *osection = bfd_make_section_anyway(obfd, ss->name);
	assert(osection != NULL);
	bfd_set_section_flags(obfd, osection, ss->flags);

	osection->userdata = ss;
	ss->symbol = osection->symbol;
	assert(bfd_set_section_size(obfd, osection, ss->contents.size));
	assert(bfd_set_section_vma(obfd, osection, 0));

	osection->lma = 0;
	assert(bfd_set_section_alignment(obfd, osection, ss->alignment));
	osection->entsize = 0;
	osection->output_section = osection;
	osection->output_offset = 0;
}

void write_section(bfd *obfd, asection *osection, void *arg)
{
	struct supersect *ss = osection->userdata;

	if ((ss->flags & SEC_GROUP) != 0 || ss->contents.size == 0)
		return;

	arelent **relocp;
	char *error_message;
	for (relocp = ss->new_relocs.data;
	     relocp < ss->new_relocs.data + ss->new_relocs.size; relocp++) {
		bfd_put(bfd_get_reloc_size((*relocp)->howto) * 8, obfd, 0,
			ss->contents.data + (*relocp)->address);
		if (bfd_install_relocation(obfd, *relocp, ss->contents.data,
					   0, osection, &error_message) !=
		    bfd_reloc_ok) {
			fprintf(stderr, "ksplice: error installing reloc: %s",
				error_message);
			DIE;
		}
	}
	memcpy(vec_grow(&ss->relocs, ss->new_relocs.size), ss->new_relocs.data,
	       ss->new_relocs.size * sizeof(*ss->new_relocs.data));

	bfd_set_reloc(obfd, osection,
		      ss->relocs.size == 0 ? NULL : ss->relocs.data,
		      ss->relocs.size);

	if (ss->flags & SEC_HAS_CONTENTS)
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
void mark_symbols_used_in_relocations(bfd *abfd, asection *isection,
				      void *ignored)
{
	struct superbfd *sbfd = fetch_superbfd(abfd);
	if (isection->output_section == NULL)
		return;

	struct supersect *ss = fetch_supersect(sbfd, isection);
	ss_mark_symbols_used_in_relocations(ss);
}

void ss_mark_symbols_used_in_relocations(struct supersect *ss)
{
	/* Examine each symbol used in a relocation.  If it's not one of the
	   special bfd section symbols, then mark it with BSF_KEEP.  */
	arelent **relocp;
	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		asymbol *sym = *(*relocp)->sym_ptr_ptr;
		if (!(bfd_is_const_section(sym->section) &&
		      sym == sym->section->symbol))
			sym->flags |= BSF_KEEP;
	}
}

/* Modified function from GNU Binutils objcopy.c
 *
 * Choose which symbol entries to copy.
 * We don't copy in place, because that confuses the relocs.
 * Return the number of symbols to print.
 */
void filter_symbols(bfd *ibfd, bfd *obfd, struct asymbolp_vec *osyms,
		    struct asymbolp_vec *isyms)
{
	asymbol **symp;
	for (symp = isyms->data; symp < isyms->data + isyms->size; symp++) {
		asymbol *sym = *symp;

		int keep;

		if (mode("keep") && (sym->flags & BSF_GLOBAL) != 0 &&
		    !(mode("keep-primary") && str_in_set(sym->name, &newsyms)))
			sym->flags = (sym->flags & ~BSF_GLOBAL) | BSF_LOCAL;

		if (mode("finalize") && (sym->flags & BSF_GLOBAL) != 0)
			sym->flags = (sym->flags & ~BSF_GLOBAL) | BSF_LOCAL;

		if ((sym->flags & BSF_KEEP) != 0	/* Used in relocation.  */
		    || ((sym->flags & BSF_SECTION_SYM) != 0
			&& ((*(sym->section)->symbol_ptr_ptr)->flags
			    & BSF_KEEP) != 0))
			keep = 1;
		else if ((sym->flags & (BSF_GLOBAL | BSF_WEAK)) != 0)
			keep = 1;
		else if (bfd_decode_symclass(sym) == 'I')
			/* Global symbols in $idata sections need to be retained.
			   External users of the  library containing the $idata
			   section may reference these symbols.  */
			keep = 1;
		else if ((sym->flags & BSF_GLOBAL) != 0
			 || (sym->flags & BSF_WEAK) != 0
			 || bfd_is_com_section(sym->section))
			keep = 1;
		else if ((sym->flags & BSF_DEBUGGING) != 0)
			keep = 1;
		else
			keep = !bfd_is_local_label(ibfd, sym);

		if (!want_section(sym->section))
			keep = 0;

		if (mode("rmsyms") && match_varargs(sym->name))
			keep = 0;

		if (keep)
			*vec_grow(osyms, 1) = sym;
	}
}

int match_varargs(const char *str)
{
	int i;
	for (i = 0; i < varargs_count; i++) {
		if (strcmp(str, varargs[i]) == 0)
			return 1;
	}
	return 0;
}

void read_str_set(struct str_vec *strs)
{
	char *buf = NULL;
	size_t n = 0;
	assert(getline(&buf, &n, stdin) >= 0);
	vec_init(strs);
	char *saveptr;
	while (1) {
		char *str = strtok_r(buf, " \n", &saveptr);
		buf = NULL;
		if (str == NULL)
			break;
		*vec_grow(strs, 1) = str;
	}
}

int str_in_set(const char *str, const struct str_vec *strs)
{
	const char **strp;
	for (strp = strs->data; strp < strs->data + strs->size; strp++) {
		if (strcmp(str, *strp) == 0)
			return 1;
	}
	return 0;
}

int want_section(asection *sect)
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

	if (mode("keep-primary") && bfd_is_abs_section(sect))
		return 1;
	const struct wsect *w = wanted_sections;
	for (; w != NULL; w = w->next) {
		if (w->sect == sect)
			return 1;
	}

	if (starts_with(sect->name, ".ksplice"))
		return 1;
	if (mode("keep-helper") && starts_with(sect->name, ".text"))
		return 1;
	if (mode("keep-helper") && starts_with(sect->name, ".exit.text")
	    && bfd_get_section_by_name(sect->owner, ".exitcall.exit") == NULL)
		return 1;
	if (mode("keep-primary") && starts_with(sect->name, "__ksymtab"))
		return 1;
	if (mode("keep-primary") && starts_with(sect->name, "__kcrctab"))
		return 1;
	if (mode("keep-primary") && str_in_set(sect->name, &sections))
		return 1;

	int i;
	for (i = 0; static_want[i] != NULL; i++) {
		if (strcmp(sect->name, static_want[i]) == 0)
			return 1;
	}
	return 0;
}

const struct specsect *is_special(asection *sect)
{
	const struct specsect *ss;
	for (ss = special_sections; ss != end_special_sections; ss++) {
		if (strcmp(ss->sectname, sect->name) == 0)
			return ss;
	}
	return NULL;
}
