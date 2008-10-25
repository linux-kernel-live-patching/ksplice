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
 * two arguments are always an input object file and an output object file.
 *
 * - keep-primary: "objmanip <post.o> <out.o> keep-primary <pre.o> <kid>"
 *
 * This mode prepares the object file to be installed as a ksplice update.  The
 * kid argument is the ksplice id string for the ksplice update being built.
 *
 * - keep-helper: "objmanip <pre.o> <out.o> keep-helper"
 *
 * This mode prepares the object file to be used for run-pre matching.  This
 * involves replacing all ELF relocations with ksplice relocations and
 * writing ksplice_section structures for each ELF text or data section.
 *
 * - rmsyms mode: "objmanip <in.o> <out.o> rmsyms
 *
 * In this mode, any ELF relocations involving the list of symbol names given on
 * standard input are replaced with ksplice relocations.  This is used only
 * for KSPLICE_STANDALONE.
 *
 * - finalize mode: "objmanip <in.o> <out.o> finalize"
 *
 * In this mode, any ELF relocations to undefined symbols are replaced with
 * ksplice relocations.
 */

/* Always define KSPLICE_STANDALONE, even if you're using integrated Ksplice.
   objmanip won't compile without it. */
#define KSPLICE_STANDALONE

#define _GNU_SOURCE
#include "objcommon.h"
#include "kmodsrc/ksplice.h"
#include "kmodsrc/offsets.h"
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#define KSPLICE_SYMBOL_STR "KSPLICE_SYMBOL_"

#define symbol_init(sym) *(sym) = (asymbol *)NULL
DEFINE_HASH_TYPE(asymbol *, symbol_hash, symbol_hash_init, symbol_hash_free,
		 symbol_hash_lookup, symbol_init);

struct export {
	const char *name;
	struct supersect *ss;
};
DECLARE_VEC_TYPE(struct export, export_vec);

DECLARE_VEC_TYPE(const char *, str_vec);

DECLARE_VEC_TYPE(unsigned long, ulong_vec);

struct export_desc {
	const char *export_type;
	bool deletion;
	struct str_vec names;
	struct supersect *sym_ss;
	struct supersect *crc_ss;
};
DECLARE_VEC_TYPE(struct export_desc, export_desc_vec);

#define bool_init(b) *(b) = false
DEFINE_HASH_TYPE(bool, bool_hash, bool_hash_init, bool_hash_free,
		 bool_hash_lookup, bool_init);

#define ulong_init(x) *(x) = 0
DEFINE_HASH_TYPE(unsigned long, ulong_hash, ulong_hash_init,
		 ulong_hash_free, ulong_hash_lookup, ulong_init);

void do_keep_primary(struct superbfd *isbfd, const char *pre);
void do_keep_helper(struct superbfd *isbfd);
void do_finalize(struct superbfd *isbfd);
void do_rmsyms(struct superbfd *isbfd);

struct export_vec *get_export_syms(struct superbfd *sbfd);
void compare_exported_symbols(struct superbfd *oldsbfd,
			      struct superbfd *newsbfd, bool deletion);
struct export_desc *new_export_desc(struct supersect *ss, bool deletion);
bool relocs_equal(struct supersect *old_src_ss, struct supersect *new_src_ss,
		  arelent *old_reloc, arelent *new_reloc);
bfd_vma non_dst_mask(struct supersect *ss, arelent *reloc);
bool all_relocs_equal(struct span *old_span, struct span *new_span);
static bool part_of_reloc(struct supersect *ss, unsigned long addr);
static bool nonrelocs_equal(struct span *old_span, struct span *new_span);
static void handle_section_symbol_renames(struct superbfd *oldsbfd,
					  struct superbfd *newsbfd);

enum supersect_type supersect_type(struct supersect *ss);
void initialize_supersect_types(struct superbfd *sbfd);
static void initialize_spans(struct superbfd *sbfd);
static void initialize_string_spans(struct supersect *ss);
static void initialize_table_spans(struct superbfd *sbfd,
				   struct table_section *s);
static void initialize_table_section_spans(struct superbfd *sbfd);
struct span *reloc_target_span(struct supersect *ss, arelent *reloc);
struct span *find_span(struct supersect *ss, bfd_size_type address);
void remove_unkept_spans(struct superbfd *sbfd);
void compute_span_shifts(struct superbfd *sbfd);
static struct span *new_span(struct supersect *ss, bfd_vma start, bfd_vma size);
bool is_table_section(const char *name, bool consider_other);
const struct table_section *get_table_section(const char *name);
void mangle_section_name(struct superbfd *sbfd, const char *name);

void rm_relocs(struct superbfd *isbfd);
void rm_some_relocs(struct supersect *ss);
void write_ksplice_reloc(struct supersect *ss, arelent *orig_reloc);
static void write_ksplice_reloc_howto(struct supersect *ss, const
				      struct ksplice_reloc_howto *const *addr,
				      reloc_howto_type *howto);
static void write_ksplice_date_reloc(struct supersect *ss, unsigned long offset,
				     const char *str,
				     enum ksplice_reloc_howto_type type);
static void write_ksplice_nonreloc_howto(struct supersect *ss,
					 const struct ksplice_reloc_howto
					 *const *addr,
					 enum ksplice_reloc_howto_type type,
					 int size);
static void write_date_relocs(struct superbfd *sbfd, const char *str,
			      enum ksplice_reloc_howto_type type);
static void write_table_relocs(struct superbfd *sbfd, const char *sectname,
			       enum ksplice_reloc_howto_type type);
static void write_ksplice_table_reloc(struct supersect *ss,
				      unsigned long address,
				      const char *label,
				      enum ksplice_reloc_howto_type type);
static void write_ksplice_ignore_reloc(struct supersect *ss,
				       unsigned long address,
				       bfd_size_type size);
void load_ksplice_symbol_offsets(struct superbfd *sbfd);
void blot_section(struct supersect *ss, int offset, reloc_howto_type *howto);
static void write_ksplice_section(struct span *span);
void write_ksplice_patch(struct superbfd *sbfd, struct span *span);
void write_ksplice_deleted_patch(struct superbfd *sbfd, const char *name,
				 const char *label, const char *sectname);
asymbol **make_undefined_symbolp(struct superbfd *sbfd, const char *name);
void filter_table_sections(struct superbfd *isbfd);
void filter_table_section(struct superbfd *sbfd, const struct table_section *s);
void keep_referenced_sections(struct superbfd *sbfd);
bfd_boolean copy_object(bfd *ibfd, bfd *obfd);
void setup_section(bfd *ibfd, asection *isection, void *obfdarg);
static void setup_new_section(bfd *obfd, struct supersect *ss);
static void write_section(bfd *obfd, asection *osection, void *arg);
static void delete_obsolete_relocs(struct supersect *ss);
void mark_symbols_used_in_relocations(bfd *abfd, asection *isection,
				      void *ignored);
static void ss_mark_symbols_used_in_relocations(struct supersect *ss);
void filter_symbols(bfd *ibfd, bfd *obfd, struct asymbolp_vec *osyms,
		    struct asymbolp_vec *isyms);
static bool deleted_table_section_symbol(bfd *abfd, asymbol *sym);
void read_str_set(struct str_vec *strs);
bool str_in_set(const char *str, const struct str_vec *strs);
struct supersect *__attribute((format(printf, 2, 3)))
make_section(struct superbfd *sbfd, const char *fmt, ...);
void __attribute__((format(printf, 3, 4)))
write_string(struct supersect *ss, const char **addr, const char *fmt, ...);
void rm_some_exports(struct superbfd *isbfd, const struct export_desc *ed);
void write_ksplice_export(struct superbfd *sbfd, const char *symname,
			  const char *export_type, bool del);
void write_reloc(struct supersect *ss, const void *addr, asymbol **symp,
		 bfd_vma offset);
arelent *create_reloc(struct supersect *ss, const void *addr, asymbol **symp,
		      bfd_vma offset);
static void foreach_symbol_pair(struct superbfd *oldsbfd, struct superbfd *newsbfd,
				void (*fn)(struct span *old_span,
					   asymbol *oldsym,
					   struct span *new_span,
					   asymbol *newsym));
static void check_global_symbols(struct span *old_span, asymbol *oldsym,
				 struct span *new_span, asymbol *newsym);
static void match_global_symbols(struct span *old_span, asymbol *oldsym,
				 struct span *new_span, asymbol *newsym);
static void match_symbol_spans(struct span *old_span, asymbol *oldsym,
			       struct span *new_span, asymbol *newsym);

static void foreach_span_pair(struct superbfd *oldsbfd,
			      struct superbfd *newsbfd,
			      void (*fn)(struct span *old_span,
					 struct span *new_span));
static void match_spans_by_label(struct span *old_span, struct span *new_span);
static void match_string_spans(struct span *old_span, struct span *new_span);
static void mark_new_spans(struct superbfd *sbfd);
static void handle_deleted_spans(struct superbfd *oldsbfd,
				 struct superbfd *newsbfd);
static void compare_matched_spans(struct superbfd *newsbfd);
static void compare_spans(struct span *old_span, struct span *new_span);
static void update_nonzero_offsets(struct superbfd *sbfd);
static void handle_nonzero_offset_relocs(struct supersect *ss);
static void keep_span(struct span *span);

static void init_objmanip_superbfd(struct superbfd *sbfd);
static const char *label_lookup(struct superbfd *sbfd, asymbol *sym);
static void label_map_set(struct superbfd *sbfd, const char *oldlabel,
			  const char *label);
static void print_label_changes(struct superbfd *sbfd);
static void init_label_map(struct superbfd *sbfd);
static asymbol **symbolp_scan(struct supersect *ss, bfd_vma value);
static void init_csyms(struct superbfd *sbfd);
static void init_callers(struct superbfd *sbfd);
static asymbol *canonical_symbol(struct superbfd *sbfd, asymbol *sym);
static asymbol **canonical_symbolp(struct superbfd *sbfd, asymbol *sym);
static char *static_local_symbol(struct superbfd *sbfd, asymbol *sym);
static char *symbol_label(struct superbfd *sbfd, asymbol *sym);

int verbose = 0;
#define debug_(sbfd, level, fmt, ...)					\
	do {								\
		if (verbose >= (level))					\
			printf("%s: " fmt, (sbfd)->abfd->filename,	\
			       ## __VA_ARGS__);				\
	} while (0)
#define debug0(sbfd, fmt, ...) debug_(sbfd, 0, fmt, ## __VA_ARGS__)
#define debug1(sbfd, fmt, ...) debug_(sbfd, 1, fmt, ## __VA_ARGS__)
#define err(sbfd, fmt, ...)						\
	do {								\
		fprintf(stderr, "%s: " fmt, (sbfd)->abfd->filename,	\
			## __VA_ARGS__);				\
	} while (0)

struct str_vec delsects, rmsyms;
struct export_desc_vec exports;
bool changed;

struct ksplice_config *config;

const char *modestr, *kid, *finalize_target = NULL;
bool write_output = true;

struct superbfd *offsets_sbfd = NULL;

#define mode(str) starts_with(modestr, str)

DECLARE_VEC_TYPE(unsigned long, addr_vec);
DEFINE_HASH_TYPE(struct addr_vec, addr_vec_hash,
		 addr_vec_hash_init, addr_vec_hash_free, addr_vec_hash_lookup,
		 vec_init);
struct addr_vec_hash system_map;

struct bool_hash system_map_written;
struct ulong_hash ksplice_symbol_offset;
struct ulong_hash ksplice_howto_offset;
struct ulong_hash ksplice_string_offset;

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

void load_ksplice_symbol_offsets(struct superbfd *sbfd)
{
	asection *sect = bfd_get_section_by_name(sbfd->abfd,
						 ".ksplice_symbols");
	if (sect == NULL)
		return;
	struct supersect *ss = fetch_supersect(sbfd, sect);

	struct ksplice_symbol *ksym;
	for (ksym = ss->contents.data;
	     (void *)ksym < ss->contents.data + ss->contents.size; ksym++) {
		const char *label = read_string(ss, &ksym->label);
		unsigned long *ksymbol_offp =
		    ulong_hash_lookup(&ksplice_symbol_offset, label, TRUE);
		*ksymbol_offp = addr_offset(ss, ksym);
	}
}

void load_offsets()
{
	char *kmodsrc = getenv("KSPLICE_KMODSRC"), *offsets_file;
	assert(kmodsrc != NULL);
	assert(asprintf(&offsets_file, "%s/offsets.o", kmodsrc) >= 0);
	bfd *offsets_bfd = bfd_openr(offsets_file, NULL);
	assert(offsets_bfd != NULL);
	char **matching;
	assert(bfd_check_format_matches(offsets_bfd, bfd_object, &matching));
	offsets_sbfd = fetch_superbfd(offsets_bfd);

	asection *config_sect = bfd_get_section_by_name(offsets_sbfd->abfd,
							".ksplice_config");
	struct supersect *config_ss =
	    fetch_supersect(offsets_sbfd, config_sect);

	config = config_ss->contents.data;
}

bool matchable_data_section(struct supersect *ss)
{
	if (ss->type == SS_TYPE_STRING)
		return true;
	if (ss->type == SS_TYPE_RODATA)
		return true;
	if (ss->type == SS_TYPE_DATA && ss->relocs.size != 0)
		return true;
	return false;
}

bool unchangeable_section(struct supersect *ss)
{
	if (ss->type == SS_TYPE_DATA)
		return true;
	if (ss->type == SS_TYPE_IGNORED && !starts_with(ss->name, ".debug") &&
	    strcmp(ss->name, "__ksymtab_strings") != 0)
		return true;
	return false;
}

int main(int argc, char *argv[])
{
	if (getenv("KSPLICE_VERBOSE") != NULL)
		verbose = atoi(getenv("KSPLICE_VERBOSE"));

	bfd_init();
	bfd *ibfd = bfd_openr(argv[1], NULL);
	assert(ibfd);

	char **matching;
	assert(bfd_check_format_matches(ibfd, bfd_object, &matching));

	const char *output_target = bfd_get_target(ibfd);

	load_system_map();
	load_offsets();

	bool_hash_init(&system_map_written);
	ulong_hash_init(&ksplice_symbol_offset);
	ulong_hash_init(&ksplice_howto_offset);
	ulong_hash_init(&ksplice_string_offset);

	struct superbfd *isbfd = fetch_superbfd(ibfd);

	modestr = argv[3];
	if (mode("finalize"))
		finalize_target = argv[4];
	init_objmanip_superbfd(isbfd);
	if (mode("keep-primary")) {
		kid = argv[5];
		do_keep_primary(isbfd, argv[4]);
	} else if (mode("keep-helper")) {
		do_keep_helper(isbfd);
	} else if (mode("finalize")) {
		do_finalize(isbfd);
	} else if (mode("rmsyms")) {
		do_rmsyms(isbfd);
	}

	if (write_output) {
		bfd *obfd = bfd_openw(argv[2], output_target);
		assert(obfd);
		copy_object(ibfd, obfd);
		assert(bfd_close(obfd));
	}

	if (offsets_sbfd != NULL)
		assert(bfd_close(offsets_sbfd->abfd));
	assert(bfd_close(ibfd));
	return EXIT_SUCCESS;
}

void do_keep_primary(struct superbfd *isbfd, const char *pre)
{
	struct bfd *prebfd = bfd_openr(pre, NULL);
	assert(prebfd != NULL);
	char **matching;
	assert(bfd_check_format_matches(prebfd, bfd_object, &matching));

	struct superbfd *presbfd = fetch_superbfd(prebfd);
	init_objmanip_superbfd(presbfd);

	foreach_symbol_pair(presbfd, isbfd, match_global_symbols);
	debug1(isbfd, "Matched global\n");
	foreach_span_pair(presbfd, isbfd, match_string_spans);
	debug1(isbfd, "Matched string spans\n");
	foreach_symbol_pair(presbfd, isbfd, match_symbol_spans);
	debug1(isbfd, "Matched by name\n");
	foreach_span_pair(presbfd, isbfd, match_spans_by_label);
	debug1(isbfd, "Matched by label\n");

	do {
		changed = false;
		compare_matched_spans(isbfd);
		update_nonzero_offsets(isbfd);
		mark_new_spans(isbfd);
	} while (changed);
	vec_init(&delsects);

	foreach_symbol_pair(presbfd, isbfd, check_global_symbols);

	handle_deleted_spans(presbfd, isbfd);
	handle_section_symbol_renames(presbfd, isbfd);

	vec_init(&exports);
	compare_exported_symbols(presbfd, isbfd, false);
	compare_exported_symbols(isbfd, presbfd, true);

	assert(bfd_close(prebfd));

	asection *sect;
	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		ss->keep = false;
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->new || span->patch)
				keep_span(span);
			else
				span->keep = false;
		}
	}

	print_label_changes(isbfd);

	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->patch)
				debug0(isbfd, "Patching span %s\n",
				       span->label);
		}
	}

	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->new)
				debug0(isbfd, "New span %s\n", span->label);
		}
	}

	const char **sectname;
	for (sectname = delsects.data;
	     sectname < delsects.data + delsects.size; sectname++)
		debug0(isbfd, "Deleted section: %s\n", *sectname);

	const struct export_desc *ed;
	for (ed = exports.data; ed < exports.data + exports.size; ed++) {
		const char **symname;
		for (symname = ed->names.data;
		     symname < ed->names.data + ed->names.size; symname++)
			debug0(isbfd, "Export %s (%s): %s\n",
			       ed->deletion ? "deletion" : "addition",
			       ed->export_type, *symname);
	}

	filter_table_sections(isbfd);
	write_output = false;
	for (ed = exports.data; ed < exports.data + exports.size; ed++) {
		const char **symname;
		for (symname = ed->names.data;
		     symname < ed->names.data + ed->names.size; symname++)
			write_ksplice_export(isbfd, *symname,
					     ed->export_type, ed->deletion);
		if (ed->deletion)
			write_output = true;
		else
			rm_some_exports(isbfd, ed);
	}

	compute_span_shifts(isbfd);

	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->keep)
				write_output = true;
			if (span->patch || span->new)
				write_ksplice_section(span);
			if (span->patch)
				write_ksplice_patch(isbfd, span);
		}
	}

	rm_relocs(isbfd);
	remove_unkept_spans(isbfd);
}

void do_keep_helper(struct superbfd *isbfd)
{
	asection *sect;
	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		ss->keep = false;
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (ss->type == SS_TYPE_TEXT &&
			    !starts_with(ss->name, ".fixup"))
				keep_span(span);
			else
				span->keep = false;
		}
	}

	asymbol **symp;
	for (symp = isbfd->syms.data;
	     symp < isbfd->syms.data + isbfd->syms.size; symp++) {
		asymbol *sym = *symp;
		if (!bfd_is_const_section(sym->section) &&
		    (sym->flags & BSF_GLOBAL) != 0) {
			struct supersect *sym_ss =
			    fetch_supersect(isbfd, sym->section);
			struct span *span = find_span(sym_ss, sym->value);
			if (sym_ss->type != SS_TYPE_IGNORED)
				keep_span(span);
		}
	}

	do {
		changed = false;
		keep_referenced_sections(isbfd);
	} while (changed);

	filter_table_sections(isbfd);
	compute_span_shifts(isbfd);

	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		asymbol *sym = canonical_symbol(isbfd, sect->symbol);
		if (sym == NULL)
			continue;
		if ((sym->flags & BSF_WEAK) != 0)
			continue;
		if (bfd_get_section_size(sect) == 0)
			continue;
		if (!ss->keep)
			continue;
		if (ss->type != SS_TYPE_TEXT && !matchable_data_section(ss))
			continue;

		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->keep)
				write_ksplice_section(span);
		}
	}

	write_table_relocs(isbfd, "__bug_table", KSPLICE_HOWTO_BUG);
	write_table_relocs(isbfd, "__ex_table", KSPLICE_HOWTO_EXTABLE);
	rm_relocs(isbfd);
	remove_unkept_spans(isbfd);

	mangle_section_name(isbfd, "__markers");
	mangle_section_name(isbfd, "__ex_table");
}

void do_finalize(struct superbfd *isbfd)
{
	load_ksplice_symbol_offsets(isbfd);
	asection *sect;
	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		if (ss->type == SS_TYPE_EXIT) {
			struct span *span;
			for (span = ss->spans.data;
			     span < ss->spans.data + ss->spans.size; span++)
				span->keep = false;
			ss->keep = false;
		}
	}
	write_date_relocs(isbfd, "<{DATE...}>", KSPLICE_HOWTO_DATE);
	write_date_relocs(isbfd, "<{TIME}>", KSPLICE_HOWTO_TIME);
	rm_relocs(isbfd);
}

void do_rmsyms(struct superbfd *isbfd)
{
	read_str_set(&rmsyms);
	rm_relocs(isbfd);
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
			exp->ss = ss;
		}
	}
	return exports;
}

struct export_desc *new_export_desc(struct supersect *ss, bool deletion)
{
	struct export_desc *ed = vec_grow(&exports, 1);
	ed->deletion = deletion;
	vec_init(&ed->names);
	ed->export_type = strdup(ss->name) + strlen("__ksymtab");
	ed->sym_ss = ss;
	char *crc_sect_name;
	assert(asprintf(&crc_sect_name, "__kcrctab%s", ed->export_type) >= 0);
	asection *crc_sect =
	    bfd_get_section_by_name(ss->parent->abfd, crc_sect_name);
	if (crc_sect == NULL)
		ed->crc_ss = NULL;
	else
		ed->crc_ss = fetch_supersect(ss->parent, crc_sect);
	return ed;
}

void compare_exported_symbols(struct superbfd *oldsbfd,
			      struct superbfd *newsbfd, bool deletion)
{
	struct export_vec *new_exports, *old_exports;
	new_exports = get_export_syms(newsbfd);
	if (new_exports == NULL)
		return;
	old_exports = get_export_syms(oldsbfd);
	struct export *old, *new;
	struct supersect *last_ss = NULL;
	struct export_desc *ed = NULL;
	for (new = new_exports->data; new < new_exports->data +
	     new_exports->size; new++) {
		bool found = false;
		if (old_exports != NULL) {
			for (old = old_exports->data; old < old_exports->data +
			     old_exports->size; old++) {
				if (strcmp(new->name, old->name) == 0 &&
				    strcmp(new->ss->name, old->ss->name) == 0) {
					found = true;
					break;
				}
			}
		}
		if (!found) {
			if (last_ss != new->ss) {
				last_ss = new->ss;
				ed = new_export_desc(new->ss, deletion);
			}
			*vec_grow(&ed->names, 1) = new->name;
		}
	}
}

void match_spans(struct span *old_span, struct span *new_span)
{
	struct superbfd *sbfd = new_span->ss->parent;
	if (old_span->match == new_span && new_span->match == old_span)
		return;
	if (old_span->match != NULL) {
		err(sbfd, "Matching conflict: old %s: %s != %s\n",
		    old_span->label, old_span->match->label, new_span->label);
		DIE;
	}
	if (new_span->match != NULL) {
		err(sbfd, "Matching conflict: new %s: %s != %s\n",
		    new_span->label, new_span->match->label, old_span->label);
		DIE;
	}
	old_span->match = new_span;
	new_span->match = old_span;
	debug1(sbfd, "Matched old %s to new %s\n", old_span->label,
	       new_span->label);
}

static void match_global_symbols(struct span *old_span, asymbol *oldsym,
				 struct span *new_span, asymbol *newsym)
{
	if ((oldsym->flags & BSF_GLOBAL) == 0 ||
	    (newsym->flags & BSF_GLOBAL) == 0)
		return;
	match_spans(old_span, new_span);
}

static void check_global_symbols(struct span *old_span, asymbol *oldsym,
				 struct span *new_span, asymbol *newsym)
{
	if ((oldsym->flags & BSF_GLOBAL) == 0 ||
	    (newsym->flags & BSF_GLOBAL) == 0)
		return;
	if (old_span->ss->type == SS_TYPE_IGNORED)
		return;
	if (old_span->match != new_span || new_span->match != old_span) {
		err(new_span->ss->parent, "Global symbol span mismatch: %s "
		    "%s/%s\n", oldsym->name, old_span->ss->name,
		    new_span->ss->name);
		DIE;
	}
}

static void foreach_symbol_pair(struct superbfd *oldsbfd, struct superbfd *newsbfd,
				void (*fn)(struct span *old_span,
					   asymbol *oldsym,
					   struct span *new_span,
					   asymbol *newsym))
{
	asymbol **oldsymp, **newsymp;
	for (oldsymp = oldsbfd->syms.data;
	     oldsymp < oldsbfd->syms.data + oldsbfd->syms.size; oldsymp++) {
		asymbol *oldsym = *oldsymp;
		if (bfd_is_const_section(oldsym->section))
			continue;
		for (newsymp = newsbfd->syms.data;
		     newsymp < newsbfd->syms.data + newsbfd->syms.size;
		     newsymp++) {
			asymbol *newsym = *newsymp;
			if (bfd_is_const_section(newsym->section))
				continue;
			if (strcmp(oldsym->name, newsym->name) != 0)
				continue;

			struct supersect *old_ss =
			    fetch_supersect(oldsbfd, oldsym->section);
			struct supersect *new_ss =
			    fetch_supersect(newsbfd, newsym->section);
			if (old_ss->type != new_ss->type ||
			    old_ss->type == SS_TYPE_SPECIAL ||
			    old_ss->type == SS_TYPE_EXPORT)
				continue;

			struct span *old_span =
			    find_span(old_ss, oldsym->value);
			struct span *new_span =
			    find_span(new_ss, newsym->value);
			if (old_span == NULL) {
				err(oldsbfd, "Could not find span for %s\n",
				    oldsym->name);
				DIE;
			}
			if (new_span == NULL) {
				err(newsbfd, "Could not find span for %s\n",
				    newsym->name);
				DIE;
			}
			fn(old_span, oldsym, new_span, newsym);
		}
	}
}

static void match_symbol_spans(struct span *old_span, asymbol *oldsym,
			       struct span *new_span, asymbol *newsym)
{
	if ((oldsym->flags & BSF_DEBUGGING) != 0 ||
	    (newsym->flags & BSF_DEBUGGING) != 0)
		return;
	if (old_span->ss->type == SS_TYPE_SPECIAL ||
	    old_span->ss->type == SS_TYPE_EXPORT)
		return;
	if (static_local_symbol(old_span->ss->parent, oldsym) ||
	    static_local_symbol(new_span->ss->parent, newsym))
		return;
	if (old_span->match == NULL && new_span->match == NULL)
		match_spans(old_span, new_span);
}

static void match_spans_by_label(struct span *old_span, struct span *new_span)
{
	if (old_span->ss->type == SS_TYPE_STRING)
		return;
	if (strcmp(old_span->label, new_span->label) == 0)
		match_spans(old_span, new_span);
}

static void match_string_spans(struct span *old_span, struct span *new_span)
{
	if (old_span->ss->type != SS_TYPE_STRING ||
	    strcmp(old_span->ss->name, new_span->ss->name) != 0)
		return;
	if (strcmp((char *)old_span->ss->contents.data + old_span->start,
		   (char *)new_span->ss->contents.data + new_span->start) == 0)
		match_spans(old_span, new_span);
}

static void foreach_span_pair(struct superbfd *oldsbfd,
			      struct superbfd *newsbfd,
			      void (*fn)(struct span *old_span,
					 struct span *new_span))
{
	asection *oldsect, *newsect;
	struct supersect *oldss, *newss;
	struct span *old_span, *new_span;
	for (newsect = newsbfd->abfd->sections; newsect != NULL;
	     newsect = newsect->next) {
		newss = fetch_supersect(newsbfd, newsect);
		if (newss->type == SS_TYPE_SPECIAL ||
		    newss->type == SS_TYPE_EXPORT)
			continue;
		for (oldsect = oldsbfd->abfd->sections; oldsect != NULL;
		     oldsect = oldsect->next) {
			oldss = fetch_supersect(oldsbfd, oldsect);
			if (oldss->type != newss->type)
				continue;
			for (new_span = newss->spans.data;
			     new_span < newss->spans.data + newss->spans.size;
			     new_span++) {
				for (old_span = oldss->spans.data;
				     old_span < oldss->spans.data +
				     oldss->spans.size; old_span++)
					fn(old_span, new_span);
			}
		}
	}
}

static void mark_new_spans(struct superbfd *sbfd)
{
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (ss->type == SS_TYPE_SPECIAL || ss->type == SS_TYPE_EXPORT ||
		    ss->type == SS_TYPE_IGNORED)
			continue;
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->match == NULL)
				span->new = true;
		}
	}
}

static void handle_deleted_spans(struct superbfd *oldsbfd,
				 struct superbfd *newsbfd)
{
	asection *sect;
	for (sect = oldsbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(oldsbfd, sect);
		if (ss->type != SS_TYPE_TEXT)
			continue;
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->match != NULL)
				continue;
			*vec_grow(&delsects, 1) = span->label;
			if (span->symbol == NULL)
				DIE;
			write_ksplice_deleted_patch(newsbfd, span->symbol->name,
						    span->label,
						    span->ss->name);
		}
	}
}

static void handle_nonzero_offset_relocs(struct supersect *ss)
{
	struct span *address_span, *target_span;
	arelent **relocp;
	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		arelent *reloc = *relocp;
		address_span = find_span(ss, reloc->address);
		if (!address_span->new && !address_span->patch)
			continue;

		asymbol *sym = *reloc->sym_ptr_ptr;
		if (bfd_is_const_section(sym->section))
			continue;
		bfd_vma offset = get_reloc_offset(ss, reloc, true);
		target_span = reloc_target_span(ss, reloc);
		if (sym->value + offset == target_span->start)
			continue;

		if (target_span->ss->type != SS_TYPE_TEXT)
			continue;
		if (target_span->patch)
			continue;

		target_span->patch = true;
		changed = true;
		debug1(ss->parent, "Changing %s because a relocation from sect "
		       "%s has a nonzero offset %lx+%lx into it\n",
		       target_span->label, ss->name, (unsigned long)sym->value,
		       (unsigned long)offset);
	}
}

static void update_nonzero_offsets(struct superbfd *sbfd)
{
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (ss->type == SS_TYPE_SPECIAL || ss->type == SS_TYPE_EXPORT ||
		    ss->type == SS_TYPE_IGNORED)
			continue;
		handle_nonzero_offset_relocs(ss);
	}
}

static void compare_spans(struct span *old_span, struct span *new_span)
{
	struct superbfd *newsbfd = new_span->ss->parent;

	if (nonrelocs_equal(old_span, new_span) &&
	    all_relocs_equal(old_span, new_span))
		return;

	char *reason;
	if (new_span->size != old_span->size)
		reason = "differing sizes";
	else if (!nonrelocs_equal(old_span, new_span))
		reason = "differing contents";
	else
		reason = "differing relocations";

	if (new_span->ss->type == SS_TYPE_TEXT) {
		if (new_span->patch)
			return;
		new_span->patch = true;
		debug1(newsbfd, "Changing %s due to %s\n", new_span->label,
		       reason);
	} else {
		debug1(newsbfd, "Unmatching %s and %s due to %s\n",
		       old_span->label, new_span->label, reason);
		new_span->match = NULL;
		old_span->match = NULL;
	}
	changed = true;
	if (unchangeable_section(new_span->ss))
		err(newsbfd, "warning: ignoring change to nonpatchable "
		    "section %s\n", new_span->ss->name);
}

static void compare_matched_spans(struct superbfd *newsbfd)
{
	asection *sect;
	for (sect = newsbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(newsbfd, sect);
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->match == NULL)
				continue;
			compare_spans(span->match, span);
		}
	}
}

static void handle_section_symbol_renames(struct superbfd *oldsbfd,
					  struct superbfd *newsbfd)
{
	asection *sect;
	struct span *span;
	for (sect = newsbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(newsbfd, sect);
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->match == NULL)
				continue;
			if (strcmp(span->label, span->match->label) == 0)
				continue;
			if (strcmp(span->orig_label, span->label) != 0 &&
			    strcmp(span->label, span->match->label) != 0)
				DIE;
			if (span->symbol != NULL)
				label_map_set(newsbfd, span->label,
					      span->match->label);
			span->label = span->match->label;
		}
	}
}

static bool part_of_reloc(struct supersect *ss, unsigned long addr)
{
	arelent **relocp;
	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		arelent *reloc = *relocp;
		if (addr >= reloc->address &&
		    addr < reloc->address + reloc->howto->size)
			return true;
	}
	return false;
}

static bool nonrelocs_equal(struct span *old_span, struct span *new_span)
{
	int i;
	struct supersect *old_ss = old_span->ss, *new_ss = new_span->ss;
	if (old_span->size != new_span->size)
		return false;
	const unsigned char *old = old_ss->contents.data + old_span->start;
	const unsigned char *new = new_ss->contents.data + new_span->start;
	for (i = 0; i < old_span->size; i++) {
		if (old[i] != new[i] &&
		    !(part_of_reloc(old_ss, i + old_span->start) &&
		      part_of_reloc(new_ss, i + new_span->start)))
			return false;
	}
	return true;
}

bool relocs_equal(struct supersect *old_src_ss, struct supersect *new_src_ss,
		  arelent *old_reloc, arelent *new_reloc)
{
	struct superbfd *oldsbfd = old_src_ss->parent;
	struct superbfd *newsbfd = new_src_ss->parent;
	struct span *old_addr_span = find_span(old_src_ss, old_reloc->address);
	struct span *new_addr_span = find_span(new_src_ss, new_reloc->address);

	if (old_reloc->address - old_addr_span->start !=
	    new_reloc->address - new_addr_span->start) {
		debug1(newsbfd, "Section %s/%s has reloc address mismatch at "
		       "%lx\n", old_src_ss->name, new_src_ss->name,
		       (unsigned long)old_reloc->address);
		return false;
	}

	if (old_reloc->howto != new_reloc->howto) {
		debug1(newsbfd, "Section %s/%s has howto type mismatch at "
		       "%lx\n", old_src_ss->name, new_src_ss->name,
		       (unsigned long)old_reloc->address);
		return false;
	}

	if (non_dst_mask(old_src_ss, old_reloc) !=
	    non_dst_mask(new_src_ss, new_reloc)) {
		debug1(newsbfd, "Section %s/%s has contents mismatch at %lx\n",
		       old_src_ss->name, new_src_ss->name,
		       (unsigned long)old_reloc->address);
		return false;
	}

	asymbol *old_sym = *old_reloc->sym_ptr_ptr;
	asymbol *new_sym = *new_reloc->sym_ptr_ptr;
	asection *old_sect = old_sym->section;
	asection *new_sect = new_sym->section;

	bfd_vma old_offset = get_reloc_offset(old_src_ss, old_reloc, true);
	bfd_vma new_offset = get_reloc_offset(new_src_ss, new_reloc, true);

	if (bfd_is_und_section(old_sect) || bfd_is_und_section(new_sect)) {
		if (!bfd_is_und_section(new_sect) && old_offset != 0 &&
		    fetch_supersect(newsbfd, new_sect)->type == SS_TYPE_TEXT)
			return false;

		if (!bfd_is_und_section(new_sect) && new_offset != 0 &&
		    fetch_supersect(oldsbfd, old_sect)->type == SS_TYPE_TEXT)
			return false;

		return strcmp(old_sym->name, new_sym->name) == 0 &&
		    old_offset == new_offset;
	}

	if (bfd_is_const_section(old_sect) || bfd_is_const_section(new_sect))
		DIE;

	struct supersect *old_ss = fetch_supersect(oldsbfd, old_sect);
	struct supersect *new_ss = fetch_supersect(newsbfd, new_sect);
	struct span *old_span = reloc_target_span(old_src_ss, old_reloc);
	struct span *new_span = reloc_target_span(new_src_ss, new_reloc);

	if (old_span->match != new_span || new_span->match != old_span) {
		debug1(newsbfd, "Nonmatching relocs from %s to %s/%s\n",
		       new_src_ss->name, old_span->label, new_span->label);
		return false;
	}

	if (old_sym->value + old_offset - old_span->start !=
	    new_sym->value + new_offset - new_span->start) {
		debug1(newsbfd, "Offsets to %s/%s differ between %s "
		       "and %s: %lx+%lx/%lx+%lx\n", old_ss->name,
		       new_ss->name, old_src_ss->name, new_src_ss->name,
		       (unsigned long)old_sym->value, (unsigned long)old_offset,
		       (unsigned long)new_sym->value,
		       (unsigned long)new_offset);
		return false;
	}

	if ((old_sym->value + old_offset - old_span->start != 0 ||
	     new_sym->value + new_offset - new_span->start != 0) &&
	    new_span->patch) {
		debug1(newsbfd, "Relocation from %s to nonzero offsets "
		       "%lx+%lx/%lx+%lx in changed section %s\n",
		       new_src_ss->name, (unsigned long)old_sym->value,
		       (unsigned long)old_offset, (unsigned long)new_sym->value,
		       (unsigned long)new_offset, new_sym->section->name);
		return false;
	}
	return true;
}

bool all_relocs_equal(struct span *old_span, struct span *new_span)
{
	struct supersect *old_ss = old_span->ss, *new_ss = new_span->ss;
	arelent **old_relocp, **new_relocp;

	for (old_relocp = old_ss->relocs.data;
	     old_relocp < old_ss->relocs.data + old_ss->relocs.size;
	     old_relocp++) {
		if (find_span(old_ss, (*old_relocp)->address) == old_span)
			break;
	}

	for (new_relocp = new_ss->relocs.data;
	     new_relocp < new_ss->relocs.data + new_ss->relocs.size;
	     new_relocp++) {
		if (find_span(new_ss, (*new_relocp)->address) == new_span)
			break;
	}

	for (; old_relocp < old_ss->relocs.data + old_ss->relocs.size &&
	     find_span(old_ss, (*old_relocp)->address) == old_span &&
	     new_relocp < new_ss->relocs.data + new_ss->relocs.size &&
	     find_span(new_ss, (*new_relocp)->address) == new_span;
	     old_relocp++, new_relocp++) {
		if (!relocs_equal(old_ss, new_ss, *old_relocp, *new_relocp))
			return false;
	}

	if ((old_relocp < old_ss->relocs.data + old_ss->relocs.size &&
	     find_span(old_ss, (*old_relocp)->address) == old_span) ||
	    (new_relocp < new_ss->relocs.data + new_ss->relocs.size &&
	     find_span(new_ss, (*new_relocp)->address) == new_span)) {
		debug1(new_ss->parent, "Different reloc count between %s and "
		       "%s\n", old_span->label, new_span->label);
		return false;
	}

	return true;
}

bfd_vma non_dst_mask(struct supersect *ss, arelent *reloc)
{
	int bits = bfd_get_reloc_size(reloc->howto) * 8;
	void *address = ss->contents.data + reloc->address;
	bfd_vma x = bfd_get(bits, ss->parent->abfd, address);
	return x & ~reloc->howto->dst_mask;
}

void rm_some_exports(struct superbfd *sbfd, const struct export_desc *ed)
{
	struct supersect *ss = ed->sym_ss;
	struct supersect *crc_ss = ed->crc_ss;
	if (crc_ss != NULL)
		assert(ss->contents.size * sizeof(unsigned long) ==
		       crc_ss->contents.size * sizeof(struct kernel_symbol));

	struct kernel_symbol *ksym;
	unsigned long *crc = NULL;
	if (crc_ss != NULL)
		crc = crc_ss->contents.data;
	struct span *span, *crc_span;
	for (ksym = ss->contents.data;
	     (void *)ksym < ss->contents.data + ss->contents.size;
	     ksym++, crc++) {
		asymbol *sym;
		read_reloc(ss, &ksym->value, sizeof(ksym->value), &sym);
		span = new_span(ss, addr_offset(ss, ksym), sizeof(*ksym));
		if (str_in_set(sym->name, &ed->names))
			keep_span(span);

		if (crc_ss != NULL) {
			crc_span = new_span(crc_ss, addr_offset(crc_ss, crc),
					    sizeof(*crc));
			if (span->keep)
				keep_span(crc_span);
		}

		if (span->keep) {
			/* Replace name with a mangled name */
			write_string(ss, (const char **)&ksym->name,
				     "DISABLED_%s_%s", sym->name, kid);
		}
	}
}

void rm_relocs(struct superbfd *isbfd)
{
	asection *p;
	for (p = isbfd->abfd->sections; p != NULL; p = p->next) {
		struct supersect *ss = fetch_supersect(isbfd, p);
		bool remove_relocs = ss->keep;

		if (mode("keep") && ss->type == SS_TYPE_SPECIAL &&
		    strcmp(ss->name, "__bug_table") != 0)
			remove_relocs = false;

		if (ss->type == SS_TYPE_KSPLICE)
			remove_relocs = false;
		if (mode("finalize") &&
		    (starts_with(ss->name, ".ksplice_patches") ||
		     starts_with(ss->name, ".ksplice_relocs")))
			remove_relocs = true;

		if (remove_relocs)
			rm_some_relocs(ss);
	}
}

void rm_some_relocs(struct supersect *ss)
{
	struct arelentp_vec orig_relocs;
	vec_move(&orig_relocs, &ss->relocs);

	arelent **relocp;
	for (relocp = orig_relocs.data;
	     relocp < orig_relocs.data + orig_relocs.size; relocp++) {
		bool rm_reloc = false;
		asymbol *sym_ptr = *(*relocp)->sym_ptr_ptr;

		if (mode("rmsyms") && str_in_set(sym_ptr->name, &rmsyms) &&
		    bfd_is_und_section(sym_ptr->section))
			rm_reloc = true;

		if (mode("keep"))
			rm_reloc = true;

		if (mode("keep-primary") &&
		    (bfd_is_const_section(sym_ptr->section) ||
		     reloc_target_span(ss, *relocp)->new))
			rm_reloc = false;

		if (mode("keep-primary")) {
			const struct table_section *ts =
			    get_table_section(ss->name);
			if (ts != NULL && ts->has_addr &&
			    ((*relocp)->address % ts->entry_size ==
			     ts->addr_offset ||
			     (*relocp)->address % ts->entry_size ==
			     ts->other_offset))
				rm_reloc = false;
		}

		if (mode("finalize") && bfd_is_und_section(sym_ptr->section))
			rm_reloc = true;

		if (strcmp(sym_ptr->name, "mcount") == 0 &&
		    bfd_is_und_section(sym_ptr->section))
			rm_reloc = false;

		if (!find_span(ss, (*relocp)->address)->keep)
			rm_reloc = false;

		if (rm_reloc)
			write_ksplice_reloc(ss, *relocp);
		else
			*vec_grow(&ss->relocs, 1) = *relocp;
	}
}

struct supersect *make_section(struct superbfd *sbfd, const char *fmt, ...)
{
	va_list ap;
	char *name;
	va_start(ap, fmt);
	assert(vasprintf(&name, fmt, ap) >= 0);
	va_end(ap);

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
	reloc->address = addr_offset(ss, addr);
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
	struct supersect *str_ss = make_section(ss->parent, ".ksplice_str");
	char *str;
	va_start(ap, fmt);
	int len = vasprintf(&str, fmt, ap);
	assert(len >= 0);
	va_end(ap);

	unsigned long *str_offp = ulong_hash_lookup(&ksplice_string_offset, str,
						    FALSE);
	if (str_offp == NULL) {
		char *buf = sect_grow(str_ss, len + 1, char);
		memcpy(buf, str, len + 1);
		str_offp = ulong_hash_lookup(&ksplice_string_offset, str, TRUE);
		*str_offp = addr_offset(str_ss, buf);
	}

	write_reloc(ss, addr, &str_ss->symbol, *str_offp);
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

void compute_system_map_array(struct superbfd *sbfd, struct addr_vec *addrs,
			      asymbol *sym)
{
	if (bfd_is_abs_section(sym->section)) {
		*vec_grow(addrs, 1) = sym->value;
	} else if (bfd_is_und_section(sym->section)) {
		lookup_system_map(addrs, sym->name, 0);
	} else if (!bfd_is_const_section(sym->section)) {
		asymbol **gsymp;
		for (gsymp = sbfd->syms.data;
		     gsymp < sbfd->syms.data + sbfd->syms.size; gsymp++) {
			asymbol *gsym = *gsymp;
			if ((gsym->flags & BSF_DEBUGGING) == 0 &&
			    gsym->section == sym->section)
				lookup_system_map(addrs, gsym->name,
						  sym->value - gsym->value);
		}
	}
}

void write_ksplice_system_map(struct superbfd *sbfd, asymbol *sym,
			      const char *label)
{
	bool *done = bool_hash_lookup(&system_map_written, label, TRUE);
	if (*done)
		return;
	*done = true;

	struct addr_vec addrs;
	vec_init(&addrs);

	compute_system_map_array(sbfd, &addrs, sym);
	if (addrs.size != 0) {
		struct supersect *smap_ss =
		    make_section(sbfd, ".ksplice_system_map");
		struct ksplice_system_map *smap =
		    sect_grow(smap_ss, 1, struct ksplice_system_map);
		write_string(smap_ss, &smap->label, "%s", label);

		struct supersect *array_ss = make_section(sbfd,
							  ".ksplice_array");
		void *buf = sect_grow(array_ss, addrs.size,
				      typeof(*addrs.data));
		memcpy(buf, addrs.data, addrs.size * sizeof(*addrs.data));
		smap->nr_candidates = addrs.size;
		write_reloc(smap_ss, &smap->candidates, &array_ss->symbol,
			    addr_offset(array_ss, buf));
	}
	vec_free(&addrs);
}

void write_ksplice_symbol_backend(struct supersect *ss,
				  struct ksplice_symbol *const *addr,
				  asymbol *sym, const char *label,
				  const char *name)
{
	struct supersect *ksymbol_ss = make_section(ss->parent,
						    ".ksplice_symbols");
	struct ksplice_symbol *ksymbol;
	unsigned long *ksymbol_offp;

	ksymbol_offp = ulong_hash_lookup(&ksplice_symbol_offset, label, FALSE);
	if (ksymbol_offp != NULL) {
		write_reloc(ss, addr, &ksymbol_ss->symbol, *ksymbol_offp);
		return;
	}
	ksymbol = sect_grow(ksymbol_ss, 1, struct ksplice_symbol);
	ksymbol_offp = ulong_hash_lookup(&ksplice_symbol_offset, label, TRUE);
	*ksymbol_offp = addr_offset(ksymbol_ss, ksymbol);

	write_reloc(ss, addr, &ksymbol_ss->symbol, *ksymbol_offp);
	write_string(ksymbol_ss, &ksymbol->label, "%s", label);
	if (name != NULL) {
		write_string(ksymbol_ss, &ksymbol->name, "%s", name);
		write_ksplice_system_map(ksymbol_ss->parent, sym, label);
	}
}

void write_ksplice_symbol(struct supersect *ss,
			  struct ksplice_symbol *const *addr,
			  asymbol *sym, struct span *span,
			  const char *addstr_sect)
{
	const char *label, *name;
	char *output;
	if (span != NULL && span->start != 0)
		label = span->label;
	else
		label = label_lookup(ss->parent, sym);

	assert(asprintf(&output, "%s%s", label, addstr_sect) >= 0);

	asymbol *gsym = canonical_symbol(ss->parent, sym);
	if (strcmp(addstr_sect, "") != 0)
		name = NULL;
	else if (bfd_is_und_section(sym->section))
		name = sym->name;
	else if (bfd_is_const_section(sym->section))
		name = NULL;
	else if (span != NULL && span->symbol == NULL)
		name = NULL;
	else if (gsym == NULL || (gsym->flags & BSF_SECTION_SYM) != 0)
		name = NULL;
	else
		name = gsym->name;

	write_ksplice_symbol_backend(ss, addr, sym, output, name);
}

void write_ksplice_reloc(struct supersect *ss, arelent *orig_reloc)
{
	asymbol *sym_ptr = *orig_reloc->sym_ptr_ptr;
	bfd_vma reloc_addend = get_reloc_offset(ss, orig_reloc, false);
	bfd_vma target_addend = get_reloc_offset(ss, orig_reloc, true);
	unsigned long *repladdr = ss->contents.data + orig_reloc->address;

	if (mode("finalize") && starts_with(ss->name, ".ksplice_patches")) {
		*repladdr = 0;
		return;
	}
	if (mode("finalize") && starts_with(ss->name, ".ksplice_relocs")) {
		assert(starts_with(sym_ptr->name, KSPLICE_SYMBOL_STR));
		asymbol fake_sym;
		fake_sym.name = sym_ptr->name + strlen(KSPLICE_SYMBOL_STR);
		fake_sym.section = bfd_und_section_ptr;
		fake_sym.value = 0;
		fake_sym.flags = 0;

		write_ksplice_symbol_backend
		    (ss, (struct ksplice_symbol **)repladdr, &fake_sym,
		     fake_sym.name, fake_sym.name);
		return;
	}

	struct span *span = reloc_target_span(ss, orig_reloc);
	if (span == ss->spans.data && span->start != target_addend)
		span = NULL;
	blot_section(ss, orig_reloc->address, orig_reloc->howto);

	struct supersect *kreloc_ss;
	if (mode("rmsyms"))
		kreloc_ss = make_section(ss->parent, ".ksplice_init_relocs");
	else
		kreloc_ss = make_section(ss->parent, ".ksplice_relocs%s",
					 ss->name);
	struct ksplice_reloc *kreloc = sect_grow(kreloc_ss, 1,
						 struct ksplice_reloc);

	struct span *address_span = find_span(ss, orig_reloc->address);
	write_reloc(kreloc_ss, &kreloc->blank_addr,
		    &ss->symbol, orig_reloc->address + address_span->shift);
	if (bfd_is_und_section(sym_ptr->section) && mode("keep")) {
		char *name;
		assert(asprintf(&name, KSPLICE_SYMBOL_STR "%s", sym_ptr->name)
		       >= 0);
		asymbol **symp = make_undefined_symbolp(ss->parent, name);
		write_reloc(kreloc_ss, &kreloc->symbol, symp, 0);
	} else {
		write_ksplice_symbol(kreloc_ss, &kreloc->symbol, sym_ptr, span,
				     "");
	}
	if (span != NULL && span->start != 0) {
		reloc_addend += sym_ptr->value - span->start;
		target_addend += sym_ptr->value - span->start;
	}
	kreloc->insn_addend = reloc_addend - target_addend;
	kreloc->target_addend = target_addend;
	write_ksplice_reloc_howto(kreloc_ss, &kreloc->howto, orig_reloc->howto);
}

static void write_ksplice_reloc_howto(struct supersect *ss, const
				      struct ksplice_reloc_howto *const *addr,
				      reloc_howto_type *howto)
{
	struct supersect *khowto_ss = make_section(ss->parent,
						   ".ksplice_reloc_howtos");
	struct ksplice_reloc_howto *khowto;
	unsigned long *khowto_offp;

	khowto_offp = ulong_hash_lookup(&ksplice_howto_offset, howto->name,
					FALSE);
	if (khowto_offp != NULL) {
		write_reloc(ss, addr, &khowto_ss->symbol, *khowto_offp);
		return;
	}
	khowto = sect_grow(khowto_ss, 1, struct ksplice_reloc_howto);
	khowto_offp = ulong_hash_lookup(&ksplice_howto_offset, howto->name,
					TRUE);
	*khowto_offp = addr_offset(khowto_ss, khowto);

	khowto->type = KSPLICE_HOWTO_RELOC;
	khowto->pcrel = howto->pc_relative;
	khowto->size = bfd_get_reloc_size(howto);
	khowto->dst_mask = howto->dst_mask;
	khowto->rightshift = howto->rightshift;
	khowto->signed_addend =
	    (howto->complain_on_overflow == complain_overflow_signed) ||
	    (howto->complain_on_overflow == complain_overflow_bitfield);
	write_reloc(ss, addr, &khowto_ss->symbol, *khowto_offp);
}

#define CANARY(x, canary) ((x & ~howto->dst_mask) | (canary & howto->dst_mask))

void blot_section(struct supersect *ss, int offset, reloc_howto_type *howto)
{
	int bits = bfd_get_reloc_size(howto) * 8;
	void *address = ss->contents.data + offset;
	bfd_vma x = bfd_get(bits, ss->parent->abfd, address);
	x = (x & ~howto->dst_mask) |
	    ((bfd_vma)KSPLICE_CANARY & howto->dst_mask);
	bfd_put(bits, ss->parent->abfd, x, address);
}

static void write_date_relocs(struct superbfd *sbfd, const char *str,
			      enum ksplice_reloc_howto_type type)
{
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (ss->type != SS_TYPE_STRING && ss->type != SS_TYPE_RODATA)
			continue;
		void *ptr;
		for (ptr = ss->contents.data;
		     ptr + strlen(str) < ss->contents.data + ss->contents.size;
		     ptr++) {
			if (strcmp((const char *)ptr, str) == 0)
				write_ksplice_date_reloc(ss,
							 addr_offset(ss, ptr),
							 str, type);
		}
	}
}

static void write_ksplice_date_reloc(struct supersect *ss, unsigned long offset,
				     const char *str,
				     enum ksplice_reloc_howto_type type)
{
	struct supersect *kreloc_ss;
	kreloc_ss = make_section(ss->parent, ".ksplice_relocs%s", ss->name);
	struct ksplice_reloc *kreloc = sect_grow(kreloc_ss, 1,
						 struct ksplice_reloc);

	const char *filename = ss->parent->abfd->filename;
	char *c = strstr(filename, ".KSPLICE");
	int flen = (c == NULL ? strlen(filename) : c - filename);

	char *label;
	assert(asprintf(&label, "%s<%.*s>", str, flen, filename) >= 0);
	write_ksplice_symbol_backend(kreloc_ss, &kreloc->symbol, NULL,
				     label, NULL);

	struct span *span = find_span(ss, offset);
	write_reloc(kreloc_ss, &kreloc->blank_addr, &ss->symbol,
		    offset + span->shift);
	write_ksplice_nonreloc_howto(kreloc_ss, &kreloc->howto, type,
				     strlen(str));
}

static void write_table_relocs(struct superbfd *sbfd, const char *sectname,
			       enum ksplice_reloc_howto_type type)
{
	asection *sect = bfd_get_section_by_name(sbfd->abfd, sectname);
	if (sect == NULL)
		return;
	struct supersect *ss = fetch_supersect(sbfd, sect);

	const struct table_section *s = get_table_section(sectname);
	if (s == NULL)
		DIE;

	void *entry;
	for (entry = ss->contents.data;
	     entry < ss->contents.data + ss->contents.size;
	     entry += s->entry_size) {
		struct span *span = find_span(ss, addr_offset(ss, entry));
		assert(span != NULL);
		if (!span->keep)
			continue;

		arelent *reloc = find_reloc(ss, entry + s->addr_offset);
		assert(reloc != NULL);
		if (strcmp(ss->name, "__bug_table") == 0)
			write_ksplice_ignore_reloc
			    (ss, addr_offset(ss, entry + s->other_offset),
			     sizeof(unsigned short));
		asymbol *sym = *reloc->sym_ptr_ptr;
		assert(!bfd_is_const_section(sym->section));
		struct supersect *sym_ss = fetch_supersect(sbfd, sym->section);
		unsigned long addr = get_reloc_offset(ss, reloc, true) +
		    sym->value;
		write_ksplice_table_reloc(sym_ss, addr, span->label, type);
	}
}

static void write_ksplice_table_reloc(struct supersect *ss,
				      unsigned long address,
				      const char *label,
				      enum ksplice_reloc_howto_type type)
{
	struct supersect *kreloc_ss;
	kreloc_ss = make_section(ss->parent, ".ksplice_relocs%s", ss->name);
	struct ksplice_reloc *kreloc = sect_grow(kreloc_ss, 1,
						 struct ksplice_reloc);
	struct span *span = find_span(ss, address);
	assert(span != NULL);

	write_ksplice_symbol_backend(kreloc_ss, &kreloc->symbol, NULL,
				     label, NULL);
	write_reloc(kreloc_ss, &kreloc->blank_addr, &ss->symbol,
		    address + span->shift);
	write_ksplice_nonreloc_howto(kreloc_ss, &kreloc->howto, type, 0);
}

static void write_ksplice_ignore_reloc(struct supersect *ss,
				       unsigned long address,
				       bfd_size_type size)
{
	struct supersect *kreloc_ss;
	kreloc_ss = make_section(ss->parent, ".ksplice_relocs%s", ss->name);
	struct ksplice_reloc *kreloc = sect_grow(kreloc_ss, 1,
						 struct ksplice_reloc);
	struct span *span = find_span(ss, address);
	assert(span != NULL);
	char *label;
	assert(asprintf(&label, "%s+%lx(IGNORED)", span->label, address) >= 0);

	write_ksplice_symbol_backend(kreloc_ss, &kreloc->symbol, NULL,
				     label, NULL);
	write_reloc(kreloc_ss, &kreloc->blank_addr, &ss->symbol,
		    address + span->shift);
	write_ksplice_nonreloc_howto(kreloc_ss, &kreloc->howto,
				     KSPLICE_HOWTO_IGNORE, size);
}

static void write_ksplice_nonreloc_howto(struct supersect *ss,
					 const struct ksplice_reloc_howto
					 *const *addr,
					 enum ksplice_reloc_howto_type type,
					 int size)
{
	struct supersect *khowto_ss =
	    make_section(ss->parent, ".ksplice_reloc_howtos");
	struct ksplice_reloc_howto *khowto =
	    sect_grow(khowto_ss, 1, struct ksplice_reloc_howto);

	khowto->type = type;
	khowto->size = size;
	khowto->pcrel = 0;
	khowto->dst_mask = 0;
	khowto->rightshift = 0;
	khowto->signed_addend = 0;
	write_reloc(ss, addr, &khowto_ss->symbol,
		    addr_offset(khowto_ss, khowto));
}

static void write_ksplice_section(struct span *span)
{
	struct supersect *ss = span->ss;
	const char *sectname = span->ss->name;
	const struct table_section *ts = get_table_section(ss->name);

	if (ts != NULL && ts->has_addr) {
		arelent *reloc = find_reloc(ss, ss->contents.data + span->start
					    + ts->addr_offset);
		assert(reloc != NULL);
		asymbol *rsym = *reloc->sym_ptr_ptr;
		assert(!bfd_is_const_section(rsym->section));
		sectname = rsym->section->name;
	}

	struct supersect *ksect_ss =
	    make_section(ss->parent, ".ksplice_sections%s", sectname);
	struct ksplice_section *ksect = sect_grow(ksect_ss, 1,
						  struct ksplice_section);
	asymbol *sym = span->symbol == NULL ? ss->symbol : span->symbol;

	write_ksplice_symbol(ksect_ss, &ksect->symbol, sym, span,
			     mode("keep-primary") ? "(post)" : "");
	ksect->size = span->size;
	ksect->flags = 0;

	if (ss->type == SS_TYPE_RODATA || ss->type == SS_TYPE_STRING)
		ksect->flags |= KSPLICE_SECTION_RODATA;
	if (ss->type == SS_TYPE_DATA)
		ksect->flags |= KSPLICE_SECTION_DATA;
	if (ss->type == SS_TYPE_TEXT)
		ksect->flags |= KSPLICE_SECTION_TEXT;
	assert(ksect->flags != 0);

	if (ss->type == SS_TYPE_STRING)
		ksect->flags |= KSPLICE_SECTION_STRING;

	write_reloc(ksect_ss, &ksect->address, &ss->symbol,
		    span->start + span->shift);
}

void write_ksplice_patch(struct superbfd *sbfd, struct span *span)
{
	struct supersect *kpatch_ss =
	    make_section(sbfd, ".ksplice_patches%s", span->ss->name);
	struct ksplice_patch *kpatch = sect_grow(kpatch_ss, 1,
						 struct ksplice_patch);

	write_ksplice_symbol_backend(kpatch_ss, &kpatch->symbol, NULL,
				     span->label, NULL);
	write_reloc(kpatch_ss, &kpatch->repladdr, &span->ss->symbol,
		    span->start + span->shift);
}

asymbol **make_undefined_symbolp(struct superbfd *sbfd, const char *name)
{
	asymbol **symp;
	for (symp = sbfd->syms.data; symp < sbfd->syms.data + sbfd->syms.size;
	     symp++) {
		asymbol *sym = *symp;
		if (strcmp(name, sym->name) == 0 &&
		    bfd_is_und_section(sym->section))
			return symp;
	}
	asymbol ***sympp;
	for (sympp = sbfd->new_syms.data;
	     sympp < sbfd->new_syms.data + sbfd->new_syms.size; sympp++) {
		asymbol **symp = *sympp;
		asymbol *sym = *symp;
		if (strcmp(name, sym->name) == 0 &&
		    bfd_is_und_section(sym->section))
			return symp;
	}

	symp = malloc(sizeof(*symp));
	*symp = bfd_make_empty_symbol(sbfd->abfd);
	asymbol *sym = *symp;
	sym->name = name;
	sym->section = bfd_und_section_ptr;
	sym->flags = 0;
	sym->value = 0;
	*vec_grow(&sbfd->new_syms, 1) = symp;
	return symp;
}

void write_ksplice_deleted_patch(struct superbfd *sbfd, const char *name,
				 const char *label, const char *sectname)
{
	struct supersect *kpatch_ss =
	    make_section(sbfd, ".ksplice_patches%s", sectname);
	struct ksplice_patch *kpatch = sect_grow(kpatch_ss, 1,
						 struct ksplice_patch);

	write_ksplice_symbol_backend(kpatch_ss, &kpatch->symbol, NULL,
				     label, NULL);

	asymbol **symp = make_undefined_symbolp(sbfd, strdup(name));
	write_reloc(kpatch_ss, &kpatch->repladdr, symp, 0);
}

void write_ksplice_export(struct superbfd *sbfd, const char *symname,
			  const char *export_type, bool del)
{
	struct supersect *export_ss = make_section(sbfd, ".ksplice_exports");
	struct ksplice_export *exp = sect_grow(export_ss, 1,
					       struct ksplice_export);

	if (del) {
		write_string(export_ss, &exp->name, "%s", symname);
		write_string(export_ss, &exp->new_name, "DISABLED_%s_%s",
			     symname, kid);
	} else {
		write_string(export_ss, &exp->new_name, "%s", symname);
		write_string(export_ss, &exp->name, "DISABLED_%s_%s", symname,
			     kid);
	}
}

void filter_table_sections(struct superbfd *isbfd)
{
	struct supersect *tables_ss =
	    fetch_supersect(offsets_sbfd,
			    bfd_get_section_by_name(offsets_sbfd->abfd,
						    ".ksplice_table_sections"));
	const struct table_section *ts;
	for (ts = tables_ss->contents.data;
	     (void *)ts < tables_ss->contents.data + tables_ss->contents.size;
	     ts++) {
		struct table_section s = *ts;
		s.sect = read_string(tables_ss, &ts->sect);
		s.other_sect = read_string(tables_ss, &ts->other_sect);
		if (s.has_addr)
			filter_table_section(isbfd, &s);
	}
}

void filter_table_section(struct superbfd *sbfd, const struct table_section *s)
{
	asection *isection = bfd_get_section_by_name(sbfd->abfd, s->sect);
	if (isection == NULL)
		return;
	struct supersect *ss = fetch_supersect(sbfd, isection);

	void *entry;
	for (entry = ss->contents.data;
	     entry < ss->contents.data + ss->contents.size;
	     entry += s->entry_size) {
		asymbol *sym;
		struct span *span = find_span(ss, addr_offset(ss, entry));
		assert(span != NULL);

		read_reloc(ss, entry + s->addr_offset, sizeof(void *), &sym);
		struct supersect *sym_ss = fetch_supersect(sbfd, sym->section);
		if (sym_ss->keep)
			keep_span(span);

		if (s->other_sect != NULL) {
			arelent *reloc =
			    find_reloc(ss, entry + s->other_offset);
			assert(reloc != NULL);
			struct span *sym_span = reloc_target_span(ss, reloc);
			if (span->keep)
				keep_span(sym_span);
		}
	}
}

void keep_referenced_sections(struct superbfd *sbfd)
{
	asection *sect;
	struct supersect *ss, *sym_ss;
	struct span *address_span, *target_span;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		ss = fetch_supersect(sbfd, sect);
		arelent **relocp;
		if (ss->type == SS_TYPE_SPECIAL || ss->type == SS_TYPE_EXPORT)
			continue;
		for (relocp = ss->relocs.data;
		     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
			asymbol *sym = *(*relocp)->sym_ptr_ptr;
			address_span = find_span(ss, (*relocp)->address);
			if (!address_span->keep)
				continue;
			target_span = reloc_target_span(ss, *relocp);
			if (target_span == NULL || target_span->keep)
				continue;
			sym_ss = fetch_supersect(sbfd, sym->section);
			if (sym_ss->type == SS_TYPE_IGNORED)
				continue;
			keep_span(target_span);
			changed = true;
		}
	}
}

void copy_symbols(struct asymbolp_vec *osyms, struct asymbolpp_vec *isyms)
{
	asymbol ***sympp;
	for (sympp = isyms->data; sympp < isyms->data + isyms->size; sympp++)
		*vec_grow(osyms, 1) = **sympp;
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
	copy_symbols(&osyms, &fetch_superbfd(ibfd)->new_syms);

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
	struct superbfd *isbfd = fetch_superbfd(ibfd);
	struct supersect *ss = fetch_supersect(isbfd, isection);
	bfd *obfd = obfdarg;
	bfd_vma vma;

	if (!ss->keep)
		return;

	asection *osection = bfd_make_section_anyway(obfd, ss->name);
	assert(osection != NULL);

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

static int compare_reloc_addresses(const void *aptr, const void *bptr)
{
	const arelent *const *a = aptr, *const *b = bptr;
	return (*a)->address - (*b)->address;
}

static void delete_obsolete_relocs(struct supersect *ss)
{
	if (ss->new_relocs.size == 0)
		return;

	qsort(ss->relocs.data, ss->relocs.size, sizeof(*ss->relocs.data),
	      compare_reloc_addresses);
	qsort(ss->new_relocs.data, ss->new_relocs.size,
	      sizeof(*ss->new_relocs.data), compare_reloc_addresses);

	struct arelentp_vec orig_relocs;
	vec_move(&orig_relocs, &ss->relocs);

	arelent **relocp, **new_relocp = ss->new_relocs.data;
	for (relocp = orig_relocs.data;
	     relocp < orig_relocs.data + orig_relocs.size; relocp++) {
		while (new_relocp < ss->new_relocs.data + ss->new_relocs.size &&
		       (*new_relocp)->address < (*relocp)->address)
			new_relocp++;
		arelent *reloc = *relocp, *new_reloc = *new_relocp;
		if (new_relocp == ss->new_relocs.data + ss->new_relocs.size ||
		    reloc->address != new_reloc->address)
			*vec_grow(&ss->relocs, 1) = reloc;
	}
}

void write_section(bfd *obfd, asection *osection, void *arg)
{
	struct supersect *ss = osection->userdata;

	if ((ss->flags & SEC_GROUP) != 0 || ss->contents.size == 0)
		return;

	delete_obsolete_relocs(ss);

	arelent **relocp;
	char *error_message;
	for (relocp = ss->new_relocs.data;
	     relocp < ss->new_relocs.data + ss->new_relocs.size; relocp++) {
		bfd_vma val;
		if (bfd_get_arch(obfd) == bfd_arch_arm)
			val = osection->use_rela_p ? 0 : (*relocp)->addend;
		else
			val = 0;
		bfd_put(bfd_get_reloc_size((*relocp)->howto) * 8, obfd, val,
			ss->contents.data + (*relocp)->address);
		if (bfd_install_relocation(obfd, *relocp, ss->contents.data,
					   0, osection, &error_message) !=
		    bfd_reloc_ok) {
			err(ss->parent, "ksplice: error installing reloc: %s",
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
	for (relocp = ss->new_relocs.data;
	     relocp < ss->new_relocs.data + ss->new_relocs.size; relocp++) {
		asymbol *sym = *(*relocp)->sym_ptr_ptr;
		if (!(bfd_is_const_section(sym->section) &&
		      sym == sym->section->symbol))
			sym->flags |= BSF_KEEP;
	}
}

static bool deleted_table_section_symbol(bfd *abfd, asymbol *sym)
{
	struct superbfd *sbfd = fetch_superbfd(abfd);
	if (bfd_is_const_section(sym->section))
		return false;
	struct supersect *ss = fetch_supersect(sbfd, sym->section);

	asymbol **symp;
	for (symp = ss->syms.data; symp < ss->syms.data + ss->syms.size; symp++) {
		if (sym == *symp)
			break;
	}
	return symp >= ss->syms.data + ss->syms.size &&
	    (sym->flags & BSF_SECTION_SYM) == 0;
}

void filter_symbols(bfd *ibfd, bfd *obfd, struct asymbolp_vec *osyms,
		    struct asymbolp_vec *isyms)
{
	asymbol **symp;
	struct superbfd *sbfd = fetch_superbfd(ibfd);
	for (symp = isyms->data; symp < isyms->data + isyms->size; symp++) {
		asymbol *sym = *symp;
		struct supersect *sym_ss = NULL;
		struct span *sym_span = NULL;
		if (!bfd_is_const_section(sym->section)) {
			sym_ss = fetch_supersect(sbfd, sym->section);
			sym_span = find_span(sym_ss, sym->value);
		}

		if (mode("keep") && (sym->flags & BSF_GLOBAL) != 0 &&
		    !(mode("keep-primary") && sym_span != NULL &&
		      sym_span->new))
			sym->flags = (sym->flags & ~BSF_GLOBAL) | BSF_LOCAL;

		if (mode("finalize") && (sym->flags & BSF_GLOBAL) != 0)
			sym->flags = (sym->flags & ~BSF_GLOBAL) | BSF_LOCAL;

		bool keep = bfd_is_const_section(sym->section) ||
		    (sym_ss->keep && (sym->flags & BSF_SECTION_SYM) != 0) ||
		    (sym_span != NULL && sym_span->keep);
		if (bfd_is_und_section(sym->section) &&
		    (sym->flags & BSF_KEEP) == 0)
			keep = false;
		if (deleted_table_section_symbol(ibfd, sym))
			keep = false;

		if (keep) {
			if (sym_ss != NULL && !sym_ss->keep) {
				err(sbfd, "Kept symbol %s in unkept section "
				    "%s\n", sym->name, sym->section->name);
				DIE;
			}
			*vec_grow(osyms, 1) = sym;
		}
	}
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

bool str_in_set(const char *str, const struct str_vec *strs)
{
	const char **strp;
	for (strp = strs->data; strp < strs->data + strs->size; strp++) {
		if (strcmp(str, *strp) == 0)
			return true;
	}
	return false;
}

bool is_table_section(const char *name, bool consider_other)
{
	struct supersect *tables_ss =
	    fetch_supersect(offsets_sbfd,
			    bfd_get_section_by_name(offsets_sbfd->abfd,
						    ".ksplice_table_sections"));
	const struct table_section *ts;
	for (ts = tables_ss->contents.data;
	     (void *)ts < tables_ss->contents.data + tables_ss->contents.size;
	     ts++) {
		if (strcmp(name, read_string(tables_ss, &ts->sect)) == 0)
			return true;
		const char *osect_name = read_string(tables_ss,
						     &ts->other_sect);
		if (consider_other && osect_name != NULL &&
		    strcmp(name, osect_name) == 0)
			return true;
	}
	return false;
}

const struct table_section *get_table_section(const char *name)
{
	struct supersect *tables_ss =
	    fetch_supersect(offsets_sbfd,
			    bfd_get_section_by_name(offsets_sbfd->abfd,
						    ".ksplice_table_sections"));
	const struct table_section *ts;
	for (ts = tables_ss->contents.data;
	     (void *)ts < tables_ss->contents.data + tables_ss->contents.size;
	     ts++) {
		if (strcmp(name, read_string(tables_ss, &ts->sect)) == 0)
			return ts;
	}
	return NULL;
}

enum supersect_type supersect_type(struct supersect *ss)
{
	if (mode("finalize") &&
	    strcmp(finalize_target, "vmlinux") == 0 &&
	    (starts_with(ss->name, ".ksplice_relocs.exit") ||
	     starts_with(ss->name, ".ksplice_sections.exit") ||
	     starts_with(ss->name, ".ksplice_patches.exit")))
		return SS_TYPE_EXIT;
	if (starts_with(ss->name, ".ksplice"))
		return SS_TYPE_KSPLICE;

	if (starts_with(ss->name, ".init"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".security_initcall.init"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".con_initcall.init"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".x86cpuvendor.init"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".early_param.init"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".taglist.init"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".arch.info.init"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".proc.info.init"))
		return SS_TYPE_IGNORED;
	/* .pci_fixup_* sections really should be treated as global rodata
	   referenced only from quirks.c */
	if (starts_with(ss->name, ".pci_fixup_"))
		return SS_TYPE_IGNORED;
	/* .builtin_fw sections are similar to .pci_fixup */
	if (starts_with(ss->name, ".builtin_fw"))
		return SS_TYPE_IGNORED;
	/* same for .tracedata */
	if (starts_with(ss->name, ".tracedata"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".debug"))
		return SS_TYPE_IGNORED;
	/* .eh_frame should probably be discarded, not ignored */
	if (starts_with(ss->name, ".eh_frame"))
		return SS_TYPE_IGNORED;
	if (config->ignore_devinit && starts_with(ss->name, ".devinit"))
		return SS_TYPE_IGNORED;
	if (config->ignore_meminit && starts_with(ss->name, ".meminit"))
		return SS_TYPE_IGNORED;
	if (config->ignore_cpuinit && starts_with(ss->name, ".cpuinit"))
		return SS_TYPE_IGNORED;
	if (config->ignore_devinit && starts_with(ss->name, ".devexit"))
		return SS_TYPE_IGNORED;
	if (config->ignore_meminit && starts_with(ss->name, ".memexit"))
		return SS_TYPE_IGNORED;
	if (config->ignore_cpuinit && starts_with(ss->name, ".cpuexit"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".vgetcpu_mode") ||
	    starts_with(ss->name, ".jiffies") ||
	    starts_with(ss->name, ".wall_jiffies") ||
	    starts_with(ss->name, ".vxtime") ||
	    starts_with(ss->name, ".sys_tz") ||
	    starts_with(ss->name, ".sysctl_vsyscall") ||
	    starts_with(ss->name, ".xtime") ||
	    starts_with(ss->name, ".xtime_lock") ||
	    starts_with(ss->name, ".vsyscall"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".vdso"))
		return SS_TYPE_IGNORED;

	if (starts_with(ss->name, ".exit.text"))
		return SS_TYPE_TEXT;
	if (starts_with(ss->name, ".exit.data"))
		return SS_TYPE_DATA;

	if (starts_with(ss->name, ".text") ||
	    starts_with(ss->name, ".kernel.text") ||
	    starts_with(ss->name, ".devinit.text") ||
	    starts_with(ss->name, ".meminit.text") ||
	    starts_with(ss->name, ".cpuinit.text") ||
	    starts_with(ss->name, ".devexit.text") ||
	    starts_with(ss->name, ".memexit.text") ||
	    starts_with(ss->name, ".cpuexit.text") ||
	    starts_with(ss->name, ".ref.text") ||
	    starts_with(ss->name, ".spinlock.text") ||
	    starts_with(ss->name, ".kprobes.text") ||
	    starts_with(ss->name, ".sched.text") ||
	    (mode("keep-helper") && starts_with(ss->name, ".fixup")))
		return SS_TYPE_TEXT;

	int n = -1;
	if (sscanf(ss->name, ".rodata.str%*u.%*u%n", &n) >= 0 &&
	    n == strlen(ss->name))
		return SS_TYPE_STRING;

	if (starts_with(ss->name, ".rodata") ||
	    starts_with(ss->name, ".kernel.rodata") ||
	    starts_with(ss->name, ".devinit.rodata") ||
	    starts_with(ss->name, ".meminit.rodata") ||
	    starts_with(ss->name, ".cpuinit.rodata") ||
	    starts_with(ss->name, ".devexit.rodata") ||
	    starts_with(ss->name, ".memexit.rodata") ||
	    starts_with(ss->name, ".cpuexit.rodata") ||
	    starts_with(ss->name, ".ref.rodata") ||
	    starts_with(ss->name, "__markers_strings") ||
	    (mode("keep-helper") && (starts_with(ss->name, "__bug_table") ||
				     starts_with(ss->name, "__ex_table"))))
		return SS_TYPE_RODATA;

	if (starts_with(ss->name, ".bss"))
		return SS_TYPE_DATA;

	/* Ignore .data.percpu sections */
	if (starts_with(ss->name, ".data.percpu") ||
	    starts_with(ss->name, ".kernel.data.percpu"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".data") ||
	    starts_with(ss->name, ".kernel.data") ||
	    starts_with(ss->name, ".devinit.data") ||
	    starts_with(ss->name, ".cpuinit.data") ||
	    starts_with(ss->name, ".meminit.data") ||
	    starts_with(ss->name, ".devexit.data") ||
	    starts_with(ss->name, ".memexit.data") ||
	    starts_with(ss->name, ".cpuexit.data") ||
	    starts_with(ss->name, ".ref.data") ||
	    starts_with(ss->name, "__markers"))
		return SS_TYPE_DATA;

	/* We replace all the ksymtab strings, so delete them */
	if (strcmp(ss->name, "__ksymtab_strings") == 0)
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, "__ksymtab"))
		return SS_TYPE_EXPORT;
	if (starts_with(ss->name, "__kcrctab"))
		return SS_TYPE_EXPORT;

	if (is_table_section(ss->name, true))
		return SS_TYPE_SPECIAL;

	if (starts_with(ss->name, ".ARM."))
		return SS_TYPE_SPECIAL;

	if (starts_with(ss->name, ".note"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".comment"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, "__param"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".exitcall.exit"))
		return SS_TYPE_IGNORED;
	if (starts_with(ss->name, ".modinfo"))
		return SS_TYPE_IGNORED;

	return SS_TYPE_UNKNOWN;
}

void initialize_supersect_types(struct superbfd *sbfd)
{
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		ss->type = supersect_type(ss);
		if (ss->type == SS_TYPE_UNKNOWN) {
			err(sbfd, "Unknown section type: %s\n", ss->name);
			DIE;
		}
	}
}

static void init_label_map(struct superbfd *sbfd)
{
	struct label_map *map;

	vec_init(&sbfd->maps);
	init_csyms(sbfd);
	init_callers(sbfd);

	struct symbol_hash csyms;
	symbol_hash_init(&csyms);

	asymbol **symp;
	for (symp = sbfd->syms.data;
	     symp < sbfd->syms.data + sbfd->syms.size; symp++) {
		asymbol *csym = canonical_symbol(sbfd, *symp);
		if (csym == NULL)
			continue;
		char *key;
		assert(asprintf(&key, "%p", csym) >= 0);
		asymbol **csymp = symbol_hash_lookup(&csyms, key, TRUE);
		free(key);
		if (*csymp != NULL)
			continue;
		*csymp = csym;

		map = vec_grow(&sbfd->maps, 1);
		map->csym = csym;
		map->count = 0;
		map->label = symbol_label(sbfd, csym);
	}

	struct label_mapp_hash label_maps;
	label_mapp_hash_init(&label_maps);
	for (map = sbfd->maps.data;
	     map < sbfd->maps.data + sbfd->maps.size; map++) {
		struct label_map **mapp =
		    label_mapp_hash_lookup(&label_maps, map->label, TRUE);
		if (*mapp == NULL) {
			*mapp = map;
			continue;
		}

		struct label_map *first_map = *mapp;
		char *buf;
		if (first_map->count == 0) {
			assert(asprintf(&buf, "%s~%d", map->label, 0) >= 0);
			first_map->label = buf;
		}
		first_map->count++;
		assert(asprintf(&buf, "%s~%d", map->label, first_map->count)
		       >= 0);
		map->label = buf;
	}

	label_mapp_hash_init(&sbfd->maps_hash);
	for (map = sbfd->maps.data;
	     map < sbfd->maps.data + sbfd->maps.size; map++) {
		char *key;
		assert(asprintf(&key, "%p", map->csym) >= 0);
		struct label_map **mapp =
		    label_mapp_hash_lookup(&sbfd->maps_hash, key, TRUE);
		free(key);
		*mapp = map;
		map->orig_label = map->label;
	}
}

static const char *label_lookup(struct superbfd *sbfd, asymbol *sym)
{
	asymbol *csym = canonical_symbol(sbfd, sym);
	char *key;
	assert(asprintf(&key, "%p", csym) >= 0);
	struct label_map **mapp =
	    label_mapp_hash_lookup(&sbfd->maps_hash, key, FALSE);
	free(key);
	if (mapp == NULL)
		DIE;
	return (*mapp)->label;
}

static void print_label_changes(struct superbfd *sbfd)
{
	asection *sect;
	struct span *span;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (strcmp(span->label, span->orig_label) != 0)
				debug1(sbfd, "Label change: %s -> %s\n",
				       span->label, span->orig_label);
		}
	}
}

static void label_map_set(struct superbfd *sbfd, const char *oldlabel,
			  const char *label)
{
	struct label_map *map;
	for (map = sbfd->maps.data;
	     map < sbfd->maps.data + sbfd->maps.size; map++) {
		if (strcmp(map->orig_label, oldlabel) == 0) {
			if (strcmp(map->orig_label, map->label) != 0 &&
			    strcmp(map->label, label) != 0)
				DIE;
			map->label = label;
			return;
		}
	}
	DIE;
}

static void init_callers(struct superbfd *sbfd)
{
	string_hash_init(&sbfd->callers);
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		arelent **relocp;
		for (relocp = ss->relocs.data;
		     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
			asymbol *sym = *(*relocp)->sym_ptr_ptr;
			unsigned long val =
			    sym->value + get_reloc_offset(ss, *relocp, true);
			char *key;
			assert(asprintf(&key, "%s+%lx", sym->section->name,
					val) >= 0);
			const char **ret = string_hash_lookup(&sbfd->callers,
							      key, TRUE);
			free(key);
			if (*ret == NULL)
				*ret = sect->name;
			else
				*ret = "*multiple_callers*";
		}
	}
}

static const char *find_caller(struct supersect *ss, asymbol *sym)
{
	char *key;
	assert(asprintf(&key, "%s+%lx", sym->section->name,
			(unsigned long)sym->value) >= 0);
	const char **ret = string_hash_lookup(&ss->parent->callers, key, FALSE);
	free(key);

	if (ret == NULL)
		return "*no_caller*";
	return *ret;
}

static void init_csyms(struct superbfd *sbfd)
{
	asymbolpp_hash_init(&sbfd->csyms);

	asymbol **symp;
	for (symp = sbfd->syms.data; symp < sbfd->syms.data + sbfd->syms.size;
	     symp++) {
		asymbol *sym = *symp;
		if ((sym->flags & BSF_DEBUGGING) != 0)
			continue;
		char *key;
		assert(asprintf(&key, "%s+%lx", sym->section->name,
				(unsigned long)sym->value) >= 0);
		asymbol ***csympp = asymbolpp_hash_lookup(&sbfd->csyms, key,
							  TRUE);
		free(key);
		if (*csympp == NULL) {
			*csympp = symp;
			continue;
		}
		asymbol *csym = **csympp;
		if ((csym->flags & BSF_GLOBAL) != 0)
			continue;
		if ((sym->flags & BSF_GLOBAL) != 0)
			*csympp = symp;
	}
}

static asymbol **symbolp_scan(struct supersect *ss, bfd_vma value)
{
	char *key;
	assert(asprintf(&key, "%s+%lx", ss->name, (unsigned long)value) >= 0);
	asymbol ***csympp =
	    asymbolpp_hash_lookup(&ss->parent->csyms, key, FALSE);
	free(key);
	if (csympp != NULL)
		return *csympp;

	/* For section symbols of sections containing no symbols, return the
	   section symbol that relocations are generated against */
	if (value == 0)
		return &ss->symbol;
	return NULL;
}

static asymbol **canonical_symbolp(struct superbfd *sbfd, asymbol *sym)
{
	if (bfd_is_const_section(sym->section)) {
		asymbol **csymp;
		for (csymp = sbfd->syms.data;
		     csymp < sbfd->syms.data + sbfd->syms.size; csymp++) {
			if (sym == *csymp)
				return csymp;
		}
		return NULL;
	}
	return symbolp_scan(fetch_supersect(sbfd, sym->section), sym->value);
}

static asymbol *canonical_symbol(struct superbfd *sbfd, asymbol *sym)
{
	if (bfd_is_const_section(sym->section))
		return sym;
	asymbol **symp = canonical_symbolp(sbfd, sym);
	return symp != NULL ? *symp : NULL;
}

static char *static_local_symbol(struct superbfd *sbfd, asymbol *sym)
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

static char *symbol_label(struct superbfd *sbfd, asymbol *sym)
{
	const char *filename = sbfd->abfd->filename;
	char *c = strstr(filename, ".KSPLICE");
	int flen = (c == NULL ? strlen(filename) : c - filename);

	char *label;
	if (bfd_is_und_section(sym->section) || (sym->flags & BSF_GLOBAL) != 0) {
		label = strdup(sym->name);
	} else if (bfd_is_const_section(sym->section)) {
		assert(asprintf(&label, "%s<%.*s>",
				sym->name, flen, filename) >= 0);
	} else {
		asymbol *gsym = canonical_symbol(sbfd, sym);

		if (gsym == NULL)
			assert(asprintf(&label, "%s+%lx<%.*s>",
					sym->section->name,
					(unsigned long)sym->value,
					flen, filename) >= 0);
		else if ((gsym->flags & BSF_GLOBAL) != 0)
			label = strdup(gsym->name);
		else if (static_local_symbol(sbfd, gsym))
			assert(asprintf(&label, "%s+%lx<%.*s>",
					static_local_symbol(sbfd, gsym),
					(unsigned long)sym->value,
					flen, filename) >= 0);
		else
			assert(asprintf(&label, "%s<%.*s>",
					gsym->name, flen, filename) >= 0);
	}

	return label;
}

static void keep_span(struct span *span)
{
	span->keep = true;
	span->ss->keep = true;
}

static struct span *new_span(struct supersect *ss, bfd_vma start, bfd_vma size)
{
	struct span *span = vec_grow(&ss->spans, 1);
	span->size = size;
	span->start = start;
	span->ss = ss;
	span->keep = true;
	span->new = false;
	span->patch = false;
	span->match = NULL;
	span->shift = 0;
	asymbol **symp = symbolp_scan(ss, span->start);
	if (symp != NULL) {
		span->symbol = *symp;
		span->label = label_lookup(ss->parent, span->symbol);
	} else {
		span->symbol = NULL;
		const char *label = label_lookup(ss->parent, ss->symbol);
		if (span->start != 0) {
			char *buf;
			assert(asprintf(&buf, "%s<span:%lx>", label,
					(unsigned long)span->start) >= 0);
			span->label = buf;
		} else {
			span->label = label;
		}
	}
	span->orig_label = span->label;
	return span;
}

static void initialize_string_spans(struct supersect *ss)
{
	const char *str;
	for (str = ss->contents.data;
	     (void *)str < ss->contents.data + ss->contents.size;) {
		bfd_vma start = (unsigned long)str -
		    (unsigned long)ss->contents.data;
		bfd_vma size = strlen(str) + 1;
		while ((start + size) % (1 << ss->alignment) != 0 &&
		       start + size < ss->contents.size) {
			if (str[size] != '\0')
				DIE;
			size++;
		}
		new_span(ss, start, size);
		str += size;
	}
}

static int compare_ulongs(const void *va, const void *vb)
{
	const unsigned long *a = va, *b = vb;
	return *a - *b;
}

static void initialize_table_spans(struct superbfd *sbfd,
				   struct table_section *s)
{
	asection *isection = bfd_get_section_by_name(sbfd->abfd, s->sect);
	if (isection == NULL)
		return;
	asection *other_sect = NULL;
	if (s->other_sect != NULL)
		other_sect = bfd_get_section_by_name(sbfd->abfd, s->other_sect);

	struct supersect *ss = fetch_supersect(sbfd, isection);
	if (ss->alignment < ffs(s->entry_align) - 1)
		ss->alignment = ffs(s->entry_align) - 1;

	struct supersect *other_ss = NULL;
	if (other_sect != NULL)
		other_ss = fetch_supersect(sbfd, other_sect);

	struct ulong_vec offsets;
	vec_init(&offsets);

	void *entry;
	for (entry = ss->contents.data;
	     entry < ss->contents.data + ss->contents.size;
	     entry += s->entry_size) {
		new_span(ss, addr_offset(ss, entry), s->entry_size);

		if (other_sect != NULL) {
			asymbol *sym;
			bfd_vma offset = read_reloc(ss, entry + s->other_offset,
						    sizeof(void *), &sym);
			if (sym->section == other_sect) {
				assert(offset >= 0 &&
				       offset < other_ss->contents.size);
				*vec_grow(&offsets, 1) = offset;
			}
		}
	}

	if (other_sect == NULL)
		return;

	qsort(offsets.data, offsets.size, sizeof(*offsets.data),
	      compare_ulongs);
	*vec_grow(&offsets, 1) = other_ss->contents.size;

	unsigned long *off;
	for (off = offsets.data; off < offsets.data + offsets.size - 1; off++) {
		if (*off != *(off + 1))
			new_span(other_ss, *off, *(off + 1) - *off);
	}
}

static void initialize_table_section_spans(struct superbfd *sbfd)
{
	struct supersect *tables_ss =
	    fetch_supersect(offsets_sbfd,
			    bfd_get_section_by_name(offsets_sbfd->abfd,
						    ".ksplice_table_sections"));
	const struct table_section *ts;
	struct table_section s;
	for (ts = tables_ss->contents.data;
	     (void *)ts < tables_ss->contents.data + tables_ss->contents.size;
	     ts++) {
		s = *ts;
		s.sect = read_string(tables_ss, &ts->sect);
		s.other_sect = read_string(tables_ss, &ts->other_sect);
		initialize_table_spans(sbfd, &s);
	}
}

static void initialize_spans(struct superbfd *sbfd)
{
	if (mode("keep"))
		initialize_table_section_spans(sbfd);

	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		if (is_table_section(sect->name, true) && mode("keep"))
			continue;

		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (ss->type == SS_TYPE_STRING)
			initialize_string_spans(ss);
		else if (!mode("keep") || ss->type != SS_TYPE_EXPORT)
			new_span(ss, 0, ss->contents.size);
	}
}

struct span *reloc_target_span(struct supersect *ss, arelent *reloc)
{
	asymbol *sym_ptr = *reloc->sym_ptr_ptr;
	if (bfd_is_const_section(sym_ptr->section))
		return NULL;

	bfd_vma addend = get_reloc_offset(ss, reloc, true) + sym_ptr->value;
	struct supersect *sym_ss =
	    fetch_supersect(ss->parent, sym_ptr->section);
	struct span *span, *target_span = sym_ss->spans.data;
	for (span = sym_ss->spans.data;
	     span < sym_ss->spans.data + sym_ss->spans.size; span++) {
		if (addend >= span->start && addend < span->start + span->size)
			target_span = span;
	}
	return target_span;
}

struct span *find_span(struct supersect *ss, bfd_size_type address)
{
	struct span *span;
	for (span = ss->spans.data; span < ss->spans.data + ss->spans.size;
	     span++) {
		if (address >= span->start &&
		    address < span->start + span->size)
			return span;
	}
	/* Deal with empty BSS sections */
	if (ss->contents.size == 0 && ss->spans.size > 0)
		return ss->spans.data;
	return NULL;
}

void compute_span_shifts(struct superbfd *sbfd)
{
	asection *sect;
	struct span *span;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (!ss->keep)
			continue;
		bfd_size_type offset = 0;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (!span->keep)
				continue;
			span->shift = offset - span->start;
			offset += span->size;
		}
	}
}

void remove_unkept_spans(struct superbfd *sbfd)
{
	asection *sect;
	struct span *span;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		delete_obsolete_relocs(ss);
		struct arelentp_vec orig_relocs;
		vec_move(&orig_relocs, &ss->relocs);
		arelent **relocp, *reloc;
		for (relocp = orig_relocs.data;
		     relocp < orig_relocs.data + orig_relocs.size; relocp++) {
			reloc = *relocp;
			asymbol *sym = *reloc->sym_ptr_ptr;
			span = reloc_target_span(ss, reloc);
			if ((span != NULL && span->keep && span->shift == 0) ||
			    bfd_is_const_section(sym->section)) {
				*vec_grow(&ss->relocs, 1) = reloc;
				continue;
			}
			struct supersect *sym_ss =
			    fetch_supersect(sbfd, sym->section);
			if (span != NULL && (sym->flags & BSF_SECTION_SYM) == 0
			    && find_span(sym_ss, sym->value) != span) {
				err(sbfd, "Spans for symbol %s and relocation "
				    "target do not match in sect %s\n",
				    sym->name, sym_ss->name);
				DIE;
			}
			if (span != NULL && span->keep) {
				arelent *new_reloc = malloc(sizeof(*new_reloc));
				*new_reloc = *reloc;
				new_reloc->addend =
				    get_reloc_offset(ss, reloc, false);
				new_reloc->addend += span->shift;
				*vec_grow(&ss->new_relocs, 1) = new_reloc;
			}
		}
	}

	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect), orig_ss;
		if (!ss->keep)
			continue;
		supersect_move(&orig_ss, ss);
		vec_init(&ss->spans);
		for (span = orig_ss.spans.data;
		     span < orig_ss.spans.data + orig_ss.spans.size; span++) {
			if (!span->keep)
				continue;
			struct span *new_span = vec_grow(&ss->spans, 1);
			*new_span = *span;
			new_span->start = span->start + span->shift;
			new_span->shift = 0;
			sect_copy(ss, sect_do_grow(ss, 1, span->size, 1),
				  &orig_ss, orig_ss.contents.data + span->start,
				  span->size);
		}
	}
}

static void init_objmanip_superbfd(struct superbfd *sbfd)
{
	init_label_map(sbfd);
	initialize_supersect_types(sbfd);
	initialize_spans(sbfd);
}

void mangle_section_name(struct superbfd *sbfd, const char *name)
{
	asection *sect = bfd_get_section_by_name(sbfd->abfd, name);
	if (sect == NULL)
		return;
	struct supersect *ss = fetch_supersect(sbfd, sect);
	char *buf;
	assert(asprintf(&buf, ".ksplice_pre.%s", ss->name) >= 0);
	ss->name = buf;
}
