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

#define symbol_init(sym) *(sym) = (asymbol *)NULL
DEFINE_HASH_TYPE(asymbol *, symbol_hash, symbol_hash_init, symbol_hash_free,
		 symbol_hash_lookup, symbol_init);

struct export {
	const char *name;
	asection *sect;
};
DECLARE_VEC_TYPE(struct export, export_vec);

DECLARE_VEC_TYPE(const char *, str_vec);

struct wsect {
	asection *sect;
	struct wsect *next;
};

struct export_desc {
	const char *sectname;
	struct str_vec names;
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
			      struct superbfd *newsbfd, char *addstr);
bool relocs_equal(struct supersect *old_ss, struct supersect *new_ss);
static bool part_of_reloc(struct supersect *ss, unsigned long addr);
static bool nonrelocs_equal(struct supersect *old_ss, struct supersect *new_ss);
static void handle_section_symbol_renames(struct superbfd *oldsbfd,
					  struct superbfd *newsbfd);

enum supersect_type supersect_type(struct supersect *ss);
void initialize_supersect_types(struct superbfd *sbfd);
bool is_table_section(const char *name, bool consider_other);

void rm_relocs(struct superbfd *isbfd);
void rm_some_relocs(struct supersect *ss);
void write_ksplice_reloc(struct supersect *ss, arelent *orig_reloc);
void blot_section(struct supersect *ss, int offset, reloc_howto_type *howto);
void write_ksplice_section(struct superbfd *sbfd, asymbol **symp);
void write_ksplice_patch(struct superbfd *sbfd, const char *sectname);
void write_ksplice_deleted_patch(struct superbfd *sbfd, const char *name,
				 const char *label);
void filter_table_sections(struct superbfd *isbfd);
void filter_table_section(struct superbfd *sbfd, const struct table_section *s);
void keep_if_referenced(bfd *abfd, asection *sect, void *ignored);
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
static bool deleted_table_section_symbol(bfd *abfd, asymbol *sym);
void read_str_set(struct str_vec *strs);
bool str_in_set(const char *str, const struct str_vec *strs);
struct supersect *make_section(struct superbfd *sbfd, const char *name);
void __attribute__((format(printf, 3, 4)))
write_string(struct supersect *ss, const char **addr, const char *fmt, ...);
void rm_some_exports(struct superbfd *isbfd, const struct export_desc *ed);
void write_ksplice_export(struct superbfd *sbfd, const char *symname,
			  const char *export_type, bool del);
void write_reloc(struct supersect *ss, const void *addr, asymbol **symp,
		 bfd_vma offset);
arelent *create_reloc(struct supersect *ss, const void *addr, asymbol **symp,
		      bfd_vma offset);
static void match_global_symbol_sections(struct superbfd *oldsbfd,
				  struct superbfd *newsbfd);
static void match_sections_by_name(struct superbfd *oldsbfd,
				   struct superbfd *newsbfd);
static void match_sections_by_contents(struct superbfd *oldsbfd,
				       struct superbfd *newsbfd);
static void match_sections_by_label(struct superbfd *oldsbfd,
				    struct superbfd *newsbfd);
static void mark_new_sections(struct superbfd *sbfd);
static void handle_deleted_sections(struct superbfd *oldsbfd,
				    struct superbfd *newsbfd);
static void compare_matched_sections(struct superbfd *sbfd);
static void update_nonzero_offsets(struct superbfd *sbfd);
static void handle_nonzero_offset_relocs(struct supersect *ss);

static const char *label_lookup(struct superbfd *sbfd, asymbol *sym);
static void print_label_map(struct superbfd *sbfd);
static void label_map_set(struct superbfd *sbfd, const char *oldlabel,
			  const char *label);
static void init_label_map(struct superbfd *sbfd);

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

const char *modestr, *kid;

struct superbfd *offsets_sbfd = NULL;

#define mode(str) starts_with(modestr, str)

DECLARE_VEC_TYPE(unsigned long, addr_vec);
DEFINE_HASH_TYPE(struct addr_vec, addr_vec_hash,
		 addr_vec_hash_init, addr_vec_hash_free, addr_vec_hash_lookup,
		 vec_init);
struct addr_vec_hash system_map;

struct bool_hash system_map_written;
struct ulong_hash ksplice_symbol_offset;
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
	if (ss->type == SS_TYPE_IGNORED && !starts_with(ss->name, ".debug"))
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
	bfd *obfd = bfd_openw(argv[2], output_target);
	assert(obfd);

	struct superbfd *isbfd = fetch_superbfd(ibfd);
	init_label_map(isbfd);

	bool_hash_init(&system_map_written);
	ulong_hash_init(&ksplice_symbol_offset);
	ulong_hash_init(&ksplice_string_offset);

	modestr = argv[3];
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

	copy_object(ibfd, obfd);

	if (offsets_sbfd != NULL)
		assert(bfd_close(offsets_sbfd->abfd));
	assert(bfd_close(obfd));
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
	init_label_map(presbfd);
	load_system_map();
	load_offsets();
	initialize_supersect_types(isbfd);
	initialize_supersect_types(presbfd);

	match_global_symbol_sections(presbfd, isbfd);
	debug1(isbfd, "Matched global\n");
	match_sections_by_name(presbfd, isbfd);
	debug1(isbfd, "Matched by name\n");
	match_sections_by_label(presbfd, isbfd);
	debug1(isbfd, "Matched by label\n");
	match_sections_by_contents(presbfd, isbfd);
	debug1(isbfd, "Matched by contents\n");

	do {
		changed = false;
		compare_matched_sections(isbfd);
		update_nonzero_offsets(isbfd);
		mark_new_sections(isbfd);
	} while (changed);
	vec_init(&delsects);

	handle_deleted_sections(presbfd, isbfd);
	handle_section_symbol_renames(presbfd, isbfd);

	vec_init(&exports);
	compare_exported_symbols(presbfd, isbfd, "");
	compare_exported_symbols(isbfd, presbfd, "del_");

	assert(bfd_close(prebfd));

	asection *sect;
	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		ss->keep = false;
		if (ss->type == SS_TYPE_STRING || ss->type == SS_TYPE_SPECIAL ||
		    ss->type == SS_TYPE_EXPORT)
			ss->keep = true;
		if (ss->new || ss->patch)
			ss->keep = true;
	}

	print_label_map(isbfd);

	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		if (ss->patch)
			debug0(isbfd, "Patching section: %s\n", sect->name);
	}

	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		if (ss->new)
			debug0(isbfd, "New section: %s\n", sect->name);
	}

	const char **sectname;
	for (sectname = delsects.data;
	     sectname < delsects.data + delsects.size; sectname++)
		debug0(isbfd, "Deleted section: %s\n", *sectname);

	const struct export_desc *ed;
	for (ed = exports.data; ed < exports.data + exports.size; ed++) {
		const char **symname;
		bool del = starts_with(ed->sectname, "del___ksymtab");
		const char *export_type = ed->sectname + strlen("__ksymtab");
		if (del)
			export_type += strlen("_del");
		for (symname = ed->names.data;
		     symname < ed->names.data + ed->names.size; symname++)
			debug0(isbfd, "Export %s (%s): %s\n",
			       del ? "deletion" : "addition",
			       export_type, *symname);
	}

	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		if (!ss->patch && !ss->new)
			continue;
		asymbol **symp = canonical_symbolp(isbfd, sect->symbol);
		if (symp == NULL)
			DIE;
		write_ksplice_section(isbfd, symp);
		if (ss->patch)
			write_ksplice_patch(isbfd, sect->name);
	}

	for (ed = exports.data; ed < exports.data + exports.size; ed++) {
		if (starts_with(ed->sectname, "del___ksymtab")) {
			const char *export_type =
			    ed->sectname + strlen("del___ksymtab");
			const char **symname;
			for (symname = ed->names.data;
			     symname < ed->names.data + ed->names.size;
			     symname++)
				write_ksplice_export(isbfd, *symname,
						     export_type, true);
		} else {
			rm_some_exports(isbfd, ed);
		}
	}

	rm_relocs(isbfd);
	filter_table_sections(isbfd);
}

void do_keep_helper(struct superbfd *isbfd)
{
	load_system_map();
	load_offsets();
	initialize_supersect_types(isbfd);

	asection *sect;
	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		ss->keep = false;
		if (ss->type == SS_TYPE_STRING || ss->type == SS_TYPE_SPECIAL ||
		    ss->type == SS_TYPE_TEXT)
			ss->keep = true;
	}
	do {
		changed = false;
		bfd_map_over_sections(isbfd->abfd, keep_if_referenced, NULL);
	} while (changed);

	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		asymbol **symp = canonical_symbolp(isbfd, sect->symbol);
		if (symp == NULL)
			continue;
		asymbol *sym = *symp;
		if ((sym->flags & BSF_WEAK) != 0)
			continue;
		if (bfd_get_section_size(sect) == 0)
			continue;
		if (ss->keep && (ss->type == SS_TYPE_TEXT ||
				 matchable_data_section(ss)))
			write_ksplice_section(isbfd, symp);
	}

	rm_relocs(isbfd);
	filter_table_sections(isbfd);
}

void do_finalize(struct superbfd *isbfd)
{
	load_system_map();
	load_offsets();
	initialize_supersect_types(isbfd);
	rm_relocs(isbfd);
}

void do_rmsyms(struct superbfd *isbfd)
{
	read_str_set(&rmsyms);
	load_system_map();
	load_offsets();
	initialize_supersect_types(isbfd);
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
	asection *last_sect = NULL;
	struct export_desc *ed;
	for (new = new_exports->data; new < new_exports->data +
	     new_exports->size; new++) {
		bool found = false;
		if (old_exports != NULL) {
			for (old = old_exports->data; old < old_exports->data +
			     old_exports->size; old++) {
				if (strcmp(new->name, old->name) == 0 &&
				    strcmp(new->sect->name, old->sect->name)
				    == 0) {
					found = true;
					break;
				}
			}
		}
		if (last_sect != new->sect) {
			last_sect = new->sect;
			ed = vec_grow(&exports, 1);
			char *sectname;
			assert(asprintf(&sectname, "%s%s", addstr,
					new->sect->name) >= 0);
			ed->sectname = sectname;
			vec_init(&ed->names);
		}
		if (!found)
			*vec_grow(&ed->names, 1) = new->name;
	}
}

void match_sections(struct supersect *oldss, struct supersect *newss)
{
	if (oldss->match == newss && newss->match == oldss)
		return;
	if (oldss->match != NULL) {
		err(newss->parent, "Matching conflict: old %s: %s != %s\n",
		    oldss->name, oldss->match->name, newss->name);
		DIE;
	}
	if (newss->match != NULL) {
		err(newss->parent, "Matching conflict: new %s: %s != %s\n",
		    newss->name, newss->match->name, oldss->name);
		DIE;
	}
	oldss->match = newss;
	newss->match = oldss;
	debug1(newss->parent, "Matched old %s to new %s\n",
	       oldss->name, newss->name);
}

static void match_global_symbol_sections(struct superbfd *oldsbfd,
					 struct superbfd *newsbfd)
{
	asymbol **oldsymp, **newsymp;
	for (oldsymp = oldsbfd->syms.data;
	     oldsymp < oldsbfd->syms.data + oldsbfd->syms.size; oldsymp++) {
		asymbol *oldsym = *oldsymp;
		if ((oldsym->flags & BSF_GLOBAL) == 0 ||
		    bfd_is_const_section(oldsym->section))
			continue;
		for (newsymp = newsbfd->syms.data;
		     newsymp < newsbfd->syms.data + newsbfd->syms.size;
		     newsymp++) {
			asymbol *newsym = *newsymp;
			if ((newsym->flags & BSF_GLOBAL) == 0 ||
			    bfd_is_const_section(oldsym->section))
				continue;
			if (strcmp(oldsym->name, newsym->name) != 0)
				continue;
			struct supersect *oldss =
			    fetch_supersect(oldsbfd, oldsym->section);
			struct supersect *newss =
			    fetch_supersect(newsbfd, newsym->section);
			match_sections(oldss, newss);
		}
	}
}

static void match_sections_by_name(struct superbfd *oldsbfd,
				   struct superbfd *newsbfd)
{
	asection *newp, *oldp;
	for (newp = newsbfd->abfd->sections; newp != NULL; newp = newp->next) {
		struct supersect *newss = fetch_supersect(newsbfd, newp);
		oldp = bfd_get_section_by_name(oldsbfd->abfd, newp->name);
		if (oldp == NULL || newss->type == SS_TYPE_STRING ||
		    newss->type == SS_TYPE_SPECIAL ||
		    newss->type == SS_TYPE_EXPORT)
			continue;
		if (static_local_symbol(newsbfd,
					canonical_symbol(newsbfd,
							 newp->symbol)))
			continue;

		struct supersect *oldss = fetch_supersect(oldsbfd, oldp);
		match_sections(oldss, newss);
	}
}

static void match_sections_by_label(struct superbfd *oldsbfd,
				    struct superbfd *newsbfd)
{
	asection *oldsect, *newsect;
	struct supersect *oldss, *newss;
	for (newsect = newsbfd->abfd->sections; newsect != NULL;
	     newsect = newsect->next) {
		newss = fetch_supersect(newsbfd, newsect);
		if (newss->type == SS_TYPE_STRING ||
		    newss->type == SS_TYPE_SPECIAL ||
		    newss->type == SS_TYPE_EXPORT)
			continue;
		for (oldsect = oldsbfd->abfd->sections; oldsect != NULL;
		     oldsect = oldsect->next) {
			if (strcmp(label_lookup(newsbfd, newsect->symbol),
				   label_lookup(oldsbfd, oldsect->symbol)) != 0)
				continue;
			oldss = fetch_supersect(oldsbfd, oldsect);
			match_sections(oldss, newss);
		}
	}
}

static void match_sections_by_contents(struct superbfd *oldsbfd,
				       struct superbfd *newsbfd)
{
	asection *oldsect, *newsect;
	struct supersect *oldss, *newss;
	for (newsect = newsbfd->abfd->sections; newsect != NULL;
	     newsect = newsect->next) {
		newss = fetch_supersect(newsbfd, newsect);
		if (newss->type != SS_TYPE_RODATA)
			continue;
		for (oldsect = oldsbfd->abfd->sections; oldsect != NULL;
		     oldsect = oldsect->next) {
			oldss = fetch_supersect(oldsbfd, oldsect);
			if (oldss->type != SS_TYPE_RODATA)
				continue;
			if (oldss->relocs.size != 0 || newss->relocs.size != 0)
				continue;
			if (oldss->contents.size != newss->contents.size)
				continue;
			if (memcmp(oldss->contents.data, newss->contents.data,
				   oldss->contents.size) != 0)
				continue;
			match_sections(oldss, newss);
		}
	}
}

static void mark_new_sections(struct superbfd *sbfd)
{
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (ss->type == SS_TYPE_STRING || ss->type == SS_TYPE_SPECIAL ||
		    ss->type == SS_TYPE_IGNORED || ss->type == SS_TYPE_EXPORT)
			continue;
		if (ss->match == NULL)
			ss->new = true;
	}
}

static void handle_deleted_sections(struct superbfd *oldsbfd,
				    struct superbfd *newsbfd)
{
	asection *sect;
	for (sect = oldsbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(oldsbfd, sect);
		if (ss->type != SS_TYPE_TEXT)
			continue;
		if (ss->match != NULL)
			continue;
		const char *label = label_lookup(oldsbfd, sect->symbol);
		*vec_grow(&delsects, 1) = label;
		asymbol *csym = canonical_symbol(oldsbfd, sect->symbol);
		write_ksplice_deleted_patch(newsbfd, csym->name, label);
	}
}

static void handle_nonzero_offset_relocs(struct supersect *ss)
{
	int i;
	for (i = 0; i < ss->relocs.size; i++) {
		asymbol *sym = *ss->relocs.data[i]->sym_ptr_ptr;
		bfd_vma offset = get_reloc_offset(ss, ss->relocs.data[i], true);
		if (sym->value + offset == 0)
			continue;
		if (bfd_is_const_section(sym->section))
			continue;
		struct supersect *sym_ss = fetch_supersect(ss->parent,
							   sym->section);
		if (sym_ss->type != SS_TYPE_TEXT)
			continue;
		if (!sym_ss->patch) {
			changed = true;
			debug1(ss->parent,
			       "Changing %s because a relocation from sect %s "
			       "has a nonzero offset %lx+%lx into it\n",
			       sym_ss->name, ss->name,
			       (unsigned long)sym->value,
			       (unsigned long)offset);
		}
		sym_ss->patch = true;
	}
}

static void update_nonzero_offsets(struct superbfd *sbfd)
{
	asection *sect;
	struct supersect *ss;

	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		ss = fetch_supersect(sbfd, sect);
		if (ss->new || ss->patch)
			handle_nonzero_offset_relocs(ss);
	}
}

static void compare_matched_sections(struct superbfd *newsbfd)
{
	asection *newp;
	struct supersect *old_ss, *new_ss;
	for (newp = newsbfd->abfd->sections; newp != NULL; newp = newp->next) {
		new_ss = fetch_supersect(newsbfd, newp);
		if (new_ss->match == NULL)
			continue;
		old_ss = new_ss->match;

		if (nonrelocs_equal(old_ss, new_ss) &&
		    relocs_equal(old_ss, new_ss))
			continue;

		char *reason;
		if (new_ss->contents.size != old_ss->contents.size)
			reason = "differing sizes";
		else if (memcmp(new_ss->contents.data, old_ss->contents.data,
				new_ss->contents.size) != 0)
			reason = "differing contents";
		else
			reason = "differing relocations";
		if (new_ss->type == SS_TYPE_TEXT) {
			if (new_ss->patch)
				continue;
			new_ss->patch = true;
			debug1(newsbfd, "Changing %s due to %s\n", new_ss->name,
			       reason);
		} else {
			debug1(newsbfd, "Unmatching %s and %s due to %s\n",
			       old_ss->name, new_ss->name, reason);
			new_ss->match = NULL;
			old_ss->match = NULL;
		}
		changed = true;
		if (unchangeable_section(new_ss))
			err(newsbfd, "warning: ignoring change to nonpatchable "
			    "section %s\n", new_ss->name);
	}
}

static void handle_section_symbol_renames(struct superbfd *oldsbfd,
					  struct superbfd *newsbfd)
{
	asection *newp, *oldp;
	for (newp = newsbfd->abfd->sections; newp != NULL; newp = newp->next) {
		struct supersect *newss = fetch_supersect(newsbfd, newp);
		if (newss->match == NULL)
			continue;
		oldp = bfd_get_section_by_name(oldsbfd->abfd,
					       newss->match->name);
		if (oldp == NULL)
			continue;

		const char *old_label = label_lookup(oldsbfd, oldp->symbol);
		const char *new_label = label_lookup(newsbfd, newp->symbol);

		if (strcmp(old_label, new_label) == 0)
			continue;
		label_map_set(newsbfd, new_label, old_label);
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

static bool nonrelocs_equal(struct supersect *old_ss, struct supersect *new_ss)
{
	int i;
	if (old_ss->contents.size != new_ss->contents.size)
		return false;
	const unsigned char *old = old_ss->contents.data;
	const unsigned char *new = new_ss->contents.data;
	for (i = 0; i < old_ss->contents.size; i++) {
		if (old[i] != new[i] &&
		    !(part_of_reloc(old_ss, i) && part_of_reloc(new_ss, i)))
			return false;
	}
	return true;
}

/*
 * relocs_equal checks to see whether the old section and the new section
 * reference different read-only data in their relocations -- if a hard-coded
 * string has been changed between the old file and the new file, relocs_equal
 * will detect the difference.
 */
bool relocs_equal(struct supersect *old_ss, struct supersect *new_ss)
{
	int i;
	struct superbfd *oldsbfd = old_ss->parent;
	struct superbfd *newsbfd = new_ss->parent;

	if (old_ss->relocs.size != new_ss->relocs.size) {
		debug1(newsbfd, "Different reloc count between %s and %s\n",
		       old_ss->name, new_ss->name);
		return false;
	}

	for (i = 0; i < old_ss->relocs.size; i++) {
		struct supersect *ro_old_ss, *ro_new_ss;

		asymbol *old_sym = *old_ss->relocs.data[i]->sym_ptr_ptr;
		asymbol *new_sym = *new_ss->relocs.data[i]->sym_ptr_ptr;

		bfd_vma old_offset =
		    get_reloc_offset(old_ss, old_ss->relocs.data[i], true);
		bfd_vma new_offset =
		    get_reloc_offset(new_ss, new_ss->relocs.data[i], true);

		if (bfd_is_und_section(old_sym->section) ||
		    bfd_is_und_section(new_sym->section)) {
			if (!bfd_is_und_section(new_sym->section) &&
			    fetch_supersect(newsbfd, new_sym->section)->type
			    == SS_TYPE_TEXT && old_offset != 0)
				return false;

			if (!bfd_is_und_section(old_sym->section) &&
			    fetch_supersect(oldsbfd, old_sym->section)->type
			    == SS_TYPE_TEXT && new_offset != 0)
				return false;

			if (strcmp(old_sym->name, new_sym->name) == 0 &&
			    old_offset == new_offset)
				continue;
			return false;
		}

		if (bfd_is_const_section(old_sym->section) ||
		    bfd_is_const_section(new_sym->section))
			DIE;

		ro_old_ss = fetch_supersect(oldsbfd, old_sym->section);
		ro_new_ss = fetch_supersect(newsbfd, new_sym->section);

		if (ro_old_ss->type == SS_TYPE_STRING &&
		    /* check it's not an out-of-range relocation to a string;
		       we'll just compare entire sections for them */
		    !(old_offset >= ro_old_ss->contents.size ||
		      new_offset >= ro_new_ss->contents.size)) {
			if (strcmp(ro_old_ss->contents.data + old_sym->value +
				   old_offset,
				   ro_new_ss->contents.data + new_sym->value +
				   new_offset) != 0) {
				debug1(newsbfd,
				       "Strings differ between %s and %s\n",
				       old_ss->name, new_ss->name);
				return false;
			}
			continue;
		}

		if (ro_old_ss->match != ro_new_ss ||
		    ro_new_ss->match != ro_old_ss) {
			debug1(newsbfd, "Nonmatching relocs from %s to %s/%s\n",
			       new_ss->name, ro_new_ss->name, ro_old_ss->name);
			return false;
		}

		if (old_sym->value + old_offset != new_sym->value + new_offset) {
			debug1(newsbfd, "Offsets to %s/%s differ between %s "
			       "and %s: %lx+%lx/%lx+%lx\n", ro_old_ss->name,
			       ro_new_ss->name, old_ss->name, new_ss->name,
			       (unsigned long)old_sym->value,
			       (unsigned long)old_offset,
			       (unsigned long)new_sym->value,
			       (unsigned long)new_offset);
			return false;
		}

		if ((old_sym->value + old_offset != 0 ||
		     new_sym->value + new_offset != 0) && ro_new_ss->patch) {
			debug1(newsbfd, "Relocation from %s to nonzero offsets "
			       "%lx+%lx/%lx+%lx in changed section %s\n",
			       new_ss->name,
			       (unsigned long)old_sym->value,
			       (unsigned long)old_offset,
			       (unsigned long)new_sym->value,
			       (unsigned long)new_offset,
			       new_sym->section->name);
			return false;
		}
	}

	return true;
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
		write_ksplice_export(ss->parent, sym->name, export_type, false);
		write_string(ss, (const char **)&ksym->name,
			     "DISABLED_%s_%s", sym->name, kid);

		if (crc_ss != NULL)
			sect_copy(crc_ss,
				  sect_grow(crc_ss, 1, typeof(*orig_crc)),
				  &orig_crc_ss, orig_crc, 1);
	}
}

void rm_relocs(struct superbfd *isbfd)
{
	asection *p;
	for (p = isbfd->abfd->sections; p != NULL; p = p->next) {
		struct supersect *ss = fetch_supersect(isbfd, p);
		if ((mode("keep") && ss->type == SS_TYPE_SPECIAL) ||
		    ss->type == SS_TYPE_KSPLICE)
			continue;
		if (ss->keep || mode("rmsyms"))
			rm_some_relocs(ss);
	}
	if (mode("finalize")) {
		p = bfd_get_section_by_name(isbfd->abfd, ".ksplice_patches");
		if (p != NULL) {
			struct supersect *ss = fetch_supersect(isbfd, p);
			rm_some_relocs(ss);
		}
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
		     fetch_supersect(ss->parent, sym_ptr->section)->new ||
		     fetch_supersect(ss->parent, sym_ptr->section)->type ==
		     SS_TYPE_STRING))
			rm_reloc = false;

		if (mode("finalize") && bfd_is_und_section(sym_ptr->section))
			rm_reloc = true;

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
	arelent *new_reloc = create_reloc(ss, addr, symp, offset), **relocp;
	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		if ((*relocp)->address == new_reloc->address) {
			memmove(relocp,
				relocp + 1,
				(void *)(ss->relocs.data + ss->relocs.size) -
				(void *)(relocp + 1));
			ss->relocs.size--;
			relocp--;
		}
	}
	*vec_grow(&ss->new_relocs, 1) = new_reloc;
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
		*str_offp = (void *)buf - str_ss->contents.data;
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

void write_ksplice_system_map(struct superbfd *sbfd, asymbol *sym,
			      const char *addstr_sect)
{
	struct supersect *smap_ss = make_section(sbfd, ".ksplice_system_map");
	struct ksplice_system_map *smap;
	const char *label = label_lookup(sbfd, sym);

	bool *done = bool_hash_lookup(&system_map_written, label, TRUE);
	if (*done)
		return;
	*done = true;

	smap = sect_grow(smap_ss, 1, struct ksplice_system_map);

	write_system_map_array(sbfd, smap_ss, &smap->candidates,
			       &smap->nr_candidates, sym);
	write_string(smap_ss, &smap->label, "%s%s", label, addstr_sect);
}

void write_ksplice_symbol(struct supersect *ss,
			  const struct ksplice_symbol *const *addr,
			  asymbol *sym, const char *addstr_sect)
{
	struct supersect *ksymbol_ss = make_section(ss->parent,
						    ".ksplice_symbols");
	struct ksplice_symbol *ksymbol;
	unsigned long *ksymbol_offp;
	const char *label = label_lookup(ss->parent, sym);
	char *output;
	assert(asprintf(&output, "%s%s", label, addstr_sect) >= 0);

	ksymbol_offp = ulong_hash_lookup(&ksplice_symbol_offset, output, FALSE);
	if (ksymbol_offp != NULL) {
		write_reloc(ss, addr, &ksymbol_ss->symbol, *ksymbol_offp);
		return;
	}
	ksymbol = sect_grow(ksymbol_ss, 1, struct ksplice_symbol);
	ksymbol_offp = ulong_hash_lookup(&ksplice_symbol_offset, output, TRUE);
	*ksymbol_offp = (void *)ksymbol - ksymbol_ss->contents.data;

	if (bfd_is_und_section(sym->section) || (sym->flags & BSF_GLOBAL) != 0) {
		write_string(ksymbol_ss, &ksymbol->name, "%s", sym->name);
	} else if (bfd_is_const_section(sym->section)) {
		ksymbol->name = NULL;
	} else {
		asymbol *gsym = canonical_symbol(ss->parent, sym);

		if (gsym == NULL || (gsym->flags & BSF_SECTION_SYM) != 0)
			ksymbol->name = NULL;
		else
			write_string(ksymbol_ss, &ksymbol->name, "%s",
				     gsym->name);
	}

	write_string(ksymbol_ss, &ksymbol->label, "%s%s", label, addstr_sect);

	write_ksplice_system_map(ksymbol_ss->parent, sym, addstr_sect);

	write_reloc(ss, addr, &ksymbol_ss->symbol, *ksymbol_offp);
}

void write_ksplice_reloc(struct supersect *ss, arelent *orig_reloc)
{
	asymbol *sym_ptr = *orig_reloc->sym_ptr_ptr;
	reloc_howto_type *howto = orig_reloc->howto;
	bfd_vma addend = get_reloc_offset(ss, orig_reloc, false);

	if (mode("finalize") && starts_with(ss->name, ".ksplice_patches")) {
		unsigned long *repladdr =
		    ss->contents.data + orig_reloc->address;
		*repladdr = 0;
		return;
	}

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
	    ((bfd_vma)KSPLICE_CANARY & howto->dst_mask);
	bfd_put(bits, ss->parent->abfd, x, address);
}

void write_ksplice_section(struct superbfd *sbfd, asymbol **symp)
{
	asymbol *sym = *symp;
	struct supersect *ksect_ss = make_section(sbfd, ".ksplice_sections");
	struct ksplice_section *ksect = sect_grow(ksect_ss, 1,
						  struct ksplice_section);

	write_ksplice_symbol(ksect_ss, &ksect->symbol, sym,
			     mode("keep-primary") ? "(post)" : "");
	ksect->size = bfd_get_section_size(sym->section);
	ksect->flags = 0;
	struct supersect *sym_ss = fetch_supersect(sbfd, sym->section);
	if (sym_ss->type == SS_TYPE_RODATA)
		ksect->flags |= KSPLICE_SECTION_RODATA;
	if (sym_ss->type == SS_TYPE_DATA)
		ksect->flags |= KSPLICE_SECTION_DATA;
	if (sym_ss->type == SS_TYPE_TEXT)
		ksect->flags |= KSPLICE_SECTION_TEXT;
	assert(ksect->flags != 0);
	write_reloc(ksect_ss, &ksect->address, symp, 0);
}

void write_ksplice_patch(struct superbfd *sbfd, const char *sectname)
{
	struct supersect *kpatch_ss = make_section(sbfd, ".ksplice_patches");
	struct ksplice_patch *kpatch = sect_grow(kpatch_ss, 1,
						 struct ksplice_patch);
	asection *sect = bfd_get_section_by_name(sbfd->abfd, sectname);
	assert(sect != NULL);

	write_string(kpatch_ss, &kpatch->label, "%s",
		     label_lookup(sbfd, sect->symbol));
	write_reloc(kpatch_ss, &kpatch->repladdr, &sect->symbol, 0);
}

void write_ksplice_deleted_patch(struct superbfd *sbfd, const char *name,
				 const char *label)
{
	struct supersect *kpatch_ss = make_section(sbfd, ".ksplice_patches");
	struct ksplice_patch *kpatch = sect_grow(kpatch_ss, 1,
						 struct ksplice_patch);

	write_string(kpatch_ss, &kpatch->label, "%s", label);
	asymbol **symp;
	for (symp = sbfd->syms.data; symp < sbfd->syms.data + sbfd->syms.size;
	     symp++) {
		asymbol *sym = *symp;
		if (bfd_is_und_section(sym->section) &&
		    strcmp(name, sym->name) == 0)
			break;
	}
	if (symp >= sbfd->syms.data + sbfd->syms.size) {
		symp = malloc(sizeof(*symp));
		*symp = bfd_make_empty_symbol(sbfd->abfd);
		asymbol *sym = *symp;
		sym->name = strdup(name);
		sym->section = bfd_und_section_ptr;
		sym->flags = 0;
		sym->value = 0;
		*vec_grow(&sbfd->new_syms, 1) = symp;
	}
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

struct fixup_entry {
	bfd_vma offset;
	bool used;
	bfd_vma ex_offset;
};
DECLARE_VEC_TYPE(struct fixup_entry, fixup_entry_vec);

int compare_fixups(const void *aptr, const void *bptr)
{
	const struct fixup_entry *a = aptr, *b = bptr;
	if (a->offset < b->offset)
		return -1;
	else if (a->offset > b->offset)
		return 1;
	else
		return (int)a->used - (int)b->used;
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
		filter_table_section(isbfd, &s);
	}
}

void filter_table_section(struct superbfd *sbfd, const struct table_section *s)
{
	asection *isection = bfd_get_section_by_name(sbfd->abfd, s->sect);
	if (isection == NULL)
		return;
	asection *fixup_sect = NULL;
	if (s->other_sect != NULL)
		fixup_sect = bfd_get_section_by_name(sbfd->abfd, s->other_sect);

	struct supersect *ss = fetch_supersect(sbfd, isection), orig_ss;
	supersect_move(&orig_ss, ss);

	struct supersect *fixup_ss = NULL;
	if (fixup_sect != NULL)
		fixup_ss = fetch_supersect(sbfd, fixup_sect);

	struct fixup_entry_vec fixups;
	vec_init(&fixups);

	void *orig_entry;
	for (orig_entry = orig_ss.contents.data;
	     orig_entry < orig_ss.contents.data + orig_ss.contents.size;
	     orig_entry += s->entry_size) {
		asymbol *sym, *fixup_sym;
		read_reloc(&orig_ss, orig_entry + s->addr_offset,
			   sizeof(void *), &sym);

		struct fixup_entry *f;
		if (fixup_sect != NULL) {
			bfd_vma fixup_offset =
			    read_reloc(&orig_ss, orig_entry + s->other_offset,
				       sizeof(void *), &fixup_sym);
			if (fixup_sym->section == fixup_sect) {
				assert(fixup_offset < fixup_ss->contents.size);
				f = vec_grow(&fixups, 1);
				f->offset = fixup_offset;
				f->used = false;
			}
		}

		struct supersect *sym_ss = fetch_supersect(sbfd, sym->section);
		if (!sym_ss->keep)
			continue;

		if (fixup_sect != NULL && fixup_sym->section == fixup_sect) {
			f->used = true;
			f->ex_offset = ss->contents.size + s->other_offset;
		}
		sect_copy(ss, sect_do_grow(ss, 1, s->entry_size,
					   s->entry_align),
			  &orig_ss, orig_entry, s->entry_size);
	}

	if (fixup_sect == NULL)
		return;

	struct supersect orig_fixup_ss;
	supersect_move(&orig_fixup_ss, fixup_ss);

	qsort(fixups.data, fixups.size, sizeof(*fixups.data), compare_fixups);
	*vec_grow(&fixups, 1) = (struct fixup_entry)
	    { .offset = orig_fixup_ss.contents.size, .used = false };

	struct fixup_entry *f;
	for (f = fixups.data; f < fixups.data + fixups.size - 1; f++) {
		if (!f->used)
			continue;
		write_reloc(ss, ss->contents.data + f->ex_offset,
			    &fixup_ss->symbol, fixup_ss->contents.size);
		sect_copy(fixup_ss,
			  sect_grow(fixup_ss, (f + 1)->offset - f->offset,
				    unsigned char),
			  &orig_fixup_ss,
			  orig_fixup_ss.contents.data + f->offset,
			  (f + 1)->offset - f->offset);
	}
}

void keep_if_referenced(bfd *abfd, asection *sect, void *ignored)
{
	struct superbfd *sbfd = fetch_superbfd(abfd);
	struct supersect *ss = fetch_supersect(sbfd, sect);
	if (ss->keep || ss->type == SS_TYPE_IGNORED)
		return;

	asymbol **symp;
	for (symp = sbfd->syms.data;
	     symp < sbfd->syms.data + sbfd->syms.size; symp++) {
		asymbol *sym = *symp;
		if (sym->section == sect && (sym->flags & BSF_GLOBAL) != 0) {
			ss->keep = true;
			changed = true;
			return;
		}
	}

	bfd_map_over_sections(abfd, check_for_ref_to_section, sect);
}

void check_for_ref_to_section(bfd *abfd, asection *looking_at,
			      void *looking_for)
{
	struct superbfd *sbfd = fetch_superbfd(abfd);
	struct supersect *ss = fetch_supersect(sbfd, looking_at);
	struct supersect *for_ss = fetch_supersect(sbfd,
						   (asection *)looking_for);
	if (!ss->keep || ss->type == SS_TYPE_STRING ||
	    ss->type == SS_TYPE_SPECIAL || ss->type == SS_TYPE_EXPORT)
		return;

	arelent **relocp;
	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		asymbol *sym = *(*relocp)->sym_ptr_ptr;
		if (sym->section != (asection *)looking_for)
			continue;
		for_ss->keep = true;
		changed = true;
		return;
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

	asection *osection = bfd_make_section_anyway(obfd, isection->name);
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

void write_section(bfd *obfd, asection *osection, void *arg)
{
	struct supersect *ss = osection->userdata;

	if ((ss->flags & SEC_GROUP) != 0 || ss->contents.size == 0)
		return;

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
	return symp >= ss->syms.data + ss->syms.size;
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
	struct superbfd *sbfd = fetch_superbfd(ibfd);
	for (symp = isyms->data; symp < isyms->data + isyms->size; symp++) {
		asymbol *sym = *symp;
		struct supersect *sym_ss = NULL;
		if (!bfd_is_const_section(sym->section))
			sym_ss = fetch_supersect(sbfd, sym->section);

		bool keep = false;

		if (mode("keep") && (sym->flags & BSF_GLOBAL) != 0 &&
		    !(mode("keep-primary") && sym_ss != NULL && sym_ss->new))
			sym->flags = (sym->flags & ~BSF_GLOBAL) | BSF_LOCAL;

		if (mode("finalize") && (sym->flags & BSF_GLOBAL) != 0)
			sym->flags = (sym->flags & ~BSF_GLOBAL) | BSF_LOCAL;

		if ((sym->flags & BSF_KEEP) != 0	/* Used in relocation.  */
		    || ((sym->flags & BSF_SECTION_SYM) != 0 && sym_ss != NULL &&
			sym_ss->keep))
			keep = true;
		else if ((sym->flags & (BSF_GLOBAL | BSF_WEAK)) != 0 &&
			 sym_ss != NULL && sym_ss->keep)
			keep = true;
		else if (mode("keep-primary") &&
			 starts_with(sym->section->name, "__ksymtab"))
			keep = true;

		if (deleted_table_section_symbol(ibfd, sym))
			keep = false;

		if (bfd_is_com_section(sym->section))
			keep = false;

		if (mode("rmsyms"))
			keep = !str_in_set(sym->name, &rmsyms);

		if (keep) {
			assert(sym_ss == NULL || sym_ss->keep);
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

enum supersect_type supersect_type(struct supersect *ss)
{
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

	if (bfd_get_section_by_name(ss->parent->abfd, ".exitcall.exit") == NULL) {
		if (starts_with(ss->name, ".exit.text"))
			return SS_TYPE_TEXT;
		if (starts_with(ss->name, ".exit.data"))
			return SS_TYPE_DATA;
	} else if (starts_with(ss->name, ".exit.text") ||
		   starts_with(ss->name, ".exit.data"))
		return SS_TYPE_IGNORED;

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
	    starts_with(ss->name, ".sched.text"))
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
	    starts_with(ss->name, "__markers_strings"))
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
	vec_init(&sbfd->maps);
	struct label_map *map, *map2;

	asymbol **symp;
	for (symp = sbfd->syms.data;
	     symp < sbfd->syms.data + sbfd->syms.size; symp++) {
		asymbol *csym = canonical_symbol(sbfd, *symp);
		if (csym == NULL)
			continue;
		for (map = sbfd->maps.data;
		     map < sbfd->maps.data + sbfd->maps.size; map++) {
			if (map->csym == csym)
				break;
		}
		if (map < sbfd->maps.data + sbfd->maps.size)
			continue;
		map = vec_grow(&sbfd->maps, 1);
		map->csym = csym;
		map->count = 0;
		map->index = 0;
		map->label = symbol_label(sbfd, csym);
	}
	for (map = sbfd->maps.data;
	     map < sbfd->maps.data + sbfd->maps.size; map++) {
		for (map2 = sbfd->maps.data;
		     map2 < sbfd->maps.data + sbfd->maps.size; map2++) {
			if (strcmp(map->label, map2->label) != 0)
				continue;
			map->count++;
			if (map2 < map)
				map->index++;
		}
	}

	for (map = sbfd->maps.data;
	     map < sbfd->maps.data + sbfd->maps.size; map++) {
		if (map->count > 1) {
			char *buf;
			assert(asprintf(&buf, "%s~%d", map->label,
					map->index) >= 0);
			map->label = buf;
		}
		map->orig_label = map->label;
	}
}

static const char *label_lookup(struct superbfd *sbfd, asymbol *sym)
{
	struct label_map *map;
	asymbol *csym = canonical_symbol(sbfd, sym);
	for (map = sbfd->maps.data;
	     map < sbfd->maps.data + sbfd->maps.size; map++) {
		if (csym == map->csym)
			return map->label;
	}
	return symbol_label(sbfd, sym);
}

static void print_label_map(struct superbfd *sbfd)
{
	struct label_map *map;
	for (map = sbfd->maps.data;
	     map < sbfd->maps.data + sbfd->maps.size; map++) {
		if (strcmp(map->orig_label, map->label) == 0)
			continue;
		debug1(sbfd, "Label change: %s -> %s\n",
		       map->label, map->orig_label);
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
