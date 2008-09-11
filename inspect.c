/*  Copyright (C) 2008  Anders Kaseorg <andersk@mit.edu>,
 *                      Tim Abbott <tabbott@mit.edu>,
 *                      Jeffrey Brian Arnold <jbarnold@mit.edu>
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

/* Always define KSPLICE_STANDALONE, even if you're using integrated Ksplice.
   inspect won't compile without it. */
#define KSPLICE_STANDALONE

#define _GNU_SOURCE
#include "objcommon.h"
#include "kmodsrc/ksplice.h"
#include <stdio.h>

char *str_ulong_vec(struct supersect *ss, const unsigned long *const *datap,
		    const unsigned long *sizep)
{
	struct supersect *data_ss;
	const unsigned long *data =
	    read_pointer(ss, (void *const *)datap, &data_ss);
	unsigned long size = read_num(ss, sizep);

	char *buf = NULL;
	size_t bufsize = 0;
	FILE *fp = open_memstream(&buf, &bufsize);
	fprintf(fp, "[ ");
	size_t i;
	for (i = 0; i < size; ++i)
		fprintf(fp, "%lx ", read_num(data_ss, &data[i]));
	fprintf(fp, "]");
	fclose(fp);
	return buf;
}

char *str_ksplice_symbol(struct supersect *ss,
			 const struct ksplice_symbol *ksymbol)
{
	char *str;
	assert(asprintf(&str, "%s (%s)",
			read_string(ss, &ksymbol->label),
			read_string(ss, &ksymbol->name)));
	return str;
}

char *str_ksplice_symbolp(struct supersect *ptr_ss,
			  const struct ksplice_symbol *const *ksymbolp)
{
	struct supersect *ss;
	const struct ksplice_symbol *ksymbol =
	    read_pointer(ptr_ss, (void *const *)ksymbolp, &ss);
	return ksymbol == NULL ? "(null)" : str_ksplice_symbol(ss, ksymbol);
}

void show_ksplice_reloc(struct supersect *ss,
			const struct ksplice_reloc *kreloc)
{
	printf("blank_addr: %s  blank_offset: %lx\n"
	       "symbol: %s\n"
	       "addend: %lx\n"
	       "pcrel: %x  size: %x  dst_mask: %lx  rightshift: %x\n"
	       "\n",
	       str_pointer(ss, (void *const *)&kreloc->blank_addr),
	       read_num(ss, &kreloc->blank_offset),
	       str_ksplice_symbolp(ss, &kreloc->symbol),
	       read_num(ss, &kreloc->addend),
	       read_num(ss, &kreloc->pcrel),
	       read_num(ss, &kreloc->size),
	       read_num(ss, &kreloc->dst_mask),
	       read_num(ss, &kreloc->rightshift));
}

void show_ksplice_relocs(struct supersect *kreloc_ss)
{
	printf("KSPLICE RELOCATIONS IN SECTION %s:\n\n", kreloc_ss->name);
	const struct ksplice_reloc *kreloc;
	for (kreloc = kreloc_ss->contents.data; (void *)kreloc <
	     kreloc_ss->contents.data + kreloc_ss->contents.size; kreloc++)
		show_ksplice_reloc(kreloc_ss, kreloc);
	printf("\n");
}

void show_ksplice_section_flags(const struct ksplice_section *ksect)
{
	printf("flags:");
	if (ksect->flags & KSPLICE_SECTION_RODATA)
		printf(" rodata");
	if (ksect->flags & KSPLICE_SECTION_TEXT)
		printf(" text");
	if (ksect->flags & KSPLICE_SECTION_DATA)
		printf(" data");
	printf("\n");
}

void show_ksplice_section(struct supersect *ss,
			  const struct ksplice_section *ksect)
{
	printf("symbol: %s\n"
	       "thismod_addr: %s  size: %lx\n",
	       str_ksplice_symbolp(ss, &ksect->symbol),
	       str_pointer(ss, (void *const *)&ksect->thismod_addr),
	       read_num(ss, &ksect->size));
	show_ksplice_section_flags(ksect);
	printf("\n");
}

void show_ksplice_sections(struct supersect *ksect_ss)
{
	printf("KSPLICE SECTIONS:\n\n");
	struct ksplice_section *ksect;
	for (ksect = ksect_ss->contents.data; (void *)ksect <
	     ksect_ss->contents.data + ksect_ss->contents.size; ksect++)
		show_ksplice_section(ksect_ss, ksect);
	printf("\n");
}

void show_ksplice_patch(struct supersect *ss,
			const struct ksplice_patch *kpatch)
{
	printf("label: %s\n"
	       "repladdr: %s\n"
	       "\n",
	       read_string(ss, &kpatch->label),
	       str_pointer(ss, (void *const *)&kpatch->repladdr));
}

void show_ksplice_patches(struct supersect *kpatch_ss)
{
	printf("KSPLICE PATCHES:\n\n");
	const struct ksplice_patch *kpatch;
	for (kpatch = kpatch_ss->contents.data; (void *)kpatch <
	     kpatch_ss->contents.data + kpatch_ss->contents.size; kpatch++)
		show_ksplice_patch(kpatch_ss, kpatch);
	printf("\n");
}

void show_ksplice_export(struct supersect *ss, const struct ksplice_export *exp)
{
	printf("name: %s\n"
	       "newname: %s\n"
	       "\n",
	       read_string(ss, &exp->name), read_string(ss, &exp->new_name));
}

void show_ksplice_exports(struct supersect *export_ss)
{
	printf("KSPLICE EXPORTS:\n\n");
	const struct ksplice_export *exp;
	for (exp = export_ss->contents.data; (void *)exp <
	     export_ss->contents.data + export_ss->contents.size; exp++)
		show_ksplice_export(export_ss, exp);
	printf("\n");
}

void show_ksplice_system_map(struct supersect *ss,
			     const struct ksplice_system_map *smap)
{
	printf("%s %s\n",
	       read_string(ss, &smap->label),
	       str_ulong_vec(ss, &smap->candidates, &smap->nr_candidates));
}

void show_ksplice_system_maps(struct supersect *smap_ss)
{
	printf("KSPLICE SYSTEM.MAP:\n\n");
	const struct ksplice_system_map *smap;
	for (smap = smap_ss->contents.data;
	     (void *)smap < smap_ss->contents.data + smap_ss->contents.size;
	     smap++)
		show_ksplice_system_map(smap_ss, smap);
	printf("\n");
}

int main(int argc, char *argv[])
{
	bfd *ibfd;

	assert(argc >= 1);
	bfd_init();
	ibfd = bfd_openr(argv[1], NULL);
	assert(ibfd);

	char **matching;
	assert(bfd_check_format_matches(ibfd, bfd_object, &matching));

	struct superbfd *sbfd = fetch_superbfd(ibfd);

	asection *kreloc_init_sect =
	    bfd_get_section_by_name(ibfd, ".ksplice_init_relocs");
	if (kreloc_init_sect != NULL) {
		struct supersect *kreloc_init_ss =
		    fetch_supersect(sbfd, kreloc_init_sect);
		show_ksplice_relocs(kreloc_init_ss);
	} else {
		printf("No ksplice init relocations.\n\n");
	}

	asection *kreloc_sect = bfd_get_section_by_name(ibfd,
							".ksplice_relocs");
	if (kreloc_sect != NULL) {
		struct supersect *kreloc_ss =
		    fetch_supersect(sbfd, kreloc_sect);
		show_ksplice_relocs(kreloc_ss);
	} else {
		printf("No ksplice relocations.\n\n");
	}

	asection *ksect_sect = bfd_get_section_by_name(ibfd,
						       ".ksplice_sections");
	if (ksect_sect != NULL) {
		struct supersect *ksect_ss = fetch_supersect(sbfd, ksect_sect);
		show_ksplice_sections(ksect_ss);
	} else {
		printf("No ksplice sections.\n\n");
	}

	asection *kpatch_sect = bfd_get_section_by_name(ibfd,
							".ksplice_patches");
	if (kpatch_sect != NULL) {
		struct supersect *kpatch_ss =
		    fetch_supersect(sbfd, kpatch_sect);
		show_ksplice_patches(kpatch_ss);
	} else {
		printf("No ksplice patches.\n\n");
	}

	asection *export_sect = bfd_get_section_by_name(ibfd,
							".ksplice_exports");
	if (export_sect != NULL) {
		struct supersect *export_ss =
		    fetch_supersect(sbfd, export_sect);
		show_ksplice_exports(export_ss);
	} else {
		printf("No ksplice exports.\n\n");
	}

	asection *smap_sect = bfd_get_section_by_name(ibfd,
						      ".ksplice_system_map");
	if (smap_sect != NULL) {
		struct supersect *smap_ss = fetch_supersect(sbfd, smap_sect);
		show_ksplice_system_maps(smap_ss);
	} else {
		printf("No ksplice System.map.\n\n");
	}

	return 0;
}
