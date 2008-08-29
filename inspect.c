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
	assert(asprintf(&str, "%s (%s %s)",
			read_string(ss, &ksymbol->label),
			read_string(ss, &ksymbol->name),
			str_ulong_vec(ss, &ksymbol->candidates,
				      &ksymbol->nr_candidates)));
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

void show_ksplice_size_flags(const struct ksplice_size *ksize)
{
	printf("flags:");
	if (ksize->flags & KSPLICE_SIZE_DELETED)
		printf(" deleted");
	if (ksize->flags & KSPLICE_SIZE_RODATA)
		printf(" rodata");
	if (ksize->flags & KSPLICE_SIZE_TEXT)
		printf(" text");
	if (ksize->flags & KSPLICE_SIZE_DATA)
		printf(" data");
	printf("\n");
}

void show_ksplice_size(struct supersect *ss, const struct ksplice_size *ksize)
{
	printf("symbol: %s\n"
	       "thismod_addr: %s  size: %lx extended_size: %lx\n",
	       str_ksplice_symbolp(ss, &ksize->symbol),
	       str_pointer(ss, (void *const *)&ksize->thismod_addr),
	       read_num(ss, &ksize->size), read_num(ss, &ksize->extended_size));
	show_ksplice_size_flags(ksize);
	printf("\n");
}

void show_ksplice_sizes(struct supersect *ksize_ss)
{
	printf("KSPLICE SIZES:\n\n");
	struct ksplice_size *ksize;
	for (ksize = ksize_ss->contents.data; (void *)ksize <
	     ksize_ss->contents.data + ksize_ss->contents.size; ksize++)
		show_ksplice_size(ksize_ss, ksize);
	printf("\n");
}

void show_ksplice_patch(struct supersect *ss,
			const struct ksplice_patch *kpatch)
{
	printf("symbol: %s\n"
	       "repladdr: %s\n"
	       "\n",
	       str_ksplice_symbolp(ss, &kpatch->symbol),
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

void show_ksplice_export(struct supersect *ss,
			 const struct ksplice_export *export)
{
	printf("name: %s\n"
	       "newname: %s\n"
	       "type: %s\n"
	       "\n",
	       read_string(ss, &export->name),
	       read_string(ss, &export->new_name),
	       read_string(ss, &export->type));
}

void show_ksplice_exports(struct supersect *export_ss)
{
	printf("KSPLICE EXPORTS:\n\n");
	const struct ksplice_export *export;
	for (export = export_ss->contents.data; (void *)export <
	     export_ss->contents.data + export_ss->contents.size; export++)
		show_ksplice_export(export_ss, export);
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

	asection *ksize_sect = bfd_get_section_by_name(ibfd, ".ksplice_sizes");
	if (ksize_sect != NULL) {
		struct supersect *ksize_ss = fetch_supersect(sbfd, ksize_sect);
		show_ksplice_sizes(ksize_ss);
	} else {
		printf("No ksplice sizes.\n\n");
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

	return 0;
}
