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

bfd_vma read_reloc(struct supersect *ss, const void *addr, size_t size,
		   asymbol **symp)
{
	arelent **relocp;
	bfd_vma val = bfd_get(size * 8, ss->parent->abfd, addr);
	bfd_vma address = addr_offset(ss, addr);
	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		arelent *reloc = *relocp;
		if (reloc->address == address) {
			if (symp != NULL)
				*symp = *reloc->sym_ptr_ptr;
			else if (*reloc->sym_ptr_ptr !=
				 bfd_abs_section_ptr->symbol)
				fprintf(stderr, "warning: unexpected "
					"non-absolute relocation at %s+%lx\n",
					ss->name, (unsigned long)address);
			return get_reloc_offset(ss, reloc, 0);
		}
	}
	if (symp != NULL)
		*symp = *bfd_abs_section_ptr->symbol_ptr_ptr;
	return val;
}

#define read_num(ss, addr) ((typeof(*(addr))) \
			    read_reloc(ss, addr, sizeof(*(addr)), NULL))

char *str_pointer(struct supersect *ss, void *const *addr)
{
	asymbol *sym;
	bfd_vma offset = read_reloc(ss, addr, sizeof(*addr), &sym);
	char *str;
	assert(asprintf(&str, "%s+%lx", sym->name, (unsigned long)offset) >= 0);
	return str;
}

const void *read_pointer(struct supersect *ss, void *const *addr,
			 struct supersect **data_ssp)
{
	asymbol *sym;
	bfd_vma offset = read_reloc(ss, addr, sizeof(*addr), &sym);
	struct supersect *data_ss = fetch_supersect(ss->parent, sym->section);
	if (bfd_is_abs_section(sym->section) && sym->value + offset == 0)
		return NULL;
	if (bfd_is_const_section(sym->section)) {
		fprintf(stderr, "warning: unexpected relocation to const "
			"section at %s+%lx\n", data_ss->name,
			(unsigned long)addr_offset(data_ss, addr));
		return NULL;
	}
	if (data_ssp != NULL)
		*data_ssp = data_ss;
	return data_ss->contents.data + sym->value + offset;
}

const char *read_string(struct supersect *ss, const char *const *addr)
{
	return read_pointer(ss, (void *const *)addr, NULL);
}

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

void show_ksplice_reloc(struct supersect *ss,
			const struct ksplice_reloc *kreloc)
{
	printf("blank_addr: %s  blank_offset: %lx\n"
	       "sym_name: %s\n"
	       "addend: %lx\n"
	       "pcrel: %x  size: %x  dst_mask: %lx  rightshift: %x\n"
	       "sym_addrs: %s\n"
	       "\n",
	       str_pointer(ss, (void *const *)&kreloc->blank_addr),
	       read_num(ss, &kreloc->blank_offset),
	       read_string(ss, &kreloc->sym_name),
	       read_num(ss, &kreloc->addend),
	       read_num(ss, &kreloc->pcrel),
	       read_num(ss, &kreloc->size),
	       read_num(ss, &kreloc->dst_mask),
	       read_num(ss, &kreloc->rightshift),
	       str_ulong_vec(ss, &kreloc->sym_addrs, &kreloc->num_sym_addrs));
}

void show_ksplice_relocs(struct supersect *kreloc_ss)
{
	printf("KSPLICE RELOCATIONS:\n\n");
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
	printf("\n");
}

void show_ksplice_size(struct supersect *ss, const struct ksplice_size *ksize)
{
	printf("name: %s\n"
	       "thismod_addr: %s  size: %lx\n"
	       "sym_addrs: %s\n",
	       read_string(ss, &ksize->name),
	       str_pointer(ss, (void *const *)&ksize->thismod_addr),
	       read_num(ss, &ksize->size),
	       str_ulong_vec(ss, &ksize->sym_addrs, &ksize->num_sym_addrs));
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
	printf("oldstr: %s\n"
	       "repladdr: %s\n"
	       "\n",
	       read_string(ss, &kpatch->oldstr),
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
