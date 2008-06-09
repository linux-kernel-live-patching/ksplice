#include "kmodsrc/allcommon.h"
#include <bfd.h>
#include <stdio.h>

#define DIE do { printf("ksplice: died at line %d of %s\n", __LINE__, __FILE__); fflush(0); exit(1); } while(0)
#define assert(x) do { if(!(x)) DIE; } while(0)
#define align(x, n) ((((x)+(n)-1)/(n))*(n))

#ifndef bfd_get_section_size
#define bfd_get_section_size(x) ((x)->_cooked_size)
#endif

struct supersect {
	bfd *parent;
	char *name;
	void *contents;
	int contents_size;
	arelent **relocs;
	int num_relocs;
	struct supersect *next;
};

long get_syms(bfd *abfd, asymbol ***syms_ptr);
struct supersect *fetch_supersect(bfd *abfd, asection *sect, asymbol **sympp);
