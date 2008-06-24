#include <bfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#define starts_with(str, prefix)			\
	(strncmp(str, prefix, strlen(prefix)) == 0)
#define ends_with(str, suffix)						\
	(strlen(str) >= strlen(suffix) &&				\
	 strcmp(&str[strlen(str) - strlen(suffix)], suffix) == 0)

int label_offset(const char *sym_name);
const char *only_label(const char *sym_name);
const char *dup_wolabel(const char *sym_name);
