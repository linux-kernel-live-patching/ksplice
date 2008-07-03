#include <bfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DIE do { fprintf(stderr, "ksplice: died at %s:%d\n", __FILE__, __LINE__); abort(); } while(0)
#define assert(x) do { if(!(x)) DIE; } while(0)
#define align(x, n) ((((x)+(n)-1)/(n))*(n))

#define DECLARE_VEC_TYPE(elt_t, vectype)	\
	struct vectype {			\
		elt_t *data;			\
		size_t size;			\
		size_t mem_size;		\
	}

/* void vec_init(struct vectype *vec); */
#define vec_init(vec) *(vec) = (typeof(*(vec))) { NULL, 0, 0 }

/* void vec_move(struct vectype *dstvec, struct vectype *srcvec); */
#define vec_move(dstvec, srcvec) do {			\
		typeof(srcvec) _srcvec = (srcvec);	\
		*(dstvec) = *(_srcvec);			\
		vec_init(_srcvec);			\
	} while (0)

/* void vec_free(struct vectype *vec); */
#define vec_free(vec) do {			\
		typeof(vec) _vec1 = (vec);	\
		free(_vec1->data);		\
		vec_init(_vec1);		\
	} while (0)

void vec_do_reserve(void **data, size_t *mem_size, size_t newsize);

/* void vec_reserve(struct vectype *vec, size_t new_mem_size); */
#define vec_reserve(vec, new_mem_size) do {				\
		typeof(vec) _vec2 = (vec);				\
		vec_do_reserve((void **)&_vec2->data, &_vec2->mem_size,	\
			       (new_mem_size));				\
	} while (0)

/* void vec_resize(struct vectype *vec, size_t new_size); */
#define vec_resize(vec, new_size) do {					\
		typeof(vec) _vec3 = (vec);				\
		_vec3->size = (new_size);				\
		vec_reserve(_vec3, _vec3->size * sizeof(*_vec3->data));	\
	} while (0)

/* elt_t *vec_grow(struct vectype *vec, size_t n); */
#define vec_grow(vec, n) ({				\
		typeof(vec) _vec4 = (vec);		\
		size_t _n = (n);			\
		vec_resize(_vec4, _vec4->size + _n);	\
		_vec4->data + (_vec4->size - _n);	\
	})

#ifndef bfd_get_section_size
#define bfd_get_section_size(x) ((x)->_cooked_size)
#endif

struct supersect {
	bfd *parent;
	char *name;
	void *contents;
	int contents_size;
	int alignment;
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
