#include "allcommon.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jeffrey Brian Arnold <jbarnold@mit.edu>");

struct ksplice_reloc {
	char *sym_name;
	char *blank_sect_name;
	long blank_sect_addr;
	long blank_offset;
	long num_sym_addrs;
	long *sym_addrs;
	long num_sect_addrs;
	long *sect_addrs;
	long flags;
	long addend;
};

/* ksplice_reloc flags bits */
#define PCREL (1 << 0)
#define SAFE (1 << 1)

struct ksplice_patch {
	char *oldstr;
	char *replstr;
	long oldaddr;
	long repladdr;
	char *saved;
};

struct ksplice_size {
	char *name;
	long size;
	long thismod_addr;
	long num_sym_addrs;
	long *sym_addrs;
};

struct starts_with_next {
	struct starts_with_next *next;
};

struct reloc_nameval {
	struct reloc_nameval *next;	/* must be first */
	char *name;
	long val;
	enum { NOVAL, TEMP, VAL } status;
};

struct reloc_addrmap {
	struct reloc_addrmap *next;	/* must be first */
	long addr;
	long addend;
	int flags;
	struct reloc_nameval *nameval;
};

struct safety_record {
	struct safety_record *next;	/* must be first */
	long addr;
	int size;
	int care;
};

struct ansglob {
	long val;
	struct ansglob *next;
};

#define singular(glob) ((glob) && !((glob)->next))
#define failed_to_find(sym_name) \
		printk("ksplice: Failed to find symbol %s at %s:%d\n", \
		sym_name, __FILE__, __LINE__)

static inline void
print_abort(const char *str)
{
	printk("ksplice: Aborted. (%s)\n", str);
}

int process_ksplice_relocs(int caller_is_helper);
int process_reloc(struct ksplice_reloc *r);
void compute_address(char *sym_name, struct ansglob **globptr);
void kernel_lookup(const char *name_wlabel, struct ansglob **globptr);

#ifdef CONFIG_KALLSYMS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
long ksplice_kallsyms_expand_symbol(unsigned long off, char *result);
#endif
void this_module_lookup(const char *name, struct ansglob **globptr);
void other_module_lookup(const char *name_wlabel, struct ansglob **globptr);
void ksplice_mod_find_sym(struct module *m, const char *name,
			  struct ansglob **globptr);
#endif

void add2glob(struct ansglob **globptr, long val);
void release(struct ansglob **globptr);
struct reloc_nameval *find_nameval(char *name, int create);
struct reloc_addrmap *find_addrmap(long addr);
void set_temp_myst_relocs(int status_val);
void release_list(struct starts_with_next *p);

#define clear_list(head, type, member) \
	do {							\
		struct list_head *_pos, *_n;			\
		list_for_each_safe(_pos, _n, head) {		\
			list_del(_pos);				\
			kfree(list_entry(_pos, type, member));	\
		}						\
	} while (0)

#include "modcommon.auto.h"
