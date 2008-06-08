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

struct reloc_nameval {
	struct list_head list;
	char *name;
	long val;
	enum { NOVAL, TEMP, VAL } status;
};

struct reloc_addrmap {
	struct list_head list;
	long addr;
	long addend;
	int flags;
	struct reloc_nameval *nameval;
};

struct safety_record {
	struct list_head list;
	long addr;
	int size;
	int care;
};

enum ksplice_state_enum {
	KSPLICE_PREPARING, KSPLICE_APPLIED, KSPLICE_REVERSED
};

struct ansglob {
	struct list_head list;
	long val;
};

#define singular(list) (!list_empty(list) && (list)->next->next == (list))
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
void compute_address(char *sym_name, struct list_head *globptr);
void kernel_lookup(const char *name_wlabel, struct list_head *globptr);

#ifdef CONFIG_KALLSYMS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
long ksplice_kallsyms_expand_symbol(unsigned long off, char *result);
#endif
void this_module_lookup(const char *name, struct list_head *globptr);
void other_module_lookup(const char *name_wlabel, struct list_head *globptr);
void ksplice_mod_find_sym(struct module *m, const char *name,
			  struct list_head *globptr);
#endif

void add2glob(struct list_head *globptr, long val);
void release(struct list_head *globptr);
struct reloc_nameval *find_nameval(char *name, int create);
struct reloc_addrmap *find_addrmap(long addr);
void set_temp_myst_relocs(int status_val);

#define clear_list(head, type, member) \
	do {							\
		struct list_head *_pos, *_n;			\
		list_for_each_safe(_pos, _n, head) {		\
			list_del(_pos);				\
			kfree(list_entry(_pos, type, member));	\
		}						\
	} while (0)

#include "modcommon.auto.h"

#define _STR(x) #x
#define STR(x) _STR(x)
#define ksplice_name "ksplice_" STR(KSPLICE_ID)

#define _PASTE(x,y) x##y
#define PASTE(x,y) _PASTE(x,y)
#define KSPLICE_UNIQ(s) PASTE(s##_,KSPLICE_ID)

#define reloc_addrmaps KSPLICE_UNIQ(reloc_addrmaps)
#define reloc_namevals KSPLICE_UNIQ(reloc_namevals)
#define safety_records KSPLICE_UNIQ(safety_records)
#define ksplice_state KSPLICE_UNIQ(ksplice_state)
#define ksplice_do_primary KSPLICE_UNIQ(ksplice_do_primary)

extern struct list_head reloc_addrmaps;
extern struct list_head reloc_namevals;
extern struct list_head safety_records;
extern enum ksplice_state_enum ksplice_state;
int ksplice_do_primary(void);
