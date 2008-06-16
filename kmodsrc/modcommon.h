#include "allcommon.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jeffrey Brian Arnold <jbarnold@mit.edu>");

enum ksplice_state_enum {
	KSPLICE_PREPARING, KSPLICE_APPLIED, KSPLICE_REVERSED
};

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
	long size;
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

struct module_pack {
	const char *name;
	int helper;
	long map_printk;
	enum ksplice_state_enum state;
	struct ksplice_reloc *primary_relocs;
	struct ksplice_size *primary_sizes;
	struct ksplice_reloc *helper_relocs;
	struct ksplice_size *helper_sizes;
	struct ksplice_patch *patches;
	struct list_head *reloc_addrmaps;
	struct list_head *reloc_namevals;
	struct list_head *safety_records;
	int (*activate_primary)(struct module_pack *pack);
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
	int size;
};

struct safety_record {
	struct list_head list;
	long addr;
	int size;
	int care;
};

struct candidate_val {
	struct list_head list;
	long val;
};

#define singular(list) (!list_empty(list) && (list)->next->next == (list))
#define failed_to_find(sym_name) \
		printk("ksplice: Failed to find symbol %s at %s:%d\n", \
		sym_name, __FILE__, __LINE__)

static inline void print_abort(const char *str)
{
	printk("ksplice: Aborted. (%s)\n", str);
}

int process_ksplice_relocs(struct module_pack *pack,
			   struct ksplice_reloc *relocs);
int process_reloc(struct module_pack *pack, struct ksplice_reloc *r);
void compute_address(struct module_pack *pack, char *sym_name,
		     struct list_head *vals);
void kernel_lookup(const char *name_wlabel, struct list_head *vals);

#ifdef CONFIG_KALLSYMS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
long ksplice_kallsyms_expand_symbol(unsigned long off, char *result);
#endif
void other_module_lookup(const char *name_wlabel, struct list_head *vals,
			 const char *ksplice_name);
void ksplice_mod_find_sym(struct module *m, const char *name,
			  struct list_head *vals);
#endif

void add_candidate_val(struct list_head *vals, long val);
void release_vals(struct list_head *vals);
struct reloc_nameval *find_nameval(struct module_pack *pack, char *name,
				   int create);
struct reloc_addrmap *find_addrmap(struct module_pack *pack, long addr);
void set_temp_myst_relocs(struct module_pack *pack, int status_val);

#define clear_list(head, type, member) \
	do {							\
		struct list_head *_pos, *_n;			\
		list_for_each_safe(_pos, _n, head) {		\
			list_del(_pos);				\
			kfree(list_entry(_pos, type, member));	\
		}						\
	} while (0)

#define _STR(x) #x
#define STR(x) _STR(x)

#define _PASTE(x,y) x##y
#define PASTE(x,y) _PASTE(x,y)
#define KSPLICE_UNIQ(s) PASTE(s##_,KSPLICE_ID)

extern struct module_pack KSPLICE_UNIQ(pack);
