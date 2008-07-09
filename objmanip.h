struct wsect {
	char *name;
	struct wsect *next;
};

struct specsect {
	char *sectname;
	unsigned char odd_relocs;
	char *odd_relocname;
	int entry_size;
};

struct ksplice_reloc {
	char *sym_name;
	long blank_addr;
	long blank_offset;
	long num_sym_addrs;
	long *sym_addrs;
	int pcrel;
	long addend;
	long size;
};

struct ksplice_size {
	char *name;
	long size;
	long thismod_addr;
	long num_sym_addrs;
	long *sym_addrs;
};

struct ksplice_patch {
	char *oldstr;
	char *replstr;
	long oldaddr;
	long repladdr;
	char *saved;
};

int main(int argc, char **argv);
void rm_some_relocs(bfd *ibfd, asection *isection);
void write_ksplice_reloc(bfd *ibfd, asection *isection, arelent *orig_reloc,
			 struct supersect *ss);
bfd_vma blot_section(bfd *abfd, asection *sect, int offset,
		     reloc_howto_type *howto);
void write_ksplice_size(bfd *ibfd, asymbol **symp);
void write_ksplice_patch(bfd *ibfd, char *symname);
void rm_from_special(bfd *ibfd, struct specsect *s);
void mark_wanted_if_referenced(bfd *abfd, asection *sect, void *ignored);
void check_for_ref_to_section(bfd *abfd, asection *looking_at,
			      void *looking_for);
static bfd_boolean copy_object(bfd *ibfd, bfd *obfd);
static void setup_section(bfd *ibfd, asection *isection, void *obfdarg);
static void setup_new_section(bfd *obfd, struct supersect *ss);
static void copy_section(bfd *ibfd, asection *isection, void *obfdarg);
static void write_new_section(bfd *obfd, struct supersect *ss);
static void mark_symbols_used_in_relocations(bfd *ibfd, asection *isection,
					     void *symbolsarg);
static void ss_mark_symbols_used_in_relocations(struct supersect *ss);
static void filter_symbols(bfd *abfd, bfd *obfd, struct asymbolp_vec *osyms,
			   struct asymbolp_vec *isyms);
int exists_sym_with_name(struct asymbolp_vec *syms, const char *desired);
int match_varargs(const char *str);
int want_section(const char *name, char **newname);
struct specsect *is_special(const char *name);
