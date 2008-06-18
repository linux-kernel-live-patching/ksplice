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

int main(int argc, char **argv);
void rm_some_relocs(bfd *ibfd, asection *isection);
void print_reloc(bfd *ibfd, asection *isection, arelent *orig_reloc,
		 struct supersect *ss);
int blot_section(bfd *abfd, asection *sect, int offset, int size);
const char *canonical_sym(const char *sect_wlabel);
void rm_from_special(bfd *ibfd, struct specsect *s);
void mark_wanted_if_referenced(bfd *abfd, asection *sect, void *ignored);
void check_for_ref_to_section(bfd *abfd, asection *looking_at,
			      void *looking_for);
static bfd_boolean copy_object(bfd *ibfd, bfd *obfd);
static void setup_section(bfd *ibfd, asection *isection, void *obfdarg);
static void copy_section(bfd *ibfd, asection *isection, void *obfdarg);
static void mark_symbols_used_in_relocations(bfd *ibfd, asection *isection,
					     void *symbolsarg);
static unsigned int filter_symbols(bfd *abfd, bfd *obfd, asymbol **osyms,
				   asymbol **isyms, long symcount);
int exists_sym_with_name(asymbol **syms, int symcount, const char *desired);
int match_varargs(const char *str);
int want_section(const char *name, char **newname);
struct specsect *is_special(const char *name);
