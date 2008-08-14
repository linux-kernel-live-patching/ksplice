typedef void (*section_fn) (asection *);

void foreach_nonmatching(bfd *oldbfd, bfd *newbfd, section_fn s_fn);
int reloc_cmp(bfd *oldbfd, asection *oldp, bfd *newbfd, asection *newp);
static void print_newbfd_section_name(asection *sect);
static void print_newbfd_entry_symbols(asection *sect);
