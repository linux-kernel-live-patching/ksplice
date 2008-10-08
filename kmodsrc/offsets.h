struct table_section {
	const char *sect;
	int entry_size;
	int entry_align;
	int has_addr;
	int addr_offset;
	const char *other_sect;
	int other_offset;
};

struct ksplice_config {
	int ignore_devinit;
	int ignore_cpuinit;
	int ignore_meminit;
};
