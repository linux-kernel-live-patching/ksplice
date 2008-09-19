struct table_section {
	const char *sect;
	int entry_size;
	int entry_align;
	int addr_offset;
	const char *other_sect;
	int other_offset;
};
