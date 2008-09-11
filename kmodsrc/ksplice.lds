SECTIONS {
  .ksplice_init_relocs : {
    ksplice_init_relocs = .;
    KEEP(*(.ksplice_init_relocs))
    ksplice_init_relocs_end = .;
  }
  .ksplice_system_map : {
    ksplice_system_map = .;
    KEEP(*(.ksplice_system_map))
    ksplice_system_map_end = .;
  }
}
