SECTIONS {
  .ksplice_init_relocs : {
    ksplice_init_relocs = .;
    KEEP(*(.ksplice_init_relocs))
    ksplice_init_relocs_end = .;
  }
}
