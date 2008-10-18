#define PTR_KEEP_SQUASH(section) \
  .##section : { \
    section = .; \
    KEEP(*(.##section##*)) \
    section##_end = .; \
  }
#define PTR_KEEP(section) \
  .##section : { \
    section = .; \
    KEEP(*(.##section)) \
    section##_end = .; \
  }
SECTIONS {
  .text : { *(.text .text.* .exit.text) }
  PTR_KEEP_SQUASH(ksplice_relocs)
  PTR_KEEP_SQUASH(ksplice_sections)
  PTR_KEEP_SQUASH(ksplice_patches)
  PTR_KEEP(ksplice_symbols)
  PTR_KEEP(ksplice_exports)
  PTR_KEEP(ksplice_system_map)
  PTR_KEEP(parainstructions)
}
