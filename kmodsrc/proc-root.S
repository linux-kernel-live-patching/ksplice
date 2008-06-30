/* proc_root is not defined since 2.6.25; use NULL instead. */
.globl proc_root
.weak proc_root
.equ proc_root, 0
