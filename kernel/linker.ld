/* μKernel Linker Script for x86_64 */

ENTRY(_start)

/* Higher-half kernel: mapped at -2GB (0xFFFFFFFF80000000) */
KERNEL_VIRT_BASE = 0xFFFFFFFF80000000;
KERNEL_PHYS_BASE = 0x100000;  /* Load at 1MB physical */

PHDRS {
    text    PT_LOAD FLAGS(5);   /* r-x */
    rodata  PT_LOAD FLAGS(4);   /* r-- */
    data    PT_LOAD FLAGS(6);   /* rw- */
}

SECTIONS {
    . = KERNEL_VIRT_BASE;

    /* Text section */
    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE) {
        PROVIDE(__text_start = .);
        *(.text.boot)           /* Boot code first */
        *(.text .text.*)
        PROVIDE(__text_end = .);
    } :text

    /* Read-only data */
    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE) {
        PROVIDE(__rodata_start = .);
        *(.rodata .rodata.*)
        PROVIDE(__rodata_end = .);
    } :rodata

    /* Initialized data */
    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE) {
        PROVIDE(__data_start = .);
        *(.data .data.*)
        PROVIDE(__data_end = .);
    } :data

    /* BSS (uninitialized data) */
    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE) {
        PROVIDE(__bss_start = .);
        *(.bss .bss.*)
        *(COMMON)
        PROVIDE(__bss_end = .);
    } :data

    /* Kernel stack */
    . = ALIGN(4K);
    PROVIDE(__stack_bottom = .);
    . += 64K;  /* 64KB kernel stack */
    PROVIDE(__stack_top = .);

    /* Kernel heap region (managed by allocator) */
    . = ALIGN(4K);
    PROVIDE(__heap_start = .);

    PROVIDE(__kernel_end = .);

    /* Discard debug and other sections */
    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
