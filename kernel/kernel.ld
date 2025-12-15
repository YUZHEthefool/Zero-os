ENTRY(_start)

SECTIONS {
    /* 虚拟地址从 0xffffffff80100000 开始，映射到物理地址 0x100000 */
    . = 0xffffffff80100000;

    kernel_start = .;

    .text : AT(0x100000) {
        text_start = .;
        *(.text._start)  /* 确保 _start 在最前面 */
        *(.text .text.*)
        . = ALIGN(4096);  /* 页对齐 */
        text_end = .;
    }

    .rodata : AT(0x100000 + (ADDR(.rodata) - 0xffffffff80100000)) {
        rodata_start = .;
        *(.rodata .rodata.*)
        . = ALIGN(4096);  /* 页对齐 */
        rodata_end = .;
    }

    .data : AT(0x100000 + (ADDR(.data) - 0xffffffff80100000)) {
        data_start = .;
        *(.data .data.*)
        . = ALIGN(4096);  /* 页对齐 */
        data_end = .;
    }

    .bss : AT(0x100000 + (ADDR(.bss) - 0xffffffff80100000)) {
        bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4096);  /* 页对齐 */
        bss_end = .;
    }

    kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.note.*)
    }
}
