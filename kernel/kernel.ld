ENTRY(_start)

SECTIONS {
    . = 0xffffffff80000000;  /* 内核高半区虚拟地址起始，参考 Linux x86_64 */
    /* 物理加载地址依然为 1MB */
    . += SIZEOF_HEADERS;
    
    .text : AT(0x100000 + SIZEOF_HEADERS) {
        *(.text._start)  /* 确保 _start 在最前面 */
        *(.text .text.*)
    }
    
    .rodata : {
        *(.rodata .rodata.*)
    }
    
    .data : {
        *(.data .data.*)
    }
    
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }
    
    /DISCARD/ : {
        *(.eh_frame)
        *(.note.*)
    }
}
