/* Zero-OS User-Space Linker Script
 *
 * Places user programs at USER_BASE (0x400000) with proper section layout.
 * Compatible with kernel's ELF loader requirements.
 */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

/* User address space starts at 4MB (0x400000) */
USER_BASE = 0x400000;

/* User stack is at the top of user address space */
USER_STACK_TOP = 0x7FFFFFFFE000;

PHDRS
{
    text PT_LOAD FLAGS(5);    /* R-X */
    rodata PT_LOAD FLAGS(4);  /* R-- */
    data PT_LOAD FLAGS(6);    /* RW- */
}

SECTIONS
{
    . = USER_BASE;

    /* Code section (read + execute) */
    .text : ALIGN(4K)
    {
        *(.text .text.*)
    } :text

    /* Read-only data section (read only) */
    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
    } :rodata

    /* Data section (read + write) */
    .data : ALIGN(4K)
    {
        *(.data .data.*)
    } :data

    /* BSS section (read + write, zero-initialized) */
    .bss : ALIGN(4K)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    /* Discard unnecessary sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.dynamic)
        *(.dynsym)
        *(.dynstr)
        *(.gnu.hash)
        *(.hash)
        *(.interp)
    }
}
