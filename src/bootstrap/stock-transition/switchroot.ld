ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); }
SECTIONS { . = 0x10000; .text : { *(.text .text.*) } :text }
