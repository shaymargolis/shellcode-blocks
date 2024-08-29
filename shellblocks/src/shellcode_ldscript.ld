SECTIONS
{
    .text : 
    {
        *(.text*)
    }

    .rodata : 
    {
        *(.rodata*)
    }

    /DISCARD/ : 
    {
        *(*)
    }
}
