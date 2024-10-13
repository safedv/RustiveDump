ENTRY(_start);

SECTIONS
{
    . = 0x0000;

    .text ALIGN(16) : 
    {
        *(.text.prologue)  
        *(.text*)          
        *(.rodata*)        
        *(.rdata*)
        *(.global*)        
    }

    /DISCARD/ :
    {
        *(.interp)
        *(.comment)        
        *(.debug_frame)    
        *(.bss)            
        *(.pdata)          
        *(.xdata)          
    }
}
