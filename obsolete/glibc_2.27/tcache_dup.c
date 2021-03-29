#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	printf("This file demonstrates a simple double-free attack with tcache.\n");

	printf("Allocating buffer.\n");
	int *a = malloc(8);

	printf("malloc(8): %p\n", a);
	printf("Freeing twice...\n");
	free(a);
	free(a);

	printf("Now the free list has [ %p, %p ].\n", a, a);
	void *b = malloc(8);
	void *c = malloc(8);
	printf("Next allocated buffers will be same: [ %p, %p ].\n", b, c);

	assert((long)b == (long)c);
	return 0;
}
