#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	printf("This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.\n");
	printf("glibc uses a first-fit algorithm to select a free chunk.\n");
	printf("If a chunk is free and large enough, malloc will select this chunk.\n");
	printf("This can be exploited in a use-after-free situation.\n");

	printf("Allocating 2 buffers. They can be large, don't have to be fastbin.\n");
	char* a = malloc(512);
	char* b = malloc(256);
	char* c;

	printf("1st malloc(512): %p\n", a);
	printf("2nd malloc(256): %p\n", b);
	printf("we could continue mallocing here...\n");
	printf("now let's put a string at a that we can read later \"this is A!\"\n");
	strcpy(a, "this is A!");
	printf("first allocation %p points to %s\n", a, a);

	printf("Freeing the first one...\n");
	free(a);

	printf("We don't need to free anything again. As long as we allocate less than 512, it will end up at %p\n", a);

	printf("So, let's allocate 500 bytes\n");
	c = malloc(500);
	printf("3rd malloc(500): %p\n", c);
	printf("And put a different string here, \"this is C!\"\n");
	strcpy(c, "this is C!");
	printf("3rd allocation %p points to %s\n", c, c);
	printf("first allocation %p points to %s\n", a, a);
	printf("If we reuse the first allocation, it now holds the data from the third allocation.");
}
