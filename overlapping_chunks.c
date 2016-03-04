/*

 A simple tale of overlapping chunk.
 This technique is taken from 
 http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc , char* argv[]){


	unsigned int p1,p2,p3,p4;

	printf("\nThis is a simple chunks overlapping problem\n\n");
	printf("Let's start to allocate 3 chunks on the heap\n");
	
	p1 = (unsigned int)malloc(100);
	p2 = (unsigned int)malloc(100);
	p3 = (unsigned int)malloc(80);

	printf("The 3 chunks have been allocated here:\np1=%08x\np2=%08x\np3=%08x\n",p1,p2,p3);

	printf("\nNow let's free the chunk p2\n", p2);
	free((void*)p2);
	printf("The chunk p2 is now in the unsorted bin ready to serve possible new malloc() of its size\n");

	printf("Now let's simulate an overflow that can overwrite the size of the chunk freed p2\n");
	printf("We are going to set the next chunk size to \\xf8 = n248\n"); // we have choose this value since it has the last 3 bits at 0 
 	
	memcpy((void*)p1+100,"\xf8",1); // this size injected is chunk_data_size + chunk_header_size (0x8)


	printf("Now let's allocate another chunk with a size equal to the data size of the chunk p2 injected size\n");
	printf("This malloc will be served from the previously freed chunk that is parked in the unsorted bin which size has been modified by us\n");
	p4 = (unsigned int)malloc(248-8);

	printf("p4 has been allocated here %08x and finish here %08x\n",p4,p4+248-8);
	printf("p3 starts here %08x and finish here %08x\n", p3,p3+80);
	printf("p4 should overlap with p3, in this case p4 includes all p3\n");


	printf("\nNow everything copied inside chunk p4 can overwrites data on chunk p3\n");
	printf("But also data written on chunk p3 can overwrite data stored on the p4 chunk.\n\n");

	
}


