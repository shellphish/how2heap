#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>


struct malloc_chunk {

  size_t      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  size_t      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

/* The corresponding word size.  */
#define SIZE_SZ (sizeof (size_t))

#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
			  ? __alignof__ (long double) : 2 * SIZE_SZ)

/* The corresponding bit mask value.  */
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)

/* The smallest possible chunk */
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))

/* The smallest size we can malloc is an aligned minimal chunk */
#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)

/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

int main()
{
    unsigned long long req;
    unsigned long long tidx;
	fprintf(stderr, "This file doesn't demonstrate an attack, but calculates the tcache idx for a given chunk size.\n");
	fprintf(stderr, "The basic formula is as follows:\n");
    fprintf(stderr, "\tIDX = (CHUNKSIZE - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT\n");
    fprintf(stderr, "\tOn a 64 bit system the current values are:\n");
    fprintf(stderr, "\t\tMINSIZE: 0x%lx\n", MINSIZE);
    fprintf(stderr, "\t\tMALLOC_ALIGNMENT: 0x%lx\n", MALLOC_ALIGNMENT);
    fprintf(stderr, "\tSo we get the following equation:\n");
    fprintf(stderr, "\tIDX = (CHUNKSIZE - 0x%lx) / 0x%lx\n\n", MINSIZE-MALLOC_ALIGNMENT+1, MALLOC_ALIGNMENT);
    fprintf(stderr, "BUT be AWARE that CHUNKSIZE is not the x in malloc(x)\n");
    fprintf(stderr, "It is calculated as follows:\n");
    fprintf(stderr, "\tIF x + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE(0x%lx) CHUNKSIZE = MINSIZE (0x%lx)\n", MINSIZE, MINSIZE);
    fprintf(stderr, "\tELSE: CHUNKSIZE = (x + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK) \n");
    fprintf(stderr, "\t=> CHUNKSIZE = (x + 0x%lx + 0x%lx) & ~0x%lx\n\n\n", SIZE_SZ, MALLOC_ALIGN_MASK, MALLOC_ALIGN_MASK);
    while(1) {
        fprintf(stderr, "[CTRL-C to exit] Please enter a size x (malloc(x)) in hex (e.g. 0x10): ");
        scanf("%llx", &req);
        tidx = usize2tidx(req);
        if (tidx > 63) {
            fprintf(stderr, "\nWARNING: NOT IN TCACHE RANGE!\n");
        }
        fprintf(stderr, "\nTCache Idx: %llu\n", tidx);
    }
    return 0;
}
