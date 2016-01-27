all: fastbin_dup fastbin_dup_into_stack unsafe_unlink house_of_spirit malloc_playground

fastbin_dup: fastbin_dup.c
	gcc fastbin_dup.c -o fastbin_dup

fastbin_dup_into_stack: fastbin_dup_into_stack.c
	gcc fastbin_dup_into_stack.c -o fastbin_dup_into_stack

unsafe_unlink: unsafe_unlink.c
	gcc unsafe_unlink.c -o unsafe_unlink

house_of_spirit: house_of_spirit.c
	gcc house_of_spirit.c -o house_of_spirit

malloc_playground: malloc_playground.c
	gcc -std=c99 malloc_playground.c -o malloc_playground

clean:
	rm -f fastbin_dup fastbin_dup_into_stack unsafe_unlink house_of_spirit malloc_playground
