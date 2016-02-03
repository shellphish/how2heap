# Educational Heap Exploitation

This repo is for learning various heap exploitation techniques.
We came up with the idea during a hack meeting, and have implemented the following techniques:

| File | Technique | Applicable CTF Challenges |
|------|-----------|---------------------------|
| [fastbin_dup.c](fastbin_dup.c) | Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist. | |
| [fastbin_dup_into_stack.c](fastbin_dup_into_stack.c) | Tricking malloc into returning a nearly-arbitrary pointer by abusing the fastbin freelist. | [9447-search-engine](https://github.com/ctfs/write-ups-2015/tree/master/9447-ctf-2015/exploitation/search-engine) |
| [unsafe_unlink.c](unsafe_unlink.c) | Exploiting free on a corrupted chunk to get arbitrary write. | [HITCON CTF 2014-stkof](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/) |
| [house_of_spirit.c](house_of_spirit.c) | Frees a fake fastbin chunk to get malloc to return a nearly-arbitrary pointer. | [hack.lu CTF 2014-OREO](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/oreo) |
| [poison_null_byte.c](poison_null_byte.c) | Exploiting a single null byte overflow. | [PlaidCTF 2015-plaiddb](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/pwnable/plaiddb) |


Have a good example?
Add it here!
Try to inline the whole technique in a single `.c` -- it's a lot easier to learn that way.

# Malloc Playground

The `malloc_playground.c` file given is the source for a program that prompts the user for commands to allocate and free memory interactively.

# Other resources

Some good heap exploitation resources are:

- Malloc Des-Maleficarum (http://phrack.org/issues/66/10.html) - some malloc exploitation techniques
- Understanding the heap by breaking it (https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf) - explains heap implementation and a couple exploits
- Glibc Adventures: The Forgotten Chunk (http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf) - advanced heap exploitation

### Hardening
There are a couple of "hardening" measures embedded in glibc, like `export MALLOC_CHECK_=1` (enables some checks), `export MALLOC_PERTURB_=1` (data is overwritten), `export MALLOC_MMAP_THRESHOLD_=1` (always use mmap()), ...

More info: [mcheck()](http://www.gnu.org/software/libc/manual/html_node/Heap-Consistency-Checking.html), [mallopt()](http://www.gnu.org/software/libc/manual/html_node/Malloc-Tunable-Parameters.html).

There's also some tracing support as [mtrace()](http://manpages.ubuntu.com/mtrace), [malloc_stats()](http://manpages.ubuntu.com/malloc_stats), [malloc_info()](http://manpages.ubuntu.com/malloc_info), [memusage](http://manpages.ubuntu.com/memusage), and in other functions in this family.
