# Educational Heap Exploitation

This repo is for learning various heap exploitation techniques.
We came up with the idea during a hack meeting, and have implemented the following techniques:

| File | Technique | Applicable CTF Challenges |
|------|-----------|---------------------------|
| [fastbin_dup.c](fastbin_dup.c) | Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist. | |
| [fastbin_dup_into_stack.c](fastbin_dup_into_stack.c) | Tricking malloc into returning a nearly-arbitrary pointer by abusing the fastbin freelist. | [9447-search-engine](https://github.com/ctfs/write-ups-2015/tree/master/9447-ctf-2015/exploitation/search-engine) |

Have a good example?
Add it here!
Try to inline the whole technique in a single `.c` -- it's a lot easier to learn that way.

## Other resources

Some good heap exploitation resources are:

- Malloc Des-Maleficarum (http://phrack.org/issues/66/10.html) - some malloc exploitation techniques
- Understanding the heap by breaking it (https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf) - explains heap implementation and a couple exploits

Note: there are a couple of "hardening" measures embedded in libc: `export MALLOC_CHECK_=1`, [mcheck()](http://www.gnu.org/software/libc/manual/html_node/Heap-Consistency-Checking.html), [mallopt()](http://www.gnu.org/software/libc/manual/html_node/Malloc-Tunable-Parameters.html]), ...
