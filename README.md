# Educational Heap Exploitation

This repo is for learning various heap exploitation techniques.
We came up with the idea during a hack meeting, and have implemented the following techniques:

| File | Technique | Applicable CTF Challenges |
|------|-----------|---------------------------|
| [first_fit.c](first_fit.c) | Demonstrating glibc malloc's first-fit behavior. | |
| [fastbin_dup.c](fastbin_dup.c) | Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist. | |
| [fastbin_dup_into_stack.c](fastbin_dup_into_stack.c) | Tricking malloc into returning a nearly-arbitrary pointer by abusing the fastbin freelist. | [9447-search-engine](https://github.com/ctfs/write-ups-2015/tree/master/9447-ctf-2015/exploitation/search-engine), [0ctf 2017-babyheap](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html) |
| [unsafe_unlink.c](unsafe_unlink.c) | Exploiting free on a corrupted chunk to get arbitrary write. | [HITCON CTF 2014-stkof](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/), [Insomni'hack 2017-Wheel of Robots](https://gist.github.com/niklasb/074428333b817d2ecb63f7926074427a) |
| [house_of_spirit.c](house_of_spirit.c) | Frees a fake fastbin chunk to get malloc to return a nearly-arbitrary pointer. | [hack.lu CTF 2014-OREO](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/oreo) |
| [poison_null_byte.c](poison_null_byte.c) | Exploiting a single null byte overflow. | [PlaidCTF 2015-plaiddb](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/pwnable/plaiddb), [Nuit du Hack 2016-night-deamonic-heap](https://github.com/ctfs/write-ups-2016/tree/master/nuitduhack-quals-2016/exploit-me/night-deamonic-heap-400) |
| [house_of_lore.c](house_of_lore.c) | Tricking malloc into returning a nearly-arbitrary pointer by abusing the smallbin freelist. | |
| [overlapping_chunks.c](overlapping_chunks.c) | Exploit the overwrite of a freed chunk size in the unsorted bin in order to make a new allocation overlap with an existing chunk | [hack.lu CTF 2015-bookstore](https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/exploiting/bookstore) |
| [house_of_force.c](house_of_force.c) | Exploiting the Top Chunk (Wilderness) header in order to get malloc to return a nearly-arbitrary pointer  | [Boston Key Party 2016-cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6), [BCTF 2016-bcloud](https://github.com/ctfs/write-ups-2016/tree/master/bctf-2016/exploit/bcloud-200) |
| [unsorted_bin_attack.c](unsorted_bin_attack.c) | Exploiting the overwrite of a freed chunk on unsorted bin freelist to write a large value into arbitrary address  | [0ctf 2016-zerostorage](https://github.com/ctfs/write-ups-2016/tree/master/0ctf-2016/exploit/zerostorage-6) |
| [house_of_einherjar.c](house_of_einherjar.c) | Exploiting a single null byte overflow to trick malloc into returning a controlled pointer  | [Seccon 2016-tinypad](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf) |

Have a good example?
Add it here!
Try to inline the whole technique in a single `.c` -- it's a lot easier to learn that way.

# Heap Exploitation Tools

There are some heap exploitation tools floating around.

## shadow

jemalloc exploitation framework: https://github.com/CENSUS/shadow

## libheap

Examine the glibc heap in gdb: https://github.com/cloudburst/libheap

## Malloc Playground

The `malloc_playground.c` file given is the source for a program that prompts the user for commands to allocate and free memory interactively.

# Other resources

Some good heap exploitation resources, roughly in order of their publication, are:

- glibc in-depth tutorial (https://heap-exploitation.dhavalkapil.com/) - book and exploit samples
- ptmalloc fanzine, a set of resources and examples related to meta-data attacks on ptmalloc (http://tukan.farm/2016/07/26/ptmalloc-fanzine/)
- A malloc diagram, from libheap (https://raw.githubusercontent.com/cloudburst/libheap/master/heap.png)
- Glibc Adventures: The Forgotten Chunk (http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf) - advanced heap exploitation
- Pseudomonarchia jemallocum (http://www.phrack.org/issues/68/10.html)
- The House Of Lore: Reloaded (http://phrack.org/issues/67/8.html)
- Malloc Des-Maleficarum (http://phrack.org/issues/66/10.html) - some malloc exploitation techniques
- Yet another free() exploitation technique (http://phrack.org/issues/66/6.html)
- Understanding the heap by breaking it (https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf) - explains heap implementation and a couple exploits
- The use of set_head to defeat the wilderness (http://phrack.org/issues/64/9.html)
- The Malloc Maleficarum (http://seclists.org/bugtraq/2005/Oct/118)
- OS X heap exploitation techniques (http://phrack.org/issues/63/5.html)
- Exploiting The Wilderness (http://seclists.org/vuln-dev/2004/Feb/25)
- Advanced Doug lea's malloc exploits (http://phrack.org/issues/61/6.html)
- GDB Enhanced Features (GEF) Heap Exploration Tools (https://gef.readthedocs.io/en/latest/commands/heap/)
- Painless intro to the Linux userland heap (https://sensepost.com/blog/2017/painless-intro-to-the-linux-userland-heap/)

# Hardening
There are a couple of "hardening" measures embedded in glibc, like `export MALLOC_CHECK_=1` (enables some checks), `export MALLOC_PERTURB_=1` (data is overwritten), `export MALLOC_MMAP_THRESHOLD_=1` (always use mmap()), ...

More info: [mcheck()](http://www.gnu.org/software/libc/manual/html_node/Heap-Consistency-Checking.html), [mallopt()](http://www.gnu.org/software/libc/manual/html_node/Malloc-Tunable-Parameters.html).

There's also some tracing support as [mtrace()](http://manpages.ubuntu.com/mtrace), [malloc_stats()](http://manpages.ubuntu.com/malloc_stats), [malloc_info()](http://manpages.ubuntu.com/malloc_info), [memusage](http://manpages.ubuntu.com/memusage), and in other functions in this family.
