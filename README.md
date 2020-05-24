# Educational Heap Exploitation

This repo is for learning various heap exploitation techniques.
We came up with the idea during a hack meeting, and have implemented the following techniques:

| File | Technique | Glibc-Version |Applicable CTF Challenges |
|------|-----------|---------------|--------------------------|
| [first_fit.c](first_fit.c) | Demonstrating glibc malloc's first-fit behavior. | | |
| [calc_tcache_idx.c](calc_tcache_idx.c) | Demonstrating glibc's tcache index calculation. | | |
| [fastbin_dup.c](fastbin_dup.c) | Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist. | | |
| [fastbin_dup_into_stack.c](glibc_2.25/fastbin_dup_into_stack.c) | Tricking malloc into returning a nearly-arbitrary pointer by abusing the fastbin freelist. | latest | [9447-search-engine](https://github.com/ctfs/write-ups-2015/tree/master/9447-ctf-2015/exploitation/search-engine), [0ctf 2017-babyheap](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html) |
| [fastbin_dup_consolidate.c](glibc_2.25/fastbin_dup_consolidate.c) | Tricking malloc into returning an already-allocated heap pointer by putting a pointer on both fastbin freelist and unsorted bin freelist. | latest | [Hitcon 2016 SleepyHolder](https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder) |
| [unsafe_unlink.c](glibc_2.26/unsafe_unlink.c) | Exploiting free on a corrupted chunk to get arbitrary write. | < 2.26 | [HITCON CTF 2014-stkof](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/), [Insomni'hack 2017-Wheel of Robots](https://gist.github.com/niklasb/074428333b817d2ecb63f7926074427a) |
| [house_of_spirit.c](glibc_2.25/house_of_spirit.c) | Frees a fake fastbin chunk to get malloc to return a nearly-arbitrary pointer. | latest | [hack.lu CTF 2014-OREO](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/oreo) |
| [poison_null_byte.c](glibc_2.25/poison_null_byte.c) | Exploiting a single null byte overflow. | < 2.26 | [PlaidCTF 2015-plaiddb](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/pwnable/plaiddb) |
| [house_of_lore.c](glibc_2.26/house_of_lore.c) | Tricking malloc into returning a nearly-arbitrary pointer by abusing the smallbin freelist. | < 2.26 | |
| [overlapping_chunks.c](glibc_2.26/overlapping_chunks.c) | Exploit the overwrite of a freed chunk size in the unsorted bin in order to make a new allocation overlap with an existing chunk | < 2.26 | [hack.lu CTF 2015-bookstore](https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/exploiting/bookstore), [Nuit du Hack 2016-night-deamonic-heap](https://github.com/ctfs/write-ups-2016/tree/master/nuitduhack-quals-2016/exploit-me/night-deamonic-heap-400) |
| [overlapping_chunks_2.c](glibc_2.25/overlapping_chunks_2.c) | Exploit the overwrite of an in use chunk size in order to make a new allocation overlap with an existing chunk  | latest | |
| [house_of_force.c](glibc_2.25/house_of_force.c) | Exploiting the Top Chunk (Wilderness) header in order to get malloc to return a nearly-arbitrary pointer | < 2.29 | [Boston Key Party 2016-cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6), [BCTF 2016-bcloud](https://github.com/ctfs/write-ups-2016/tree/master/bctf-2016/exploit/bcloud-200) |
| [unsorted_bin_into_stack.c](glibc_2.26/unsorted_bin_into_stack.c) | Exploiting the overwrite of a freed chunk on unsorted bin freelist to return a nearly-arbitrary pointer.  | < 2.26 | |
| [unsorted_bin_attack.c](glibc_2.26/unsorted_bin_attack.c) | Exploiting the overwrite of a freed chunk on unsorted bin freelist to write a large value into arbitrary address  | < 2.28 | [0ctf 2016-zerostorage](https://github.com/ctfs/write-ups-2016/tree/master/0ctf-2016/exploit/zerostorage-6) |
| [large_bin_attack.c](glibc_2.26/large_bin_attack.c) | Exploiting the overwrite of a freed chunk on large bin freelist to write a large value into arbitrary address  | < 2.26 | [0ctf 2018-heapstorm2](https://dangokyo.me/2018/04/07/0ctf-2018-pwn-heapstorm2-write-up/) |
| [house_of_einherjar.c](glibc_2.26/house_of_einherjar.c) | Exploiting a single null byte overflow to trick malloc into returning a controlled pointer  | < 2.26 | [Seccon 2016-tinypad](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf) |
| [house_of_orange.c](glibc_2.25/house_of_orange.c) | Exploiting the Top Chunk (Wilderness) in order to gain arbitrary code execution  | < 2.26 | [Hitcon 2016 houseoforange](https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/house-of-orange-500) |
| [house_of_roman.c](glibc_2.25/house_of_roman.c) | Leakless technique in order to gain remote code execution via fake fastbins, the unsorted_bin attack and relative overwrites. |< 2.26 |
| [tcache_dup.c](glibc_2.26/tcache_dup.c) | Tricking malloc into returning an already-allocated heap pointer by abusing the tcache freelist. | 2.26 - 2.28 | |
| [tcache_poisoning.c](glibc_2.26/tcache_poisoning.c) | Tricking malloc into returning a completely arbitrary pointer by abusing the tcache freelist. | > 2.25  | |
| [tcache_house_of_spirit.c](glibc_2.26/tcache_house_of_spirit.c) | Frees a fake chunk to get malloc to return a nearly-arbitrary pointer. | > 2.25 | |
| [house_of_botcake.c](glibc_2.26/house_of_botcake.c) | Bypass double free restriction on tcache. | > 2.25 | |
| [tcache_stashing_unlink_attack.c](glibc_2.26/tcache_stashing_unlink_attack.c) | Exploiting the overwrite of a freed chunk on small bin freelist to trick malloc into returning an arbitrary pointer and write a large value into arbitraty address with the help of calloc. | > 2.25 | [Hitcon 2019 one punch man](https://github.com/xmzyshypnc/xz_files/tree/master/hitcon2019_one_punch_man) |
| [fastbin_reverse_into_tcache.c](glibc_2.26/fastbin_reverse_into_tcache.c) | Exploiting the overwrite of a freed chunk in the fastbin to write a large value into an arbitrary address. | > 2.25 | |

The GnuLibc is under constant development and several of the techniques above have let to consistency checks introduced in the malloc/free logic.
Consequently, these checks regularly break some of the techniques and require adjustments to bypass them (if possible).
We address this issue by keeping multiple versions of the same technique for each Glibc-release that required an adjustment.
The structure is `glibc_<version>/technique.c`.

Have a good example?
Add it here!
Try to inline the whole technique in a single `.c` -- it's a lot easier to learn that way.

# Heap Exploitation Tools

There are some heap exploitation tools floating around.

## shadow

jemalloc exploitation framework: https://github.com/CENSUS/shadow

## libheap

Examine the glibc heap in gdb: https://github.com/cloudburst/libheap

## heap-viewer

Examine the glibc heap in IDA Pro: https://github.com/danigargu/heap-viewer

## heapinspect

A Python based heap playground with good visualization for educational purposes: https://github.com/matrix1001/heapinspect

## Malloc Playground

The `malloc_playground.c` file given is the source for a program that prompts the user for commands to allocate and free memory interactively.

## Pwngdb

Examine the glibc heap in gdb: https://github.com/scwuaptx/Pwngdb

# Other resources

Some good heap exploitation resources, roughly in order of their publication, are:

- glibc in-depth tutorial (https://heap-exploitation.dhavalkapil.com/) - book and exploit samples
- ptmalloc fanzine, a set of resources and examples related to meta-data attacks on ptmalloc (http://tukan.farm/2016/07/26/ptmalloc-fanzine/)
- A malloc diagram, from libheap (https://raw.githubusercontent.com/cloudburst/libheap/master/heap.png)
- Glibc Adventures: The Forgotten Chunk (https://go.contextis.com/rs/140-OCV-459/images/Glibc_Adventures-The_Forgotten_Chunks.pdf) - advanced heap exploitation
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
- GDB Enhanced Features (GEF) Heap Exploration Tools (https://gef.readthedocs.io/en/master/commands/heap/)
- Painless intro to the Linux userland heap (https://sensepost.com/blog/2017/painless-intro-to-the-linux-userland-heap/)

# Hardening
There are a couple of "hardening" measures embedded in glibc, like `export MALLOC_CHECK_=1` (enables some checks), `export MALLOC_PERTURB_=1` (data is overwritten), `export MALLOC_MMAP_THRESHOLD_=1` (always use mmap()), ...

More info: [mcheck()](http://www.gnu.org/software/libc/manual/html_node/Heap-Consistency-Checking.html), [mallopt()](http://www.gnu.org/software/libc/manual/html_node/Malloc-Tunable-Parameters.html).

There's also some tracing support as [mtrace()](http://manpages.ubuntu.com/mtrace), [malloc_stats()](http://manpages.ubuntu.com/malloc_stats), [malloc_info()](http://manpages.ubuntu.com/malloc_info), [memusage](http://manpages.ubuntu.com/memusage), and in other functions in this family.

