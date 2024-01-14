# Educational Heap Exploitation

This repo is for learning various heap exploitation techniques.
We use Ubuntu's Libc releases as the gold-standard. Each technique is verified to work on corresponding Ubuntu releases.
You can run `apt source libc6` to download the source code of the Libc your are using on Debian-based operating system. You can also click :arrow_forward: to debug the technique in your browser using gdb.

We came up with the idea during a hack meeting, and have implemented the following techniques:

| File | :arrow_forward: | Technique | Glibc-Version | Patch | Applicable CTF Challenges |
|------|-----|-----------|---------------|-------|---------------------------|
| [first_fit.c](first_fit.c) | |  Demonstrating glibc malloc's first-fit behavior. | | | |
| [calc_tcache_idx.c](calc_tcache_idx.c)| |  Demonstrating glibc's tcache index calculation.| | | |
| [fastbin_dup.c](glibc_2.35/fastbin_dup.c) | <a href="https://wargames.ret2.systems/level/how2heap_fastbin_dup_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist. | latest | | |
| [fastbin_dup_into_stack.c](glibc_2.35/fastbin_dup_into_stack.c) | <a href="https://wargames.ret2.systems/level/how2heap_fastbin_dup_into_stack_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | Tricking malloc into returning a nearly-arbitrary pointer by abusing the fastbin freelist. | latest | | [9447-search-engine](https://github.com/ctfs/write-ups-2015/tree/master/9447-ctf-2015/exploitation/search-engine), [0ctf 2017-babyheap](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html) |
| [fastbin_dup_consolidate.c](glibc_2.35/fastbin_dup_consolidate.c) | <a href="https://wargames.ret2.systems/level/how2heap_fastbin_dup_consolidate_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | Tricking malloc into returning an already-allocated heap pointer by putting a pointer on both fastbin freelist and unsorted bin freelist. | latest | | [Hitcon 2016 SleepyHolder](https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder) |
| [unsafe_unlink.c](glibc_2.35/unsafe_unlink.c) | <a href="https://wargames.ret2.systems/level/how2heap_unsafe_unlink_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Exploiting free on a corrupted chunk to get arbitrary write. | latest | | [HITCON CTF 2014-stkof](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/), [Insomni'hack 2017-Wheel of Robots](https://gist.github.com/niklasb/074428333b817d2ecb63f7926074427a) |
| [house_of_spirit.c](glibc_2.35/house_of_spirit.c) | <a href="https://wargames.ret2.systems/level/how2heap_house_of_spirit_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | Frees a fake fastbin chunk to get malloc to return a nearly-arbitrary pointer. | latest | | [hack.lu CTF 2014-OREO](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/oreo) |
| [poison_null_byte.c](glibc_2.35/poison_null_byte.c) | <a href="https://wargames.ret2.systems/level/how2heap_poison_null_byte_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Exploiting a single null byte overflow. | latest | | [PlaidCTF 2015-plaiddb](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/pwnable/plaiddb), [BalsnCTF 2019-PlainNote](https://gist.github.com/st424204/6b5c007cfa2b62ed3fd2ef30f6533e94?fbclid=IwAR3n0h1WeL21MY6cQ_C51wbXimdts53G3FklVIHw2iQSgtgGo0kR3Lt-1Ek)|
| [house_of_lore.c](glibc_2.35/house_of_lore.c) | <a href="https://wargames.ret2.systems/level/how2heap_house_of_lore_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Tricking malloc into returning a nearly-arbitrary pointer by abusing the smallbin freelist. | latest | | |
| [overlapping_chunks.c](glibc_2.27/overlapping_chunks.c) | <a href="https://wargames.ret2.systems/level/how2heap_overlapping_chunks_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Exploit the overwrite of a freed chunk size in the unsorted bin in order to make a new allocation overlap with an existing chunk | < 2.29 | [patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) | [hack.lu CTF 2015-bookstore](https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/exploiting/bookstore), [Nuit du Hack 2016-night-deamonic-heap](https://github.com/ctfs/write-ups-2016/tree/master/nuitduhack-quals-2016/exploit-me/night-deamonic-heap-400) |
| [overlapping_chunks_2.c](glibc_2.23/overlapping_chunks_2.c) | <a href="https://wargames.ret2.systems/level/how2heap_overlapping_chunks_2_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | Exploit the overwrite of an in use chunk size in order to make a new allocation overlap with an existing chunk  | < 2.29|[patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) | |
| [mmap_overlapping_chunks.c](glibc_2.35/mmap_overlapping_chunks.c) | |  Exploit an in use mmap chunk in order to make a new allocation overlap with a current mmap chunk | latest | | | 
| [house_of_force.c](glibc_2.27/house_of_force.c) | <a href="https://wargames.ret2.systems/level/how2heap_house_of_force_2.27" title="Debug Technique In Browser">:arrow_forward:</a> | Exploiting the Top Chunk (Wilderness) header in order to get malloc to return a nearly-arbitrary pointer | < 2.29 | [patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=30a17d8c95fbfb15c52d1115803b63aaa73a285c) | [Boston Key Party 2016-cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6), [BCTF 2016-bcloud](https://github.com/ctfs/write-ups-2016/tree/master/bctf-2016/exploit/bcloud-200) |
| [unsorted_bin_into_stack.c](glibc_2.27/unsorted_bin_into_stack.c) | <a href="https://wargames.ret2.systems/level/how2heap_unsorted_bin_into_stack_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | Exploiting the overwrite of a freed chunk on unsorted bin freelist to return a nearly-arbitrary pointer.  | < 2.29 | [patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c)| |
| [unsorted_bin_attack.c](glibc_2.27/unsorted_bin_attack.c) | <a href="https://wargames.ret2.systems/level/how2heap_unsorted_bin_attack_2.27" title="Debug Technique In Browser">:arrow_forward:</a> | Exploiting the overwrite of a freed chunk on unsorted bin freelist to write a large value into arbitrary address  | < 2.29 | [patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) | [0ctf 2016-zerostorage](https://github.com/ctfs/write-ups-2016/tree/master/0ctf-2016/exploit/zerostorage-6) |
| [large_bin_attack.c](glibc_2.35/large_bin_attack.c) | <a href="https://wargames.ret2.systems/level/how2heap_large_bin_attack_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Exploiting the overwrite of a freed chunk on large bin freelist to write a large value into arbitrary address  | latest | | [0ctf 2018-heapstorm2](https://dangokyo.me/2018/04/07/0ctf-2018-pwn-heapstorm2-write-up/) |
| [house_of_einherjar.c](glibc_2.35/house_of_einherjar.c) | <a href="https://wargames.ret2.systems/level/how2heap_house_of_einherjar_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Exploiting a single null byte overflow to trick malloc into returning a controlled pointer  | latest | | [Seccon 2016-tinypad](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf) |
| [house_of_water.c](glibc_2.36/house_of_water.c) | | Exploit a UAF or double free to gain leakless control of the t-cache metadata and a leakless way to link libc in t-cache | latest | | [37c3 Potluck - Tamagoyaki](https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki)|
| [house_of_orange.c](glibc_2.23/house_of_orange.c) | <a href="https://wargames.ret2.systems/level/how2heap_house_of_orange_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | Exploiting the Top Chunk (Wilderness) in order to gain arbitrary code execution  | < 2.26 | [patch](https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=stdlib/abort.c;h=117a507ff88d862445551f2c07abb6e45a716b75;hp=19882f3e3dc1ab830431506329c94dcf1d7cc252;hb=91e7cf982d0104f0e71770f5ae8e3faf352dea9f;hpb=0c25125780083cbba22ed627756548efe282d1a0) | [Hitcon 2016 houseoforange](https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/house-of-orange-500) |
| [house_of_roman.c](glibc_2.23/house_of_roman.c) | <a href="https://wargames.ret2.systems/level/how2heap_house_of_roman_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | Leakless technique in order to gain remote code execution via fake fastbins, the unsorted\_bin attack and relative overwrites. |< 2.29 |[patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) |
| [tcache_poisoning.c](glibc_2.35/tcache_poisoning.c) | <a href="https://wargames.ret2.systems/level/how2heap_tcache_poisoning_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Tricking malloc into returning a completely arbitrary pointer by abusing the tcache freelist. (requires heap leak on and after 2.32) | > 2.25  | [patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41) | |
| [tcache_house_of_spirit.c](glibc_2.35/tcache_house_of_spirit.c) | <a href="https://wargames.ret2.systems/level/how2heap_tcache_house_of_spirit_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Frees a fake chunk to get malloc to return a nearly-arbitrary pointer. | > 2.25 | | | 
| [house_of_botcake.c](glibc_2.35/house_of_botcake.c) | <a href="https://wargames.ret2.systems/level/how2heap_house_of_botcake_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Bypass double free restriction on tcache. Make `tcache_dup` great again. | > 2.25 | | |
| [tcache_stashing_unlink_attack.c](glibc_2.35/tcache_stashing_unlink_attack.c) | <a href="https://wargames.ret2.systems/level/how2heap_tcache_stashing_unlink_attack_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Exploiting the overwrite of a freed chunk on small bin freelist to trick malloc into returning an arbitrary pointer and write a large value into arbitraty address with the help of calloc. | > 2.25 | | [Hitcon 2019 one punch man](https://github.com/xmzyshypnc/xz_files/tree/master/hitcon2019_one_punch_man) | 
| [fastbin_reverse_into_tcache.c](glibc_2.35/fastbin_reverse_into_tcache.c) | <a href="https://wargames.ret2.systems/level/how2heap_fastbin_reverse_into_tcache_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Exploiting the overwrite of a freed chunk in the fastbin to write a large value into an arbitrary address. | > 2.25 | | |
| [house_of_mind_fastbin.c](glibc_2.35/house_of_mind_fastbin.c) | <a href="https://wargames.ret2.systems/level/how2heap_house_of_mind_fastbin_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Exploiting a single byte overwrite with arena handling to write a large value (heap pointer) to an arbitrary address | latest | | |
| [house_of_storm.c](glibc_2.27/house_of_storm.c) | <a href="https://wargames.ret2.systems/level/how2heap_house_of_storm_2.27" title="Debug Technique In Browser">:arrow_forward:</a> | Exploiting a use after free on both a large and unsorted bin chunk to return an arbitrary chunk from malloc| < 2.29 | | |
| [house_of_gods.c](glibc_2.24/house_of_gods.c) | <a href="https://wargames.ret2.systems/level/how2heap_house_of_gods_2.24" title="Debug Technique In Browser">:arrow_forward:</a> | A technique to hijack a thread's arena within 8 allocations | < 2.27 | | |
| [decrypt_safe_linking.c](glibc_2.35/decrypt_safe_linking.c) | <a href="https://wargames.ret2.systems/level/how2heap_decrypt_safe_linking_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | Decrypt the poisoned value in linked list to recover the actual pointer | >= 2.32 | | |
| [safe_link_double_protect.c](glibc_2.36/safe_link_double_protect.c) | | Leakless bypass for PROTECT_PTR by protecting a pointer twice, allowing for arbitrary pointer linking in t-cache | >= 2.32 | | [37c3 Potluck - Tamagoyaki](https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki)|
| [tcache_dup.c](obsolete/glibc_2.27/tcache_dup.c)(obsolete) | |  Tricking malloc into returning an already-allocated heap pointer by abusing the tcache freelist. | 2.26 - 2.28 | [patch](https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d) | |

The GnuLibc is under constant development and several of the techniques above have let to consistency checks introduced in the malloc/free logic.
Consequently, these checks regularly break some of the techniques and require adjustments to bypass them (if possible).
We address this issue by keeping multiple versions of the same technique for each Glibc-release that required an adjustment.
The structure is `glibc_<version>/technique.c`.

Have a good example?
Add it here!
Try to inline the whole technique in a single `.c` -- it's a lot easier to learn that way.

# Get Started

## Quick Setup

- make sure you have the following packages/tools installed: `patchelf zstd wget` (of course also `build-essential` or similar for compilers, `make`, ...)
- also, `/usr/bin/python` must be/point to your `python` binary (e. g. `/usr/bin/python3`)

```shell
git clone https://github.com/shellphish/how2heap
cd how2heap
make clean all
./glibc_run.sh 2.30 ./malloc_playground -u -r
```

## Complete Setup

This creates a Docker-based environment to get started with `pwndbg` and `pwntools`.

```shell
## on your host
git clone https://github.com/shellphish/how2heap
cd how2heap
git clone https://github.com/pwndbg/pwndbg
docker build -t how2heap-pwndbg pwndbg 
docker run -it --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v $(pwd):/io:Z --name how2heap how2heap-pwndbg

## inside the docker container
apt update
apt -y install patchelf zstd python-is-python3 wget
python -m pip install pwntools
export PATH="$PATH:$(python -c 'import site; print(site.getsitepackages()[0])')/bin"
cd /io
git config --global --add safe.directory "*"
make clean all
./glibc_run.sh 2.30 ./malloc_playground -u -r

## debugging
# check modified RUNPATH and interpreter
readelf -d -W malloc_playground | grep RUNPATH # or use checksec
readelf -l -W malloc_playground | grep interpreter
gdb -q -ex "start" ./malloc_playground
```

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

## Forkever

Debugger that lets you set "checkpoints" as well as view and edit the heap using a hexeditor: https://github.com/haxkor/forkever

## Malloc Playground

The `malloc_playground.c` file given is the source for a program that prompts the user for commands to allocate and free memory interactively.

## Pwngdb

Examine the glibc heap in gdb: https://github.com/scwuaptx/Pwngdb

## heaptrace

Helps you visualize heap operations by replacing addresses with symbols: https://github.com/Arinerron/heaptrace

## Heap Search

Search for applicable heap exploitation techniques based on primitive requirements: https://kissprogramming.com/heap/heap-search

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
- Heap exploitation techniques that work on glibc-2.31 (https://github.com/StarCross-Tech/heap_exploit_2.31)
- Overview of GLIBC heap exploitation techniques (https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/)

# Hardening
There are a couple of "hardening" measures embedded in glibc, like `export MALLOC_CHECK_=1` (enables some checks), `export MALLOC_PERTURB_=1` (data is overwritten), `export MALLOC_MMAP_THRESHOLD_=1` (always use mmap()), ...

More info: [mcheck()](http://www.gnu.org/software/libc/manual/html_node/Heap-Consistency-Checking.html), [mallopt()](http://www.gnu.org/software/libc/manual/html_node/Malloc-Tunable-Parameters.html).

There's also some tracing support as [mtrace()](http://manpages.ubuntu.com/mtrace), [malloc_stats()](http://manpages.ubuntu.com/malloc_stats), [malloc_info()](http://manpages.ubuntu.com/malloc_info), [memusage](http://manpages.ubuntu.com/memusage), and in other functions in this family.

