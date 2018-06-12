ChangeLog for relevant heap-protection changes
--------------------------------------------

## Version 2.25

All attacks in this repo work at least in this version.

## Version 2.26

- tcache (per-thread cache) is introduced (enabled in ubuntu-build since 2.27)
    * See [tukan.farm](http://tukan.farm/2017/07/08/tcache/) for a short overview
    

- `unlink(AV, P, BK, FD)`:
    * Add size consistency check:
        ```
            if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))
              malloc_printerr ("corrupted size vs. prev_size");
        ```

## Version 2.27

- `malloc_consolidate(mstate av)`:
    * Add size check when placing chunks into fastbins:
        ```
        unsigned int idx = fastbin_index (chunksize (p));
        if ((&fastbin (av, idx)) != fb)
          malloc_printerr ("malloc_consolidate(): invalid chunk size");
        ```
