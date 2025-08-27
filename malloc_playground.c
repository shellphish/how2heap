#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef __GLIBC__
# include <malloc.h>
# include <mcheck.h>
void print_mcheck_status(enum mcheck_status s)
{
	fprintf(stderr, "%s\n", (s == MCHECK_DISABLED) ? "N/A, you didn't enable mcheck()" :
				   (s == MCHECK_OK) ? "No inconsistency detected" :
				   (s == MCHECK_HEAD) ? "Memory preceding an allocated block was clobbered" :
				   (s == MCHECK_TAIL) ? "Memory following an allocated block was clobbered" :
				   (s == MCHECK_FREE) ? "A block of memory was freed twice" :
				   "unknown memory check code!");
}
void report_mcheck_fail(enum mcheck_status s)
{
	fprintf(stderr, "*** PROGRAM WOULD ABORT: "); print_mcheck_status(s);
}
#endif


#define MAX_PTR_NUM 20;

char **ptrArray;

int main(int argc, char ** argv) {
	int num;
	int ptrNumber = -1;
	int maxPtr = MAX_PTR_NUM;
	int sizeArg;
	char sizeTable[maxPtr];

	char buffer[1000];
	char cmd[1000];
	char arg1[100];
	char arg2[100];

	memset(sizeTable, 0, maxPtr);
	memset(cmd, 0, 1000);
	memset(arg1, 0, 100);
	memset(arg2, 0, 100);

	fprintf(stderr, "pid: %d\n", getpid());
	ptrArray = malloc(sizeof(char*) * 20);
	for (int i = 0; i < maxPtr; i++){
		ptrArray[i] = 0;
	}
	while (1) {
		fprintf(stderr, "> ");
		fgets(buffer, sizeof(buffer), stdin);
		num = sscanf(buffer, "%s %s %s\n", cmd, arg1, arg2);
		if (strcmp(cmd, "malloc") == 0) {
			if (ptrNumber < maxPtr){
				sizeArg = atoi((const char *) &arg1);
				void *result = malloc(sizeArg);
				ptrNumber++;
				sizeTable[ptrNumber] = sizeArg;
				ptrArray[ptrNumber] = result;
				strcpy(result, "none");
				fprintf(stderr, "==> OK, %p\n", result);
			}
			else{
				printf("Max pointer reached, free or restart");
			}
		} else if (strcmp(cmd, "free") == 0) {
			if (ptrNumber > -1){
				if (num == 1){
					free((void*) ptrArray[ptrNumber]);
					ptrArray[ptrNumber] = 0;
					sizeTable[ptrNumber] = 0;
					fprintf(stderr, "==> ok\n");
					ptrNumber -= 1;
				}
				else if (num == 2){
					int tmpArg = atoi((const char *) &arg1);
					ptrArray[tmpArg] = 0;
					sizeTable[tmpArg] = 0;
					free((void *) ptrArray[tmpArg]);
					ptrNumber -= 1;
					fprintf(stderr, "==> ok\n");
				}
			}
			else{
				fprintf(stderr, "==> list empty :/\n");

			}
		} else if (strcmp(cmd, "write") == 0) {
			if (num == 1){
				printf("write: write value [pointer index]\n");
			}
			else if (num == 2){
				int len = strlen((const char *) &arg1);
				strcpy(ptrArray[ptrNumber], (const char *) &arg1);
				fprintf(stderr, "==> ok, wrote %s\n", ptrArray[ptrNumber]);
			}
			else if (num == 3){
				int len = strlen((const char *) &arg1);
				int tmpArg2 = atoi((const char *) &arg2);
				//if (tmpArg2 > ptrNumber){
					strcpy(ptrArray[tmpArg2], (const char *) &arg1);
					fprintf(stderr, "==> ok, wrote %s\n", ptrArray[tmpArg2]);
				//}
				//else{
				//	printf("Invalid Index\n");
				//}
			}
		} else if (strcmp(cmd, "listp") == 0) {
			printf("\n");
			for (int i = 0; i < 20; i++){
				if (ptrArray[i]){
					printf("%d - %p - %s - %d\n", i, ptrArray[i], ptrArray[i], sizeTable[i]);
				}
			}
			fprintf(stderr, "==> ok\n");
		} else if (strcmp(cmd, "listpall") == 0) {
			int tmpIndex = 0;
			printf("\n");
			for (int i=0; i < maxPtr; i++){
				printf("%d - %p - %s - %d\n", tmpIndex, ptrArray[tmpIndex], ptrArray[tmpIndex], sizeTable[i]);
				tmpIndex++;
			}
			fprintf(stderr, "==> ok\n");
		} else if (strcmp(cmd, "clearlist") == 0) {
			ptrNumber = -1;
			for (int i = 0; i < maxPtr; i++){
				free(ptrArray[i]);
				ptrArray[i] = 0;
				memset(sizeTable, 0, maxPtr);
		}
			fprintf(stderr, "==> ok, array cleared\n");
#ifdef __GLIBC__
		} else if (strcmp(cmd, "usable") == 0) {
			fprintf(stderr, "usable size: %zu\n", malloc_usable_size((void*) arg1));
		} else if (strcmp(cmd, "stats") == 0) {
			malloc_stats();
		} else if (strcmp(cmd, "info") == 0) {
			malloc_info(0, stdout);
			printf("Ptrptr %d\n", ptrNumber);
		} else if (strcmp(cmd, "mcheck") == 0) {
			fprintf(stderr, "==> %s\n", mcheck(report_mcheck_fail) == 0 ? "OK" : "ERROR");
		} else if (strcmp(cmd, "mcheck_pedantic") == 0) {
			fprintf(stderr, "==> %s\n", mcheck_pedantic(report_mcheck_fail) == 0 ? "OK" : "ERROR");
		} else if (strcmp(cmd, "mprobe") == 0) {
			if (num > 1) {
				print_mcheck_status(mprobe((void*) arg1));
			} else {
				mcheck_check_all();
				fprintf(stderr, "==> check_all ok\n");
			}
#endif
		} else {
			puts("Commands: malloc n, free p, usable p, stats, info, mprobe [p], mcheck, mcheck_pedantic, ");
			puts("Commands: [BETA]  write str, listp, listpall, clearlist\n");
		}
	}
}