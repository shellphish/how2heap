#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char ** argv) {
	char buffer[1000];
	while (1) {
		printf("> ");
		gets(buffer);
		char cmd[1000];
		long arg1, arg2;
		int num = sscanf(buffer, "%s %li %li", cmd, &arg1, &arg2);
		if (strcmp(cmd, "malloc") == 0) {
			long result = malloc(arg1);
			printf("==> %#lx\n", result);
		} else if (strcmp(cmd, "free") == 0) {
			free(arg1);
			printf("==> ok\n");
		} else if (strcmp(cmd, "show") == 0) {
			if (num == 2) {
				arg2 = 1;
			}
			long * src = arg1;
			for (int i = 0; i < arg2; i++) {
				printf("%p: %#16.0lx\n", &src[i], src[i]);
			}
		} else {
			puts("Commands: malloc n, free n, show n [m]");
		}
	}
}
