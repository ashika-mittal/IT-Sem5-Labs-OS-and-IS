#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int cmpfunc(const void *a, const void *b) {
    return strcmp(*(char **)a, *(char **)b);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <strings>\n", argv[0]);
        return 1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        return 1;
    } 
    else if (pid == 0) {
        // Child process: Sort and display
        printf("Child: Sorted Strings:\n");
        qsort(&argv[1], argc - 1, sizeof(char *), cmpfunc);
        for (int i = 1; i < argc; i++) {
            printf("%s\n", argv[i]);
        }
    } 
    else {
        // Parent process waits
        wait(NULL);
        printf("Parent: Unsorted Strings:\n");
        for (int i = 1; i < argc; i++) {
            printf("%s\n", argv[i]);
        }
    }

    return 0;
}

