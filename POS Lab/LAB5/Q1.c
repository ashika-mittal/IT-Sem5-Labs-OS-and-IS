#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        return 1;
    } 
    else if (pid == 0) {  
        // Child process
        printf("This is the Child Process\n");
        printf("Child PID: %d\n", getpid());
        printf("Child's Parent PID (PPID): %d\n", getppid());
    } 
    else {  
        // Parent process
        printf("This is the Parent Process\n");
        printf("Parent PID: %d\n", getpid());
        printf("Parent's Parent PID (PPID): %d\n", getppid());
    }

    return 0;
}

