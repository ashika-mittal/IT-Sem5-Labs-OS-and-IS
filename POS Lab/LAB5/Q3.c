#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

// Bubble Sort
void bubbleSort(char arr[][50], int n) {
    char temp[50];
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (strcmp(arr[j], arr[j + 1]) > 0) {
                strcpy(temp, arr[j]);
                strcpy(arr[j], arr[j + 1]);
                strcpy(arr[j + 1], temp);
            }
        }
    }
}

// Selection Sort
void selectionSort(char arr[][50], int n) {
    int minIndex;
    char temp[50];
    for (int i = 0; i < n - 1; i++) {
        minIndex = i;
        for (int j = i + 1; j < n; j++) {
            if (strcmp(arr[j], arr[minIndex]) < 0) {
                minIndex = j;
            }
        }
        strcpy(temp, arr[i]);
        strcpy(arr[i], arr[minIndex]);
        strcpy(arr[minIndex], temp);
    }
}

int main() {
    int n;
    printf("Enter number of strings: ");
    scanf("%d", &n);

    char arr[n][50];
    printf("Enter %d strings:\n", n);
    for (int i = 0; i < n; i++) {
        scanf("%s", arr[i]);
    }

    pid_t pid1 = fork();

    if (pid1 == 0) {
        // First child: Bubble Sort
        bubbleSort(arr, n);
        printf("Child 1 (Bubble Sort):\n");
        for (int i = 0; i < n; i++) {
            printf("%s\n", arr[i]);
        }
        exit(0);
    } else {
        pid_t pid2 = fork();
        if (pid2 == 0) {
            // Second child: Selection Sort
            selectionSort(arr, n);
            printf("Child 2 (Selection Sort):\n");
            for (int i = 0; i < n; i++) {
                printf("%s\n", arr[i]);
            }
            exit(0);
        } else {
            // Parent waits until one child finishes
            wait(NULL);
            printf("Parent: At least one child has finished sorting.\n");
        }
    }

    return 0;
}

