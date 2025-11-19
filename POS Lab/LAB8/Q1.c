#include <stdio.h>
#include <stdbool.h>

#define P 5   // number of processes
#define R 3   // number of resources

// Function to check if system is in a safe state
bool isSafe(int processes[], int avail[], int max[][R], int allot[][R]) {
    int need[P][R];
    int i, j;

    // Calculate need matrix
    for (i = 0; i < P; i++)
        for (j = 0; j < R; j++)
            need[i][j] = max[i][j] - allot[i][j];

    // Initialize work = avail, finish[] = false
    int work[R];
    for (i = 0; i < R; i++)
        work[i] = avail[i];

    bool finish[P] = {0};
    int safeSeq[P];
    int count = 0;

    // While not all processes are finished
    while (count < P) {
        bool found = false;
        for (i = 0; i < P; i++) {
            if (!finish[i]) {
                // Check if need <= work
                bool canRun = true;
                for (j = 0; j < R; j++) {
                    if (need[i][j] > work[j]) {
                        canRun = false;
                        break;
                    }
                }

                if (canRun) {
                    // This process can finish
                    for (j = 0; j < R; j++)
                        work[j] += allot[i][j];
                    safeSeq[count++] = i;
                    finish[i] = true;
                    found = true;
                }
            }
        }

        if (!found) {
            printf("System is NOT in a safe state.\n");
            return false;
        }
    }

    printf("System is in a SAFE state.\nSafe sequence: ");
    for (i = 0; i < P; i++)
        printf("P%d ", safeSeq[i]);
    printf("\n");
    return true;
}

// Function to request resources
void requestResources(int pid, int request[], int avail[], int max[][R], int allot[][R]) {
    int need[P][R];
    int i, j;

    // Calculate current need
    for (i = 0; i < P; i++)
        for (j = 0; j < R; j++)
            need[i][j] = max[i][j] - allot[i][j];

    // Check if request <= need
    for (j = 0; j < R; j++) {
        if (request[j] > need[pid][j]) {
            printf("Error: Process P%d has exceeded its maximum claim.\n", pid);
            return;
        }
    }

    // Check if request <= available
    for (j = 0; j < R; j++) {
        if (request[j] > avail[j]) {
            printf("Process P%d must wait, resources not available.\n", pid);
            return;
        }
    }

    // Pretend to allocate
    for (j = 0; j < R; j++) {
        avail[j] -= request[j];
        allot[pid][j] += request[j];
        // max stays same
    }

    // Check if new state is safe
    if (isSafe((int[]){0,1,2,3,4}, avail, max, allot)) {
        printf("Request by P%d granted.\n", pid);
    } else {
        // Rollback
        for (j = 0; j < R; j++) {
            avail[j] += request[j];
            allot[pid][j] -= request[j];
        }
        printf("Request by P%d denied (would lead to unsafe state).\n", pid);
    }
}

int main() {
    int processes[P] = {0, 1, 2, 3, 4};

    // Example available resources
    int avail[R] = {3, 3, 2};

    // Example maximum demand matrix
    int max[P][R] = {
        {7, 5, 3},
        {3, 2, 2},
        {9, 0, 2},
        {2, 2, 2},
        {4, 3, 3}
    };

    // Example allocation matrix
    int allot[P][R] = {
        {0, 1, 0},
        {2, 0, 0},
        {3, 0, 2},
        {2, 1, 1},
        {0, 0, 2}
    };

    // Initial safety check
    isSafe(processes, avail, max, allot);

    // Example requests
    int req1[R] = {1, 0, 2};
    requestResources(1, req1, avail, max, allot);

    int req2[R] = {3, 3, 0};
    requestResources(4, req2, avail, max, allot);

    return 0;
}
