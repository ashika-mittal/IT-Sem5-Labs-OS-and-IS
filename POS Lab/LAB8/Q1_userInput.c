#include <stdio.h>
#include <stdbool.h>

#define MAX_P 10   // max number of processes
#define MAX_R 10   // max number of resources

// Function to check if system is in a safe state
bool isSafe(int n, int m, int avail[], int max[][MAX_R], int allot[][MAX_R]) {
    int need[MAX_P][MAX_R];
    int i, j;

    // Calculate need matrix
    for (i = 0; i < n; i++)
        for (j = 0; j < m; j++)
            need[i][j] = max[i][j] - allot[i][j];

    // Initialize work = avail, finish[] = false
    int work[MAX_R];
    for (i = 0; i < m; i++)
        work[i] = avail[i];

    bool finish[MAX_P] = {0};
    int safeSeq[MAX_P];
    int count = 0;

    // While not all processes are finished
    while (count < n) {
        bool found = false;
        for (i = 0; i < n; i++) {
            if (!finish[i]) {
                // Check if need <= work
                bool canRun = true;
                for (j = 0; j < m; j++) {
                    if (need[i][j] > work[j]) {
                        canRun = false;
                        break;
                    }
                }

                if (canRun) {
                    // This process can finish
                    for (j = 0; j < m; j++)
                        work[j] += allot[i][j];
                    safeSeq[count++] = i;
                    finish[i] = true;
                    found = true;
                }
            }
        }

        if (!found) {
            printf("\nSystem is NOT in a safe state.\n");
            return false;
        }
    }

    printf("\nSystem is in a SAFE state.\nSafe sequence: ");
    for (i = 0; i < n; i++)
        printf("P%d ", safeSeq[i]);
    printf("\n");
    return true;
}

// Function to request resources
void requestResources(int n, int m, int pid, int request[], int avail[], int max[][MAX_R], int allot[][MAX_R]) {
    int need[MAX_P][MAX_R];
    int i, j;

    // Calculate current need
    for (i = 0; i < n; i++)
        for (j = 0; j < m; j++)
            need[i][j] = max[i][j] - allot[i][j];

    // Check if request <= need
    for (j = 0; j < m; j++) {
        if (request[j] > need[pid][j]) {
            printf("Error: Process P%d has exceeded its maximum claim.\n", pid);
            return;
        }
    }

    // Check if request <= available
    for (j = 0; j < m; j++) {
        if (request[j] > avail[j]) {
            printf("Process P%d must wait, resources not available.\n", pid);
            return;
        }
    }

    // Pretend to allocate
    for (j = 0; j < m; j++) {
        avail[j] -= request[j];
        allot[pid][j] += request[j];
    }

    // Check if new state is safe
    if (isSafe(n, m, avail, max, allot)) {
        printf("Request by P%d GRANTED.\n", pid);
    } else {
        // Rollback
        for (j = 0; j < m; j++) {
            avail[j] += request[j];
            allot[pid][j] -= request[j];
        }
        printf("Request by P%d DENIED (would lead to unsafe state).\n", pid);
    }
}

int main() {
    int n, m;
    int i, j;

    printf("Enter number of processes: ");
    scanf("%d", &n);
    printf("Enter number of resources: ");
    scanf("%d", &m);

    int avail[MAX_R];
    int max[MAX_P][MAX_R];
    int allot[MAX_P][MAX_R];

    printf("Enter allocation matrix (%d x %d):\n", n, m);
    for (i = 0; i < n; i++)
        for (j = 0; j < m; j++)
            scanf("%d", &allot[i][j]);

    printf("Enter maximum demand matrix (%d x %d):\n", n, m);
    for (i = 0; i < n; i++)
        for (j = 0; j < m; j++)
            scanf("%d", &max[i][j]);

    printf("Enter available resources (length %d):\n", m);
    for (j = 0; j < m; j++)
        scanf("%d", &avail[j]);

    // Initial safety check
    isSafe(n, m, avail, max, allot);

    // Handle requests
    while (1) {
        int pid;
        printf("\nEnter process id making request (-1 to exit): ");
        scanf("%d", &pid);
        if (pid == -1) break;

        int req[MAX_R];
        printf("Enter request vector (length %d): ", m);
        for (j = 0; j < m; j++)
            scanf("%d", &req[j]);

        requestResources(n, m, pid, req, avail, max, allot);
    }

    return 0;
}
