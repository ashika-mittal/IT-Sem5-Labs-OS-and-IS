#include <stdio.h>
#include <stdlib.h>

// Structure to represent a memory block
typedef struct {
    int size;
    int allocated;  // 0 = free, 1 = allocated
} Block;

// Structure to represent a process
typedef struct {
    int size;
    int blockAssigned; // index of block, -1 if not assigned
} Process;

// Function to implement First Fit strategy
void firstFit(Block *blocks, int m, Process *procs, int n) {
    printf("\n--- First Fit Allocation ---\n");
    for (int i = 0; i < n; i++) {
        procs[i].blockAssigned = -1;
        for (int j = 0; j < m; j++) {
            if (!blocks[j].allocated && blocks[j].size >= procs[i].size) {
                // Allocate this block
                procs[i].blockAssigned = j;
                blocks[j].allocated = 1;
                printf("Process %d (Size %d) allocated to Block %d (Size %d)\n",
                       i + 1, procs[i].size, j + 1, blocks[j].size);
                break;
            }
        }
        if (procs[i].blockAssigned == -1) {
            printf("Process %d (Size %d) not allocated\n", i + 1, procs[i].size);
        }
    }
}

// Function to implement Best Fit strategy
void bestFit(Block *blocks, int m, Process *procs, int n) {
    printf("\n--- Best Fit Allocation ---\n");
    for (int i = 0; i < n; i++) {
        procs[i].blockAssigned = -1;
        int bestIdx = -1;
        for (int j = 0; j < m; j++) {
            if (!blocks[j].allocated && blocks[j].size >= procs[i].size) {
                if (bestIdx == -1 || blocks[j].size < blocks[bestIdx].size) {
                    bestIdx = j;
                }
            }
        }
        if (bestIdx != -1) {
            procs[i].blockAssigned = bestIdx;
            blocks[bestIdx].allocated = 1;
            printf("Process %d (Size %d) allocated to Block %d (Size %d)\n",
                   i + 1, procs[i].size, bestIdx + 1, blocks[bestIdx].size);
        } else {
            printf("Process %d (Size %d) not allocated\n", i + 1, procs[i].size);
        }
    }
}

int main() {
    int m, n;

    printf("Enter number of memory blocks: ");
    scanf("%d", &m);
    Block *blocks1 = (Block *)malloc(m * sizeof(Block)); // For First Fit
    Block *blocks2 = (Block *)malloc(m * sizeof(Block)); // For Best Fit

    printf("Enter sizes of memory blocks:\n");
    for (int i = 0; i < m; i++) {
        scanf("%d", &blocks1[i].size);
        blocks1[i].allocated = 0;
        blocks2[i].size = blocks1[i].size;
        blocks2[i].allocated = 0;
    }

    printf("Enter number of processes: ");
    scanf("%d", &n);
    Process *procs1 = (Process *)malloc(n * sizeof(Process)); // For First Fit
    Process *procs2 = (Process *)malloc(n * sizeof(Process)); // For Best Fit

    printf("Enter sizes of processes:\n");
    for (int i = 0; i < n; i++) {
        scanf("%d", &procs1[i].size);
        procs2[i].size = procs1[i].size;
    }

    // Run First Fit
    firstFit(blocks1, m, procs1, n);

    // Run Best Fit
    bestFit(blocks2, m, procs2, n);

    // Free dynamically allocated memory
    free(blocks1);
    free(blocks2);
    free(procs1);
    free(procs2);

    return 0;
}
'''
student@cl20-06:~/Documents/230911332/LAB9$ ./Q1
Enter number of memory blocks: 5
Enter sizes of memory blocks:
100
500
200
300
600
Enter number of processes: 4
Enter sizes of processes:
212
417
112
426

--- First Fit Allocation ---
Process 1 (Size 212) allocated to Block 2 (Size 500)
Process 2 (Size 417) allocated to Block 5 (Size 600)
Process 3 (Size 112) allocated to Block 3 (Size 200)
Process 4 (Size 426) not allocated

--- Best Fit Allocation ---
Process 1 (Size 212) allocated to Block 4 (Size 300)
Process 2 (Size 417) allocated to Block 2 (Size 500)
Process 3 (Size 112) allocated to Block 3 (Size 200)
Process 4 (Size 426) allocated to Block 5 (Size 600)
'''