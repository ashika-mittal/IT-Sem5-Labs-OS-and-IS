#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Function to sort an array (for LOOK)
void sort(int arr[], int n) {
    for (int i = 0; i < n - 1; i++)
        for (int j = 0; j < n - i - 1; j++)
            if (arr[j] > arr[j + 1]) {
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
}

// ----------------------
// FCFS Algorithm
// ----------------------
void FCFS(int req[], int n, int head) {
    int total = 0;
    printf("\nFCFS Disk Scheduling Order: %d", head);
    for (int i = 0; i < n; i++) {
        printf(" -> %d", req[i]);
        total += abs(head - req[i]);
        head = req[i];
    }
    printf("\nTotal Head Movement: %d\n", total);
}

// ----------------------
// LOOK Algorithm
// ----------------------
void LOOK(int req[], int n, int head) {
    int total = 0;
    int temp[n + 1], size = 0;

    // Copy requests and include head
    for (int i = 0; i < n; i++) temp[size++] = req[i];
    temp[size++] = head;
    sort(temp, size);

    int pos = 0;
    while (temp[pos] != head) pos++;

    // Automatically decide direction toward the nearest end
    int dir = (head - temp[0] < temp[size - 1] - head) ? -1 : 1;

    printf("\nLOOK Disk Scheduling Order (Auto Direction: toward %s end): %d",
           (dir == -1) ? "lower" : "higher", head);

    if (dir == -1) {
        // Move left
        for (int i = pos - 1; i >= 0; i--) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
        // Then reverse direction
        for (int i = pos + 1; i < size; i++) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
    } else {
        // Move right
        for (int i = pos + 1; i < size; i++) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
        // Then reverse direction
        for (int i = pos - 1; i >= 0; i--) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
    }

    printf("\nTotal Head Movement: %d\n", total);
}

// ----------------------
// Main Program
// ----------------------
int main() {
    int n, choice, head, tail;

    printf("Enter number of requests: ");
    scanf("%d", &n);
    int req[n];

    printf("Enter request sequence:\n");
    for (int i = 0; i < n; i++)
        scanf("%d", &req[i]);

    printf("Enter the initial head position: ");
    scanf("%d", &head);
    printf("Enter the position of the tail track: ");
    scanf("%d", &tail); // tail not used in LOOK but kept for consistency

    do {
        printf("\n--- Disk Scheduling Menu ---\n");
        printf("1. FCFS\n2. LOOK\n3. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: FCFS(req, n, head); break;
            case 2: LOOK(req, n, head); break;
            case 3: printf("Exiting...\n"); break;
            default: printf("Invalid choice!\n");
        }
    } while (choice != 3);

    return 0;
}
'''
Enter number of requests: 8
Enter request sequence:
95
180
34
119
11
123
62
64
Enter the initial head position: 50
Enter the position of the tail track: 199

--- Disk Scheduling Menu ---
1. FCFS
2. LOOK
3. Exit
Enter your choice: 1

FCFS Disk Scheduling Order: 50 -> 95 -> 180 -> 34 -> 119 -> 11 -> 123 -> 62 -> 64
Total Head Movement: 644

--- Disk Scheduling Menu ---
1. FCFS
2. LOOK
3. Exit
Enter your choice: 2

LOOK Disk Scheduling Order (Auto Direction: toward lower end): 50 -> 34 -> 11 -> 62 -> 64 -> 95 -> 119 -> 123 -> 180
Total Head Movement: 208

--- Disk Scheduling Menu ---
1. FCFS
2. LOOK
3. Exit
Enter your choice: 3
Exiting...
'''