#include <stdio.h>
#include <stdlib.h>
#include <math.h>

void sort(int arr[], int n) {
    for (int i = 0; i < n - 1; i++)
        for (int j = 0; j < n - i - 1; j++)
            if (arr[j] > arr[j + 1]) {
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
}

void SSTF(int req[], int n, int head) {
    int done[n], total = 0;
    for (int i = 0; i < n; i++) done[i] = 0;

    printf("\nSSTF Disk Scheduling Order: %d", head);
    for (int i = 0; i < n; i++) {
        int min = 9999, idx = -1;
        for (int j = 0; j < n; j++) {
            if (!done[j] && abs(head - req[j]) < min) {
                min = abs(head - req[j]);
                idx = j;
            }
        }
        total += abs(head - req[idx]);
        head = req[idx];
        done[idx] = 1;
        printf(" -> %d", head);
    }
    printf("\nTotal Head Movement: %d\n", total);
}

void SCAN(int req[], int n, int head, int tail) {
    int total = 0, dir; 
    int temp[n + 2], size = 0;

    for (int i = 0; i < n; i++) temp[size++] = req[i];
    temp[size++] = head;
    temp[size++] = 0;
    temp[size++] = tail;
    sort(temp, size);

    int pos = 0;
    while (temp[pos] != head) pos++;

    // Choose direction automatically toward nearest end
    dir = (head - 0 < tail - head) ? -1 : 1;
    printf("\nSCAN Disk Scheduling Order (Auto Direction: toward %s end): %d", 
           (dir == -1) ? "lower" : "higher", head);

    if (dir == -1) {
        for (int i = pos - 1; i >= 0; i--) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
        for (int i = pos + 1; i < size; i++) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
    } else {
        for (int i = pos + 1; i < size; i++) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
        for (int i = pos - 1; i >= 0; i--) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
    }
    printf("\nTotal Head Movement: %d\n", total);
}

void CSCAN(int req[], int n, int head, int tail) {
    int total = 0, dir;
    int temp[n + 3], size = 0;

    for (int i = 0; i < n; i++) temp[size++] = req[i];
    temp[size++] = head;
    temp[size++] = 0;
    temp[size++] = tail;
    sort(temp, size);

    int pos = 0;
    while (temp[pos] != head) pos++;

    dir = (head - 0 < tail - head) ? -1 : 1;
    printf("\nC-SCAN Disk Scheduling Order (Adaptive): %d", head);

    if (dir == -1) {
        // Move toward lower end
        for (int i = pos - 1; i >= 0; i--) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
        // Jump to other end (jump not counted)
        head = tail;
        printf(" -> (jump) -> %d", head);
        for (int i = size - 2; i > pos; i--) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
    } else {
        // Move toward higher end
        for (int i = pos + 1; i < size; i++) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
        // Jump to other end (jump not counted)
        head = 0;
        printf(" -> (jump) -> %d", head);
        for (int i = 1; i < pos; i++) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
    }
    printf("\nTotal Head Movement: %d\n", total);
}

void CLOOK(int req[], int n, int head) {
    int total = 0, dir;
    int temp[n + 1], size = 0;

    for (int i = 0; i < n; i++) temp[size++] = req[i];
    temp[size++] = head;
    sort(temp, size);

    int pos = 0;
    while (temp[pos] != head) pos++;

    dir = (head - temp[0] < temp[size - 1] - head) ? -1 : 1;
    printf("\nC-LOOK Disk Scheduling Order (Adaptive): %d", head);

    if (dir == -1) {
        // Move left to smallest
        for (int i = pos - 1; i >= 0; i--) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
        // Jump to highest request (jump not counted)
        head = temp[size - 1];
        printf(" -> (jump) -> %d", head);
        for (int i = size - 2; i > pos; i--) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
    } else {
        // Move right to largest
        for (int i = pos + 1; i < size; i++) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
        // Jump to smallest request (jump not counted)
        head = temp[0];
        printf(" -> (jump) -> %d", head);
        for (int i = 1; i < pos; i++) {
            printf(" -> %d", temp[i]);
            total += abs(head - temp[i]);
            head = temp[i];
        }
    }
    printf("\nTotal Head Movement: %d\n", total);
}

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
    scanf("%d", &tail);

    do {
        printf("\n--- Disk Scheduling Menu ---\n");
        printf("1. SSTF\n2. SCAN\n3. C-SCAN\n4. C-LOOK\n5. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: SSTF(req, n, head); break;
            case 2: SCAN(req, n, head, tail); break;
            case 3: CSCAN(req, n, head, tail); break;
            case 4: CLOOK(req, n, head); break;
            case 5: printf("Exiting...\n"); break;
            default: printf("Invalid choice!\n");
        }
    } while (choice != 5);

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
1. SSTF
2. SCAN
3. C-SCAN
4. C-LOOK
5. Exit
Enter your choice: 1

SSTF Disk Scheduling Order: 50 -> 62 -> 64 -> 34 -> 11 -> 95 -> 119 -> 123 -> 180
Total Head Movement: 236

--- Disk Scheduling Menu ---
1. SSTF
2. SCAN
3. C-SCAN
4. C-LOOK
5. Exit
Enter your choice: 2

SCAN Disk Scheduling Order (Auto Direction: toward lower end): 50 -> 34 -> 11 -> 0 -> 62 -> 64 -> 95 -> 119 -> 123 -> 180 -> 199
Total Head Movement: 249

--- Disk Scheduling Menu ---
1. SSTF
2. SCAN
3. C-SCAN
4. C-LOOK
5. Exit
Enter your choice: 3

C-SCAN Disk Scheduling Order (Adaptive): 50 -> 34 -> 11 -> 0 -> (jump) -> 199 -> 180 -> 123 -> 119 -> 95 -> 64 -> 62
Total Head Movement: 187

--- Disk Scheduling Menu ---
1. SSTF
2. SCAN
3. C-SCAN
4. C-LOOK
5. Exit
Enter your choice: 4

C-LOOK Disk Scheduling Order (Adaptive): 50 -> 34 -> 11 -> (jump) -> 180 -> 123 -> 119 -> 95 -> 64 -> 62
Total Head Movement: 157

--- Disk Scheduling Menu ---
1. SSTF
2. SCAN
3. C-SCAN
4. C-LOOK
5. Exit
Enter your choice: 5
Exiting...
'''