#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int id;
    int exec_time;   // Execution time
    int period;      // Period (for RM)
    int deadline;    // Relative deadline (for EDF)
    int remaining;   // Remaining execution time
    int next_deadline;
} Task;

void rateMonotonic(Task tasks[], int n, int hyperperiod) {
    int time = 0, completed = 0;

    // RM Priority: smaller period = higher priority
    for (int i = 0; i < n - 1; i++)
        for (int j = i + 1; j < n; j++)
            if (tasks[i].period > tasks[j].period) {
                Task tmp = tasks[i];
                tasks[i] = tasks[j];
                tasks[j] = tmp;
            }

    printf("\n--- Rate Monotonic Scheduling Simulation ---\n");
    printf("Time\tExecuting Task\n");

    while (time < hyperperiod) {
        int chosen = -1;

        // Reset tasks at start of each period
        for (int i = 0; i < n; i++) {
            if (time % tasks[i].period == 0)
                tasks[i].remaining = tasks[i].exec_time;
        }

        // Select the highest priority ready task
        for (int i = 0; i < n; i++) {
            if (tasks[i].remaining > 0) {
                chosen = i;
                break;
            }
        }

        if (chosen != -1) {
            printf("%d\tT%d\n", time, tasks[chosen].id);
            tasks[chosen].remaining--;
        } else {
            printf("%d\tIdle\n", time);
        }

        time++;
    }
}

void earliestDeadlineFirst(Task tasks[], int n, int hyperperiod) {
    int time = 0;

    // Initialize deadlines
    for (int i = 0; i < n; i++) {
        tasks[i].next_deadline = tasks[i].deadline;
        tasks[i].remaining = tasks[i].exec_time;
    }

    printf("\n--- Earliest Deadline First Scheduling Simulation ---\n");
    printf("Time\tExecuting Task\n");

    while (time < hyperperiod) {
        // Release tasks at start of period
        for (int i = 0; i < n; i++) {
            if (time % tasks[i].period == 0) {
                tasks[i].remaining = tasks[i].exec_time;
                tasks[i].next_deadline = time + tasks[i].deadline;
            }
        }

        // Choose task with earliest deadline
        int chosen = -1;
        int min_deadline = 9999;
        for (int i = 0; i < n; i++) {
            if (tasks[i].remaining > 0 && tasks[i].next_deadline < min_deadline) {
                min_deadline = tasks[i].next_deadline;
                chosen = i;
            }
        }

        if (chosen != -1) {
            printf("%d\tT%d\n", time, tasks[chosen].id);
            tasks[chosen].remaining--;
        } else {
            printf("%d\tIdle\n", time);
        }

        time++;
    }
}

int main() {
    int n, hyperperiod, choice;

    printf("Enter number of tasks: ");
    scanf("%d", &n);

    Task tasks[n];

    printf("Enter details for each task:\n");
    for (int i = 0; i < n; i++) {
        tasks[i].id = i + 1;
        printf("\nTask %d:\n", i + 1);
        printf("Execution time: ");
        scanf("%d", &tasks[i].exec_time);
        printf("Period: ");
        scanf("%d", &tasks[i].period);
        printf("Deadline (relative): ");
        scanf("%d", &tasks[i].deadline);
        tasks[i].remaining = tasks[i].exec_time;
    }

    printf("\nEnter hyperperiod (simulation duration): ");
    scanf("%d", &hyperperiod);

    do {
        printf("\n--- Real-Time Scheduling Menu ---\n");
        printf("1. Rate Monotonic (RM)\n");
        printf("2. Earliest Deadline First (EDF)\n");
        printf("3. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                rateMonotonic(tasks, n, hyperperiod);
                break;
            case 2:
                earliestDeadlineFirst(tasks, n, hyperperiod);
                break;
            case 3:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice!\n");
        }
    } while (choice != 3);

    return 0;
}
'''
Enter number of tasks: 3
Enter details for each task:

Task 1:
Execution time: 1
Period: 4
Deadline (relative): 4

Task 2:
Execution time: 2
Period: 5
Deadline (relative): 5

Task 3:
Execution time: 1
Period: 10
Deadline (relative): 10

Enter hyperperiod (simulation duration): 20

--- Real-Time Scheduling Menu ---
1. Rate Monotonic (RM)
2. Earliest Deadline First (EDF)
3. Exit
Enter your choice: 1

--- Rate Monotonic Scheduling Simulation ---
Time    Executing Task
0   T1
1   T2
2   T2
3   T3
4   T1
5   T2
6   T2
7   Idle
8   T1
9   Idle
10  T2
11  T2
12  T1
13  T3
14  Idle
15  T2
16  T1
17  T2
18  Idle
19  Idle

--- Real-Time Scheduling Menu ---
1. Rate Monotonic (RM)
2. Earliest Deadline First (EDF)
3. Exit
Enter your choice: 2

--- Earliest Deadline First Scheduling Simulation ---
Time    Executing Task
0   T1
1   T2
2   T2
3   T3
4   T1
5   T2
6   T2
7   Idle
8   T1
9   Idle
10  T2
11  T2
12  T1
13  T3
14  Idle
15  T2
16  T1
17  T2
18  Idle
19  Idle

--- Real-Time Scheduling Menu ---
1. Rate Monotonic (RM)
2. Earliest Deadline First (EDF)
3. Exit
Enter your choice: 3
Exiting...
'''