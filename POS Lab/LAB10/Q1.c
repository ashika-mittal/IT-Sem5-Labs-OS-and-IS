#include <stdio.h>
#include <stdlib.h>

// Function to check if a page is present in frames
int isInFrames(int *frames, int frameCount, int page) {
    for (int i = 0; i < frameCount; i++) {
        if (frames[i] == page) return 1;
    }
    return 0;
}

// FIFO Page Replacement
void fifoPageReplacement(int *pages, int n, int frameCount) {
    int *frames = (int *)malloc(frameCount * sizeof(int));
    for (int i = 0; i < frameCount; i++) frames[i] = -1;

    int pageFaults = 0, nextToReplace = 0;

    printf("\n--- FIFO Page Replacement ---\n");

    for (int i = 0; i < n; i++) {
        int page = pages[i];
        if (!isInFrames(frames, frameCount, page)) {
            frames[nextToReplace] = page;
            nextToReplace = (nextToReplace + 1) % frameCount;
            pageFaults++;
        }

        // Print frame state
        printf("Page %d -> ", page);
        for (int j = 0; j < frameCount; j++) {
            if (frames[j] != -1)
                printf("%d ", frames[j]);
            else
                printf("_ ");
        }
        printf("\n");
    }

    printf("Total Page Faults (FIFO): %d\n", pageFaults);
    free(frames);
}

// Function to predict the next use of a page for Optimal Algorithm
int predict(int *pages, int n, int *frames, int frameCount, int index) {
    int res = -1, farthest = index;

    for (int i = 0; i < frameCount; i++) {
        int j;
        for (j = index; j < n; j++) {
            if (frames[i] == pages[j]) {
                if (j > farthest) {
                    farthest = j;
                    res = i;
                }
                break;
            }
        }
        if (j == n)  // Not found in future
            return i;
    }

    return (res == -1) ? 0 : res;
}

// Optimal Page Replacement
void optimalPageReplacement(int *pages, int n, int frameCount) {
    int *frames = (int *)malloc(frameCount * sizeof(int));
    for (int i = 0; i < frameCount; i++) frames[i] = -1;

    int pageFaults = 0;

    printf("\n--- Optimal Page Replacement ---\n");

    for (int i = 0; i < n; i++) {
        int page = pages[i];

        if (!isInFrames(frames, frameCount, page)) {
            int j;
            for (j = 0; j < frameCount; j++) {
                if (frames[j] == -1) {
                    frames[j] = page;
                    break;
                }
            }
            if (j == frameCount) {
                int pos = predict(pages, n, frames, frameCount, i + 1);
                frames[pos] = page;
            }
            pageFaults++;
        }

        // Print frame state
        printf("Page %d -> ", page);
        for (int j = 0; j < frameCount; j++) {
            if (frames[j] != -1)
                printf("%d ", frames[j]);
            else
                printf("_ ");
        }
        printf("\n");
    }

    printf("Total Page Faults (Optimal): %d\n", pageFaults);
    free(frames);
}

int main() {
    int n, frameCount;

    printf("Enter number of pages in reference string: ");
    scanf("%d", &n);

    int *pages = (int *)malloc(n * sizeof(int));
    printf("Enter the reference string:\n");
    for (int i = 0; i < n; i++) {
        scanf("%d", &pages[i]);
    }

    printf("Enter number of frames: ");
    scanf("%d", &frameCount);

    fifoPageReplacement(pages, n, frameCount);
    optimalPageReplacement(pages, n, frameCount);

    free(pages);
    return 0;
}
/*
Enter number of pages in reference string: 12
Enter the reference string:
7
0
1
2
0
3
0
4
2
3
0
3
Enter number of frames: 3

--- FIFO Page Replacement ---
Page 7 -> 7 _ _ 
Page 0 -> 7 0 _ 
Page 1 -> 7 0 1 
Page 2 -> 2 0 1 
Page 0 -> 2 0 1 
Page 3 -> 2 3 1 
Page 0 -> 2 3 0 
Page 4 -> 4 3 0 
Page 2 -> 4 2 0 
Page 3 -> 4 2 3 
Page 0 -> 0 2 3 
Page 3 -> 0 2 3 
Total Page Faults (FIFO): 10

--- Optimal Page Replacement ---
Page 7 -> 7 _ _ 
Page 0 -> 7 0 _ 
Page 1 -> 7 0 1 
Page 2 -> 2 0 1 
Page 0 -> 2 0 1 
Page 3 -> 2 0 3 
Page 0 -> 2 0 3 
Page 4 -> 2 4 3 
Page 2 -> 2 4 3 
Page 3 -> 2 4 3 
Page 0 -> 0 4 3 
Page 3 -> 0 4 3 
Total Page Faults (Optimal): 7
*/