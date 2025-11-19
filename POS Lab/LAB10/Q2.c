#include <stdio.h>
#include <stdlib.h>

// Function to check if a page is in frames
int isInFrames(int *frames, int frameCount, int page) {
    for (int i = 0; i < frameCount; i++) {
        if (frames[i] == page) return 1;
    }
    return 0;
}

// Function to find LRU page index
int findLRU(int *lastUsed, int frameCount) {
    int min = lastUsed[0], pos = 0;
    for (int i = 1; i < frameCount; i++) {
        if (lastUsed[i] < min) {
            min = lastUsed[i];
            pos = i;
        }
    }
    return pos;
}

// LRU Page Replacement Simulation
void lruPageReplacement(int *pages, int n, int frameCount) {
    int *frames = (int *)malloc(frameCount * sizeof(int));
    int *lastUsed = (int *)malloc(frameCount * sizeof(int)); // store last used time
    for (int i = 0; i < frameCount; i++) {
        frames[i] = -1; // empty
        lastUsed[i] = -1;
    }

    int pageFaults = 0, time = 0;

    printf("\n--- LRU Page Replacement ---\n");

    for (int i = 0; i < n; i++) {
        int page = pages[i];
        time++;

        if (isInFrames(frames, frameCount, page)) {
            // Update last used time for this page
            for (int j = 0; j < frameCount; j++) {
                if (frames[j] == page) {
                    lastUsed[j] = time;
                    break;
                }
            }
        } else {
            // Page fault
            int j;
            for (j = 0; j < frameCount; j++) {
                if (frames[j] == -1) {
                    // Empty frame found
                    frames[j] = page;
                    lastUsed[j] = time;
                    break;
                }
            }
            if (j == frameCount) {
                // No empty frame, replace LRU page
                int pos = findLRU(lastUsed, frameCount);
                frames[pos] = page;
                lastUsed[pos] = time;
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

    printf("Total Page Faults (LRU): %d\n", pageFaults);

    free(frames);
    free(lastUsed);
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

    lruPageReplacement(pages, n, frameCount);

    free(pages);
    return 0;
}
