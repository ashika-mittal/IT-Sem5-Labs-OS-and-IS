#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

sem_t mutex;      // controls access to read_count
sem_t wrt;        // controls access to shared resource
int read_count = 0; // number of active readers

int data = 0;     // shared data (the "file")

void *reader(void *arg) {
    int id = *((int *)arg);
    while (1) {
        sem_wait(&mutex);
        read_count++;
        if (read_count == 1)
            sem_wait(&wrt);  // first reader locks writers
        sem_post(&mutex);

        // --- Reading section ---
        printf("Reader %d is reading data = %d\n", id, data);
        sleep(1);

        sem_wait(&mutex);
        read_count--;
        if (read_count == 0)
            sem_post(&wrt);  // last reader unlocks writers
        sem_post(&mutex);

        sleep(1);
    }
    return NULL;
}

void *writer(void *arg) {
    int id = *((int *)arg);
    while (1) {
        sem_wait(&wrt);  // wait for exclusive access

        // --- Writing section ---
        data++;
        printf("Writer %d is writing data = %d\n", id, data);
        sleep(1);

        sem_post(&wrt);  // release exclusive access

        sleep(2);
    }
    return NULL;
}

int main() {
    pthread_t rtid[5], wtid[2];
    int i, id[5] = {1,2,3,4,5}, wid[2] = {1,2};

    sem_init(&mutex, 0, 1);
    sem_init(&wrt, 0, 1);

    // create reader threads
    for (i = 0; i < 5; i++)
        pthread_create(&rtid[i], NULL, reader, &id[i]);

    // create writer threads
    for (i = 0; i < 2; i++)
        pthread_create(&wtid[i], NULL, writer, &wid[i]);

    // join threads (infinite loop, so program runs continuously)
    for (i = 0; i < 5; i++)
        pthread_join(rtid[i], NULL);
    for (i = 0; i < 2; i++)
        pthread_join(wtid[i], NULL);

    sem_destroy(&mutex);
    sem_destroy(&wrt);

    return 0;
}
/*
STUDENT@MIT-ICT-L11-06:~/230911332/LAB7$ ./Q2
Reader 2 is reading data = 0
Reader 5 is reading data = 0
Reader 1 is reading data = 0
Reader 4 is reading data = 0
Reader 3 is reading data = 0
Writer 1 is writing data = 1
Writer 2 is writing data = 2
Reader 5 is reading data = 2
Reader 2 is reading data = 2
Reader 1 is reading data = 2
Reader 4 is reading data = 2
Reader 3 is reading data = 2
Writer 1 is writing data = 3
Writer 2 is writing data = 4
Reader 2 is reading data = 4
Reader 5 is reading data = 4
Reader 1 is reading data = 4
Reader 4 is reading data = 4
Reader 3 is reading data = 4
Writer 1 is writing data = 5
Writer 2 is writing data = 6
Reader 2 is reading data = 6
Reader 5 is reading data = 6
Reader 1 is reading data = 6
Reader 4 is reading data = 6
Reader 3 is reading data = 6
^C
*/