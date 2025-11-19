#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

#define BUFFER_SIZE 5   // bounded buffer size

int buffer[BUFFER_SIZE];
int in = 0, out = 0;   // buffer indices

sem_t empty;  // semaphore for empty slots
sem_t full;   // semaphore for full slots
pthread_mutex_t mutex; // mutex for buffer

void *producer(void *param) {
    int item, i;
    for (i = 0; i < 10; i++) {
        item = rand() % 100;   // produce an item

        sem_wait(&empty);      // wait for empty slot
        pthread_mutex_lock(&mutex);

        // critical section
        buffer[in] = item;
        printf("Producer produced %d at buffer[%d]\n", item, in);
        in = (in + 1) % BUFFER_SIZE;

        pthread_mutex_unlock(&mutex);
        sem_post(&full);       // signal full slot

        sleep(1);
    }
    pthread_exit(0);
}

void *consumer(void *param) {
    int item, i;
    for (i = 0; i < 10; i++) {
        sem_wait(&full);       // wait for full slot
        pthread_mutex_lock(&mutex);

        // critical section
        item = buffer[out];
        printf("Consumer consumed %d from buffer[%d]\n", item, out);
        out = (out + 1) % BUFFER_SIZE;

        pthread_mutex_unlock(&mutex);
        sem_post(&empty);      // signal empty slot

        sleep(2);
    }
    pthread_exit(0);
}

int main() {
    pthread_t prod, cons;

    // initialize semaphores and mutex
    sem_init(&empty, 0, BUFFER_SIZE);
    sem_init(&full, 0, 0);
    pthread_mutex_init(&mutex, NULL);

    // create producer and consumer threads
    pthread_create(&prod, NULL, producer, NULL);
    pthread_create(&cons, NULL, consumer, NULL);

    // wait for threads to finish
    pthread_join(prod, NULL);
    pthread_join(cons, NULL);

    // cleanup
    sem_destroy(&empty);
    sem_destroy(&full);
    pthread_mutex_destroy(&mutex);

    return 0;
}
/*
STUDENT@MIT-ICT-L11-06:~/230911332/LAB7$ gcc Q1.c -o Q1 -pthread
STUDENT@MIT-ICT-L11-06:~/230911332/LAB7$ ./Q1
Producer produced 83 at buffer[0]
Consumer consumed 83 from buffer[0]
Producer produced 86 at buffer[1]
Consumer consumed 86 from buffer[1]
Producer produced 77 at buffer[2]
Producer produced 15 at buffer[3]
Consumer consumed 77 from buffer[2]
Producer produced 93 at buffer[4]
Producer produced 35 at buffer[0]
Consumer consumed 15 from buffer[3]
Producer produced 86 at buffer[1]
Producer produced 92 at buffer[2]
Consumer consumed 93 from buffer[4]
Producer produced 49 at buffer[3]
Producer produced 21 at buffer[4]
Consumer consumed 35 from buffer[0]
Consumer consumed 86 from buffer[1]
Consumer consumed 92 from buffer[2]
Consumer consumed 49 from buffer[3]
Consumer consumed 21 from buffer[4]
*/