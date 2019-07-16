#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <pthread.h>

const int N = 8;   // total threads
_Atomic int S = 0; // threads which have started
_Atomic int E = 8; // threads which have ended

void* thread(void* arg) {
    const int n = 1<<14;
    for (int i = 0; i < n; i++) {
        void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (m != MAP_FAILED) munmap(m,4096);
        if (i == n/8) S++;
    }
    E--;
    puts("thread done");
    return NULL;
}

int main() {
    pthread_t tids[N];
    for (int i = 0; i < N; i++) {
        if (0 != pthread_create(&tids[i], NULL, thread, NULL))
            return 1;
    }
    while (S < N) ; // wait for threads to be in-progress
    // while (E != 0) ; // wait for threads to complete
    puts("--------------- Done");
    return 0;
}
