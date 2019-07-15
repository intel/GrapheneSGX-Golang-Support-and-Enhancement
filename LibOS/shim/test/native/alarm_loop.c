/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>

volatile bool loop = true;
volatile int count = 0;

void handler (int signal)
{
    count++;
    int s = count;
    printf("alarm goes off count = %d &s = %p s = %d\n", count, &s, s);
    fflush(stdout);
    loop = false;
    alarm(1);
    if (count % 2) {
        time_t begin = time(NULL);
        time_t now = time(NULL);
        while (now - begin < 3) {
#if 1
            for (volatile unsigned long i = 0; i < 10000000UL; i++) {
                /* do nothing */
            }
#endif
            now = time(NULL);
        }
    } else {
        sleep(3);
    }
    printf("finish alarm handler count = %d &s = %p s = %d\n", count, &s, s);
    fflush(stdout);
}

int main(int argc, char ** argv)
{
    signal(SIGALRM, &handler);

    alarm(1);
    sleep(3);

    alarm(1);
    while (loop) {
        ;
    }
    printf("done exiting\n");
    return 0;
}
