#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>

void handler (int signal)
{
    int a;
    printf("alarm goes off %p\n", &a);
    fflush(stdout);
}

int main(int argc, char ** argv)
{
    signal(SIGALRM, &handler);
    //alarm(100 * 100);
    //sleep(3);
    struct timespec t = {
        .tv_sec = 3,
        .tv_nsec = 0
    };
    printf("&t %p\n", &t);
    fflush(stdout);
    alarm(1);
    nanosleep(&t, NULL);
    printf("done exiting\n");
    fflush(stdout);
    return 0;
}
