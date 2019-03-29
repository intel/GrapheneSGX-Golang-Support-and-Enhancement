#include <err.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

_Atomic int count = 0;

void handler(int signal, siginfo_t * info, void * ucontext)
{
    int ret;
    count++;

    stack_t old;
    printf("sig %d count %d goes off %p handler %p\n",
           signal, count, &old, handler);
    fflush(stdout);

    memset(&old, 0, sizeof(old));
    ret = sigaltstack(NULL, &old);
    if (ret < 0) {
        err(EXIT_FAILURE, "sigaltstack in handler");
    }
    if (old.ss_flags & SS_ONSTACK) {
        printf("FAIL on sigaltstack in handler\n");
    } else if (old.ss_flags & SS_DISABLE) {
        printf("OK on sigaltstack in handler\n");
    } else {
        printf("FAIL on sigaltstack in handler !SS_DISABLED\n");
    }

    if (count <= 2) {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGALRM);
        ret = sigprocmask(SIG_UNBLOCK, &set, NULL);
        if (ret) {
            err(EXIT_FAILURE, "sigprocmask");
        }
        raise(SIGALRM);
    }

    printf("sig returning sig %d count %d goes off %p handler %p\n",
           signal, count, &old, handler);
    fflush(stdout);

    count--;
}

int main(int argc, char ** argv)
{
    int ret;

    struct sigaction act;
    act.sa_sigaction = handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO | SA_NODEFER;
    ret = sigaction(SIGALRM, &act, NULL);
    if (ret < 0) {
        err(EXIT_FAILURE, "sigaction");
    }

    printf("&act %p handler %p\n", &act, &handler);
    fflush(stdout);
    alarm(1);
    pause();

    stack_t old;
    memset(&old, 0xff, sizeof(old));
    ret = sigaltstack(NULL, &old);
    if (ret < 0) {
        err(EXIT_FAILURE, "sigaltstack");
    }
    if (old.ss_flags & SS_ONSTACK) {
        printf("FAIL on sigaltstack in main thread\n");
    } else if (old.ss_flags & SS_DISABLE) {
        printf("OK on sigaltstack in main thread\n");
    } else {
        printf("FAIL on sigaltstack in main thread !SS_DISABLED\n");
    }

    printf("done exiting\n");
    fflush(stdout);
    return 0;
}
