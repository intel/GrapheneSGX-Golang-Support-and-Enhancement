#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define SRV_IP "127.0.0.1"
#define PORT 9930
#define BUFLEN 512
#define NPACK 10

in_port_t port = PORT;
enum { SINGLE, PARALLEL } mode = PARALLEL;
int do_fork = 0;

int pipefds[2];

int server(void)
{
    struct sockaddr_in si_me, si_other;
    int s, i;
    socklen_t slen = sizeof(si_other);
    char buf[BUFLEN];

    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1) {
        fprintf(stderr, "socket() failed\n");
        exit(EXIT_FAILURE);
    }

    if (mode == PARALLEL) {
        int optval = 0;
        if (setsockopt(s, SOL_IP, IP_BIND_ADDRESS_NO_PORT,
                       &optval, sizeof(optval)) < 0) {
            perror("setcokopt");
            exit(EXIT_FAILURE);
        }
        port = 0;
    }

    memset((char *) &si_me, 0, sizeof(si_me));
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(port);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *) &si_me, sizeof(si_me))==-1) {
        fprintf(stderr, "bind() failed\n");
        exit(EXIT_FAILURE);
    }

    if (mode == PARALLEL) {
        socklen_t len = sizeof(si_me);
        if (getsockname(s, (struct sockaddr *) &si_me, &len) < 0) {
            perror("getsockname");
            exit(EXIT_FAILURE);
        }
        port = ntohs(si_me.sin_port);
        printf("server: port %d\n", port);
    }

    if (mode == PARALLEL) {
        close(pipefds[0]);
        write(pipefds[1], &port, sizeof(port));
    }

    if (do_fork) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            exit(EXIT_FAILURE);
        }

        if (pid > 0) {
            close(s);
            if (wait(NULL) < 0) {
                perror("server: wait");
                exit(EXIT_FAILURE);
            }
            return 0;
        }
    }

    for (i=0; i<NPACK; i++) {
        if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other,
                     &slen)==-1) {
            fprintf(stderr, "recvfrom() failed\n");
            exit(EXIT_FAILURE);
        }

        printf("server: Received packet from %s:%d\nData: %s\n",
               inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port), buf);
    }

    if (close(s) < 0)
        perror("server: close");
    if (do_fork)
        exit(EXIT_SUCCESS);
    return 0;
}

int client(void)
{
    struct sockaddr_in si_other;
    int s, i;
    socklen_t slen = sizeof(si_other);
    char buf[BUFLEN]= "hi";
    int res;

    if (mode == PARALLEL) {
        close(pipefds[1]);
        read(pipefds[0], &port, sizeof(port));
    }
    printf("client: port %d\n", port);

    if ((s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))==-1) {
        fprintf(stderr, "socket() failed\n");
        exit(EXIT_FAILURE);
    }

    if (do_fork) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("client: fork");
            exit(EXIT_FAILURE);
        }

        if (pid > 0) {
            close(s);
            if (wait(NULL) < 0) {
                perror("wait");
                exit(EXIT_FAILURE);
            }
            return 0;
        }
    }

    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(port);
    if (inet_aton(SRV_IP, &si_other.sin_addr)==0) {
        fprintf(stderr, "inet_aton() failed\n");
        exit(EXIT_FAILURE);
    }

    for (i=0; i<10; i++) {
        printf("client: Sending packet %d\n", i);
        sprintf(buf, "This is packet %d", i);
        if ( (res = sendto(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other,
                           slen))== -1) {
            fprintf(stderr, "sendto() failed\n");
            exit(EXIT_FAILURE);
        }
    }

    close(s);
    if (do_fork)
        exit(EXIT_SUCCESS);
    return 0;
}

int main(int argc, char ** argv)
{
    if (argc > 1) {
        if (strcmp(argv[1], "client") == 0) {
            mode = SINGLE;
            client();
            return EXIT_SUCCESS;
        }

        if (strcmp(argv[1], "server") == 0) {
            mode = SINGLE;
            server();
            return EXIT_SUCCESS;
        }

        if (strcmp(argv[1], "fork") == 0) {
            do_fork = 1;
            goto old;
        }
    }
    else {
old:
        pipe(pipefds);

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            exit(EXIT_FAILURE);
        }

        if (pid == 0)
            client();
        else {
            server();
            waitpid(pid, NULL, -1);
        }
    }

    return EXIT_SUCCESS;
}
