/* copied from http://www.daniweb.com/software-development/c/threads/179814 */

#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define SRV_BIND_IP "0.0.0.0"
#define SRV_IP "127.0.0.1"
#define PORT 9930

in_port_t port = PORT;
const char * fname;

enum { SINGLE, PARALLEL } mode = PARALLEL;
int do_fork = 0;

int pipefds[2];

int server(void)
{
    int create_socket, new_socket, fd;
    socklen_t addrlen;
    size_t bufsize = 1024;
    char * buffer = malloc(bufsize);
    struct sockaddr_in address;

    create_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (create_socket < 0) {
        perror("server socket");
        exit(EXIT_FAILURE);
    }
    printf("server: The socket was created\n");

    if (mode == PARALLEL) {
        int optval = 0;
        if (setsockopt(create_socket, SOL_IP, IP_BIND_ADDRESS_NO_PORT,
                       &optval, sizeof(optval)) < 0) {
            perror("setcokopt");
            exit(EXIT_FAILURE);
        }
        port = 0;
    }

    address.sin_family = AF_INET;
    inet_pton(AF_INET, SRV_BIND_IP, &(address.sin_addr));
    address.sin_port = htons(port);

    if (bind(create_socket, (struct sockaddr *) &address,
             sizeof(address)) < 0) {
        perror("bind");
        close(create_socket);
        exit(EXIT_FAILURE);
    }

    if (mode == PARALLEL) {
        socklen_t len = sizeof(address);
        if (getsockname(
                create_socket, (struct sockaddr *) &address, &len) < 0) {
            perror("getsockname");
            exit(EXIT_FAILURE);
        }
        port = ntohs(address.sin_port);
        printf("server: port %d\n", port);
    }

    if (listen(create_socket, 3) < 0) {
        perror("listen");
        close(create_socket);
        exit(EXIT_FAILURE);
    }

    if (mode == PARALLEL) {
        close(pipefds[0]);
        write(pipefds[1], &port, sizeof(port));
    }

    addrlen = sizeof(address);
    new_socket = accept(create_socket, (struct sockaddr *) &address,
                        &addrlen);

    if (new_socket < 0) {
        perror("accept");
        close(create_socket);
        exit(EXIT_FAILURE);
    }

    if (close(create_socket) < 0) {
        perror("close(create_socket)");
        exit(EXIT_FAILURE);
    }

    if (do_fork) {
        pid_t pid = fork();
        if (pid) {
            perror("server fork");
            exit(EXIT_FAILURE);
        }
        if (pid > 0) {
            close(new_socket);
            wait(NULL);
            return 0;
        }
    }

    char buff[18] = {'\0'};
    if (inet_ntop(AF_INET, &address.sin_addr, buff, 18) <= 0) {
        perror("address conversion");
        exit(EXIT_FAILURE);
    }

    printf("server: The client %s is connected...\n", buff);

    if ((fd = open(fname, O_RDONLY, 0)) < 0) {
        perror("file open failed");
        close(new_socket);
        close(create_socket);
        exit(EXIT_FAILURE);
    }

    while (true) {
        size_t conn = read(fd, buffer, bufsize);
        if (conn < 0) {
            perror("server read");
            exit(EXIT_FAILURE);
        }
        if (conn == 0)
            break;
        if (sendto(new_socket, buffer, conn, 0, 0, 0) < 0) {
            perror("server sendto");
            exit(EXIT_FAILURE);
        }
    }

    printf("server: Request completed\n");

    close(new_socket);
    if (do_fork)
        exit(EXIT_SUCCESS);
    return 0;
}

int client(void)
{
    int create_socket;
    size_t bufsize = 1024;
    char * buffer = malloc(bufsize);
    struct sockaddr_in address;

    if (mode == PARALLEL) {
        close(pipefds[1]);
        read(pipefds[0], &port, sizeof(port));
    }

    create_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (create_socket < 0) {
        perror("client socket");
        exit(EXIT_FAILURE);
    }
    printf("client: The Socket was created\n");

    address.sin_family = AF_INET;
    inet_pton(AF_INET, SRV_IP, &address.sin_addr);
    address.sin_port = ntohs(port);
    printf("client: port %d\n", port);
    if (connect(create_socket, (struct sockaddr *) &address,
                sizeof(address)) == 0) {
        printf("client: The connection was accepted with the server\n");
    } else {
        perror("connect");
        exit(EXIT_SUCCESS);
    }

    if (do_fork) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("client fork");
            exit(EXIT_FAILURE);
        }
        if (pid > 0) {
            close(create_socket);
            wait(NULL);
            return 0;
        }
    }

    printf("client: Content:\n");

    while (true) {
        size_t count = recv(create_socket, buffer, bufsize, 0);
        if (count < 0) {
            perror("client recv");
            exit(EXIT_FAILURE);
        }
        if (count == 0)
            break;

        count = write(1, buffer, count);
        if (count < 0) {
            perror("client write");
            exit(EXIT_FAILURE);
        }
        if (count == 0)
            break;
    }

    printf("client: EOF\n");

    buffer[0] = 0;
    close(create_socket);
    if (do_fork)
        exit(EXIT_SUCCESS);
    return 0;
}

int main(int argc, char ** argv)
{
    char fnamebuf[40];
    strcpy(fnamebuf, argv[0]);
    strcat(fnamebuf, ".c");
    fname = fnamebuf;

    setvbuf(stdout, NULL, _IONBF, 0);

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
        if (pipe(pipefds) < 0) {
            perror("pipe");
            return EXIT_FAILURE;
        }

        int pid = fork();
        if (pid < 0) {
            perror("fork");
            return EXIT_FAILURE;
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
