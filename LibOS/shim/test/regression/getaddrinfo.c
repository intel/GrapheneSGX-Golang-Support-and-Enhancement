#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

int
fetch_ifaddrs(int fd);

int
fetch_ifaddrs(int fd)
{
#ifdef PAGE_SIZE
    const size_t buf_size = PAGE_SIZE;
#else
    const size_t buf_size = 4096;
#endif
    char buf[buf_size];
    int done = 0;
    char addr_str[buf_size];
    struct req
    {
        struct nlmsghdr nlh;
        struct rtgenmsg g;
        char pad[3];
    } req;
    struct sockaddr_nl nladdr;
    req.nlh.nlmsg_len = sizeof (req);
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
    req.nlh.nlmsg_pid = 0;
    req.nlh.nlmsg_seq = time (NULL);
    req.g.rtgen_family = AF_UNSPEC;
    assert (sizeof (req) - offsetof (struct req, pad) == 3);
    memset (req.pad, '\0', sizeof (req.pad));
    memset (&nladdr, '\0', sizeof (nladdr));
    nladdr.nl_family = AF_NETLINK;
    struct iovec iov = { buf, buf_size };
    if (sendto (fd, (void *) &req, sizeof (req), 0,
                (struct sockaddr *) &nladdr,
                sizeof (nladdr)) < 0)
        goto out_fail;

    do {
        struct msghdr msg =
            {
                .msg_name = (void *) &nladdr,
                .msg_namelen =  sizeof (nladdr),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = NULL,
                .msg_controllen = 0,
                .msg_flags = 0
            };
        ssize_t read_len = recvmsg (fd, &msg, 0);
        if (read_len < 0)
            goto out_fail;
        if (msg.msg_flags & MSG_TRUNC)
            goto out_fail;
        struct nlmsghdr *nlmh;
        for (nlmh = (struct nlmsghdr *) buf;
             NLMSG_OK (nlmh, (size_t) read_len);
             nlmh = (struct nlmsghdr *) NLMSG_NEXT (nlmh, read_len))
        {
            if (nladdr.nl_pid != 0
                || nlmh->nlmsg_seq != req.nlh.nlmsg_seq)
                continue;
            if (nlmh->nlmsg_type == RTM_NEWADDR)
            {
                struct ifaddrmsg *ifam = (struct ifaddrmsg *) NLMSG_DATA (nlmh);
                struct rtattr *rta = IFA_RTA (ifam);
                size_t len = nlmh->nlmsg_len - NLMSG_LENGTH (sizeof (*ifam));
                if (ifam->ifa_family != AF_INET
                    && ifam->ifa_family != AF_INET6)
                    continue;
                const void *local = NULL;
                const void *address = NULL;
                while (RTA_OK (rta, len))
                {
                    switch (rta->rta_type)
                    {
                    case IFA_LOCAL:
                        local = RTA_DATA (rta);
                        break;
                    case IFA_ADDRESS:
                        address = RTA_DATA (rta);
                        goto out;
                    }
                    rta = RTA_NEXT (rta, len);
                }
                if (local != NULL)
                {
                    address = local;
                out:
                    printf("AF_INET: %s\n",
                           inet_ntop(ifam->ifa_family,address,addr_str, buf_size));
                }
            }
            else if (nlmh->nlmsg_type == NLMSG_DONE) {
                /* We found the end, leave the loop.  */
                done = 1;
                printf ("netlink message done.\n");
            }
        }
    }
    while (! done);
    return 0;
 out_fail:
    return -1;
}

int main (void)
{
    int ret = -1;
    printf ("Testing netlink protocol in bind way.\n");
    int fd = socket (PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd > 0) {
        struct sockaddr_nl nladdr;
        memset (&nladdr, '\0', sizeof (nladdr));
        nladdr.nl_family = AF_NETLINK;
        
        if (bind (fd, (struct sockaddr *) &nladdr, sizeof (nladdr)) == 0)
            ret = fetch_ifaddrs(fd);
        close(fd);
        assert(ret == 0);
    }
    printf ("Testing netlink protocol in connect way.\n");
    fd = socket (PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd > 0) {
        struct sockaddr_nl nladdr;
        memset (&nladdr, '\0', sizeof (nladdr));
        nladdr.nl_family = AF_NETLINK;
        
        if (connect (fd, (struct sockaddr *) &nladdr, sizeof (nladdr)) == 0)
            ret = fetch_ifaddrs(fd);
        close(fd);
        assert(ret == 0);
    }
    printf ("TEST netlink protocol in both bind and connect ways... SUCCESS\n");
    return ret;
}
