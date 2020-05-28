/*
   This file is part of Graphene Library OS.
   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.
   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * rune_pal.h
 *
 * This file contains definition of API.
 */

#ifndef __RUNE_PAL_H__
#define __RUNE_PAL_H__

#include <stddef.h>
#include <errno.h>

#include <pal_linux.h>
#include <pal_linux_error.h>
#include <pal_rtld.h>
#include <pal_security.h>
#include <hex.h>

#include "debugger/sgx_gdb.h"
#include "sgx_enclave.h"
#include "sgx_internal.h"
#include "sgx_tls.h"

#include <asm/fcntl.h>
#include <asm/socket.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <asm/errno.h>
#include <ctype.h>

#include <sysdep.h>
#include <sysdeps/generic/ldsodefs.h>
#include <libgen.h>
#include <string.h>

static const int CURRENT_PAL_VERSION = 0x1;

#ifdef __cplusplus
extern "C" {
#endif

struct pal_attr_t {
    const char *instance_dir;
    const char *log_level;
};

struct stdio_fds {
    int stdin, stdout, stderr;
};

/*
 * @return:     <=0: invalid
 *              >0: current version number.
 */
int gsgx_pal_version();

/*
 * @param:      instance_path: LibOS instance file path.
 * @return:     0: success
 *              ENOENT: not exist
 *              other: customized by LibOS
 */
int gsgx_pal_init(struct pal_attr_t *attr);

/*
 * @param:      path: being executed binary file path, relative in LibOS filesystem.
 *              argv: arguments of binary.
 *              exit_value: exit code.
 *              stdin_fd: file descriptor of standard input.
 *              stdout_fd: file descriptor of standard output.
 *              stderr_fd: file descriptor of standard error.
 * @return:     0: success
 *              ENOENT: not exist
 *              EACCESS: access error
 *              ENOEXEC: not an executable
 *              ENOMEM: memory is not enough
 *              EINVAL: other error
 *              other: customized by LibOS
 */
int gsgx_pal_exec(char *path, char *argv[], struct stdio_fds *stdio, int *exit_value);

/*
 * @param:      sig: signal number
 *              pid: process id of target, -1 means all.
 * @return:     0: success
 *              EINVAL: invalid signal number.
 *              ESRCH: invalid process id.
 *              EPERM: signal cannot be delivered
 *              ENOSYS: un-implemented
 *              other: customized by LibOS
 */
int gsgx_pal_kill(int sig, int pid);

/*
 * @param:      none
 * @return:     0: success
 *              ENOSYS: un-implemented
 *              other: customized by LibOS
 */
int gsgx_pal_destroy();

/*
 * @param:      targetinfo: sgx_target_info_t
 *              targetinfo_len: data length of targetinfo
 *              report_data:
 *              report_data_len: data length of report_data
 *              report: sgx_report_t
 *              report_len: data length of report
 * @return:     0: success
 *              EAGAIN: report buffer too small, retry and get actual length by report_len.
 *              ENOSYS: un-implemented
 *              other: customized by LibOS
 */
int gsgx_pal_get_report(void *targetinfo, size_t targetinfo_len, void *report_data, size_t report_data_len, void *report, size_t *report_len);

char * resolve_absolute_uri(const char *uri, const char *dir);
char * resolve_manifest_uri(const char *exec_uri);

//
// import from sgx_main.c
//
extern int load_manifest (int fd, struct config_store ** config_ptr);
extern void __attribute__ ((noinline)) force_linux_to_grow_stack();
extern int get_cpu_count(void);
extern char * resolve_uri (const char * uri, const char ** errstring);
extern int initialize_enclave (struct pal_enclave * enclave);
extern char * resolve_uri (const char * uri, const char ** errstring);
extern char * alloc_concat(const char * p, size_t plen, const char * s, size_t slen);
extern int load_enclave (struct pal_enclave * enclave,
                         int manifest_fd,
                         char * manifest_uri,
                         char * exec_uri,
                         char * args, size_t args_size,
                         char * env, size_t env_size,
                         bool exec_uri_inferred);
#ifdef __cplusplus
}
#endif

#define UNUSED(var) ((void)(var))

#endif // __RUNE_PAL_H__