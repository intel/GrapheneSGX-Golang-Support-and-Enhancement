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
 * rune_pal.c
 *
 * This file contains API functions to support loading as a recyclable enclave.
 */

#include "rune_pal.h"

#include <libgen.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <signal.h>
#include <sysdeps/generic/setjmp.h>

extern struct pal_enclave pal_enclave;

int gsgx_pal_version()
{
    return CURRENT_PAL_VERSION;
}
int pal_version() __attribute__ ((weak, alias ("gsgx_pal_version")));

//
// @param:      instance_path is path of enclave (libpal.so)
//
int gsgx_pal_init(struct pal_attr_t *attr)
{
    const char *instance_path = attr->instance_dir;
    char *manifest_uri = NULL;
    char *exec_uri = NULL;
    int manifest_fd = -1;
    int ret = 0;

    if (!instance_path) {
        return -EINVAL;
    }

    exec_uri = alloc_concat(URI_PREFIX_FILE, URI_PREFIX_FILE_LEN, instance_path, (size_t)-1);
    if (!exec_uri) {
        return -EINVAL;
    }

    //
    // Resolve manifest
    //
    manifest_uri = resolve_manifest_uri(exec_uri);
    if (!manifest_uri) {
        ret = -EINVAL;
        goto cleanup;
    }

    manifest_fd = INLINE_SYSCALL(open, 3, manifest_uri + URI_PREFIX_FILE_LEN, O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(manifest_fd)) {
        SGX_DBG(DBG_E, "Cannot open manifest file: %s\n", manifest_uri);
        ret = -EINVAL;
        goto cleanup;
    }

    pal_enclave.manifest = manifest_fd;

    /* Deferred executable loading */
    ret = load_enclave(&pal_enclave, manifest_fd, manifest_uri, NULL, NULL, 0, NULL, 0, false);

cleanup:
    if (exec_uri) {
        free(exec_uri);
    }

    if (manifest_uri) {
        free(manifest_uri);
    }

    return ret;
}
int pal_init(struct pal_attr_t *attr) __attribute__ ((weak, alias ("gsgx_pal_init")));

inline int count_args(char *argv[])
{
    int argc = 0;

    while (argv && argv[argc]) {
        argc++;
    }

    return argc;
}

int gsgx_pal_exec(char *path, char *argv[], struct stdio_fds *stdio, int *exit_value)
{
    UNUSED(stdio);

    char *exec_uri = NULL;
    int ret = 0;
    int exitcode = 0;

    exec_uri = alloc_concat(URI_PREFIX_FILE, URI_PREFIX_FILE_LEN, path, (size_t)-1);
    if (!exec_uri) {
        return -ENOMEM;
    }

    pal_enclave.exec = INLINE_SYSCALL(open, 3, exec_uri + URI_PREFIX_FILE_LEN, O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(pal_enclave.exec)) {
        SGX_DBG(DBG_E, "Cannot open executable %s\n", exec_uri);
        free(exec_uri);
        return -EINVAL;
    }

    memcpy(pal_enclave.pal_sec.exec_name, exec_uri, strlen(exec_uri) + 1);
    free(exec_uri);

    int argc = count_args(argv);

    /* Create a new arguments array that placed 'path' into the first element. */
    char *_argv[argc + 1];
    _argv[0] = path;
    for (int i = 0; i < argc; i++) {
        _argv[i + 1] = argv[i];
    }
    argc++;
    char *args = _argv[0];
    size_t args_size = (_argv[argc - 1] - args) + strlen(_argv[argc - 1]) + 1;

    ret = sgx_signal_setup();
    if (ret < 0)
        return ret;

    void* alt_stack = (void*)INLINE_SYSCALL(mmap, 6, NULL, ALT_STACK_SIZE,
                                            PROT_READ | PROT_WRITE,
                                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (IS_ERR_P(alt_stack))
        return -ENOMEM;

    /* initialize TCB at the top of the alternative stack */
    PAL_TCB_URTS* tcb = alt_stack + ALT_STACK_SIZE - sizeof(PAL_TCB_URTS);
    pal_tcb_urts_init(
        tcb, /*stack=*/NULL, alt_stack); /* main thread uses the stack provided by Linux */
    pal_thread_init(tcb);

    SGX_DBG(DBG_I, "Ready to launch executable %s\n", exec_uri);

    if (setjmp(tcb->jmp) == 0) {
        /* setjmp return 0 when called directly */
        tcb->jmp_set = 1;
        /* start running trusted PAL */
        ecall_enclave_start(args, args_size, NULL, 0);
    } else {
        /* return from app */
        exitcode = tcb->exitcode;
    }

    SGX_DBG(DBG_I, "Executable %s exited\n", exec_uri);

#if PRINT_ENCLAVE_STAT == 1
    PAL_NUM exit_time = 0;
    INLINE_SYSCALL(gettimeofday, 2, &tv, NULL);
    exit_time = tv.tv_sec * 1000000UL + tv.tv_usec;
#endif

    unmap_tcs();
    INLINE_SYSCALL(munmap, 2, alt_stack, ALT_STACK_SIZE);

    if (exit_value) {
        *exit_value = exitcode;
    }

    return ret;
}
int pal_exec(char *path, char *argv[], struct stdio_fds *stdio, int *exit_value) __attribute__ ((weak, alias ("gsgx_pal_exec")));

int gsgx_pal_kill(int sig, int pid)
{
    UNUSED(sig);
    UNUSED(pid);

    if (pid == -1) {
        raise(sig);
    } else {
        kill(sig, pid);
    }

    return 0;
}
int pal_kill(int sig, int pid) __attribute__ ((weak, alias ("gsgx_pal_kill")));

int gsgx_pal_destroy()
{
    INLINE_SYSCALL(exit, 0);
    return 0;
}
int pal_destroy() __attribute__ ((weak, alias ("gsgx_pal_destroy")));

int gsgx_pal_get_report(void *targetinfo, size_t targetinfo_len, void *report_data, size_t report_data_len, void *report, size_t *report_len)
{
    UNUSED(targetinfo);
    UNUSED(targetinfo_len);
    UNUSED(report_data);
    UNUSED(report_data_len);
    UNUSED(report);
    UNUSED(report_len);

    return ENOSYS;
}
int pal_get_report(void *targetinfo, size_t targetinfo_len, void *report_data, size_t report_data_len, void *report, size_t *report_len) __attribute__ ((weak, alias ("gsgx_pal_get_report")));
