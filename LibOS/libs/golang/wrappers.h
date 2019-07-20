#ifndef __GOLANG_WRAPPERS_H__
#define __GOLANG_WRAPPERS_H__

// These functions take unknown sets of arguments, so we do not declare the
// prototype as fn(void); but rather as fn ();
// Disable the strict warning just for these declarations.
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
void syscall_wrapper_arch_prctl();
void syscall_wrapper_brk();
void syscall_wrapper_clone();
void syscall_wrapper_close();
void syscall_wrapper_epoll_create();
void syscall_wrapper_epoll_create1();
void syscall_wrapper_epoll_ctl();
void syscall_wrapper_epoll_pwait();
void syscall_wrapper_exit();
void syscall_wrapper_exit_group();
void syscall_wrapper_fcntl();
void syscall_wrapper_futex();
void syscall_wrapper_getpid();
void syscall_wrapper_gettid();
void syscall_wrapper_kill();
void syscall_wrapper_madvise();
void syscall_wrapper_mincore();
void syscall_wrapper_mmap();
void syscall_wrapper_munmap();
void syscall_wrapper_openat();
void syscall_wrapper_pselect6();
void syscall_wrapper_read();
void syscall_wrapper_readlinkat();
void syscall_wrapper_rt_sigaction();
void syscall_wrapper_rt_sigprocmask();
void syscall_wrapper_rt_sigreturn();
void syscall_wrapper_sched_getaffinity();
void syscall_wrapper_sched_yield();
void syscall_wrapper_setittimer();
void syscall_wrapper_sigaltstack();
void syscall_wrapper_syscall();
void syscall_wrapper_syscall6();
void syscall_wrapper_tkill();
void syscall_wrapper_write();
#pragma GCC diagnostic pop

#endif
