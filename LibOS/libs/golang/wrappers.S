/*
 * syscall_wrapper.S
 *
 * This file holds syscall wrappers that invoke the library OS system call
 * entry points from statically compiled applications. Direct use of syscall
 * by such applications is replaced with a call to a wrapper in this file.
 * These functions are to only be invoked by a patched Golang
 * application.
 */

# TODO incorporate per-Go-version knowledge
# TODO make func-local labels as .L rather than full labels
# TODO wrapper implementations tied to specific version of Go?
# TODO remove addl / subl rsp 128

.section .data

.global rtstackcheck
rtstackcheck:
.quad 0

.global rtentersyscall
rtentersyscall:
.quad 0

.global rtexitsyscall
rtexitsyscall:
.quad 0

.weak syscalldb
.type syscalldb, @function

.weak syscall_wrapper
.type syscall_wrappe, @function

.set SYS_read, 0
.set SYS_write, 1
.set SYS_close, 3
.set SYS_mmap, 9
.set SYS_munmap, 11
.set SYS_brk, 12
.set SYS_rt_sigaction, 13
.set SYS_rt_sigprocmask, 14
.set SYS_rt_sigreturn, 15
.set SYS_sched_yield, 24
.set SYS_mincore, 27
.set SYS_madvise, 28
.set SYS_setittimer, 38
.set SYS_getpid, 39
.set SYS_clone, 56
.set SYS_exit, 60
.set SYS_kill, 62
.set SYS_fcntl, 72
.set SYS_sigaltstack, 131
.set SYS_arch_prctl, 158
.set SYS_gettid, 186
.set SYS_tkill, 200
.set SYS_futex, 202
.set SYS_sched_getaffinity, 204
.set SYS_epoll_create, 213
.set SYS_exit_group, 231
.set SYS_epoll_ctl, 233
.set SYS_openat, 257
.set SYS_readlinkat, 267
.set SYS_pselect6, 270
.set SYS_epoll_pwait, 281
.set SYS_epoll_create1, 291

.macro FUNCTION name
.global syscall_wrapper_\name
.p2align 4,0xcc
.type syscall_wrapper_\name , @function
syscall_wrapper_\name:
.endm

# Wrapper functions with a trivial implementation.

.macro WRAPPER name num
FUNCTION \name
    mov $\num,%eax
    callq *syscalldb@GOTPCREL(%rip)
    retq
.endm

WRAPPER  close      SYS_close
WRAPPER  epoll_create1  SYS_epoll_create1
WRAPPER  epoll_create   SYS_epoll_create
WRAPPER  epoll_ctl      SYS_epoll_ctl
WRAPPER  epoll_pwait    SYS_epoll_pwait
WRAPPER  fcntl      SYS_fcntl
WRAPPER  getpid     SYS_getpid
WRAPPER  kill       SYS_kill
WRAPPER  madvise    SYS_madvise
WRAPPER  openat     SYS_openat
WRAPPER  readlinkat     SYS_readlinkat
WRAPPER  read       SYS_read
WRAPPER  rt_sigreturn   SYS_rt_sigreturn
WRAPPER  setittimer     SYS_setittimer
WRAPPER  tkill      SYS_tkill

# Wrapper functions with non-trivial implementation.

FUNCTION write
    movq 0x8(%rsp), %rdi
    movq 0x10(%rsp), %rsi
    movl 0x18(%rsp), %edx
    movl $SYS_write, %eax
    movq ret_write@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_write:
    cmp $0xfffffffffffff001,%rax
    jbe write_ok
    movl $0xffffffff, %eax
write_ok:
    movl %eax, 0x20(%rsp)
    retq

FUNCTION mmap
    movq 0x8(%rsp), %rdi
    movq 0x10(%rsp), %rsi
    movl 0x18(%rsp), %edx
    movl 0x1c(%rsp), %r10d
    movl 0x20(%rsp), %r8d
    movl 0x24(%rsp), %r9d
    movl $SYS_mmap, %eax
    movq ret_mmap@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_mmap:
    cmp $0xfffffffffffff001,%rax
    jbe mmap_ok
    not %rax
    inc %rax
    movq $0x0, 0x28(%rsp)
    movq %rax, 0x30(%rsp)
    ret
mmap_ok:
    movq %rax, 0x28(%rsp)
    movq $0x0, 0x30(%rsp)
    retq

FUNCTION munmap
    movq 0x8(%rsp), %rdi
    movq 0x10(%rsp), %rsi
    movl $SYS_munmap, %eax
    movq ret_munmap@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_munmap:
    cmp $0xfffffffffffff001,%rax
    jbe munmap_return
    movl $0xf1,0xf1
    retq
munmap_return:
    retq

FUNCTION brk
    movq $0x0, %rdi
    movl $SYS_brk, %eax
    movq ret_brk@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_brk:
    callq *syscalldb@GOTPCREL(%rip)
    movq %rax, 0x8(%rsp)
    retq

FUNCTION rt_sigaction
    movq 0x8(%rsp), %rdi
    movq 0x10(%rsp), %rsi
    movq 0x18(%rsp), %rdx
    movq 0x20(%rsp), %r10
    movl $SYS_rt_sigaction, %eax
    movq ret_rt_sigaction@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_rt_sigaction:
    movq %rax, 0x28(%rsp)
    retq

FUNCTION rt_sigprocmask
    movl 0x8(%rsp), %edi
    movq 0x10(%rsp), %rsi
    movq 0x18(%rsp), %rdx
    movl 0x20(%rsp), %r10d
    movl $SYS_rt_sigprocmask, %eax
    movq ret_rt_sigprocmask@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_rt_sigprocmask:
    cmp $0xfffffffffffff001,%rax
    jbe sigprocmask_ret
    movl $0xf1, 0xf1
    retq
sigprocmask_ret:
    retq 

FUNCTION sched_yield
    movl $SYS_sched_yield, %eax
    movq ret_sched_yield@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_sched_yield:
    retq

FUNCTION mincore
    movq 0x8(%rsp), %rdi
    movq 0x10(%rsp), %rsi
    movq 0x18(%rsp), %rdx
    movl $SYS_mincore, %eax
    movq ret_syscall_wrapper_mincore@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_syscall_wrapper_mincore:
    ret

FUNCTION clone
    movl 0x8(%rsp), %edi
    movq 0x10(%rsp), %rsi
    movq $0x0, %rdx
    movq $0x0, %r10
    movq 0x18(%rsp), %r8
    movq 0x20(%rsp), %r9
    movq 0x28(%rsp), %r12
    movl $SYS_clone, %eax
    movq ret_clone_in_clone@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_clone_in_clone:
    cmp $0x0, %rax
    je in_child
    movl %eax, 0x30(%rsp)
    retq 
in_child:
    movq %rsi, %rsp
    cmp $0x0, %r8
    je nog
    cmp $0x0, %r9
    je nog
    movl $SYS_gettid, %eax
    movq ret_gettid_in_clone@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_gettid_in_clone:
    movq %rax, 0x48(%r8)
    lea 0x88(%r8), %rdi
    callq *syscall_wrapper_arch_prctl@GOTPCREL(%rip)
    movq %r8, 0x30(%r9)
    movq %r9,%fs:0xfffffffffffffff8
    movq rtstackcheck@GOTPCREL(%rip), %rcx
    movq (%rcx), %rcx
    callq *%rcx
nog:
    callq *%r12
    jmp clone_loop
clone_loop:
    movl $0x6f, %edi
    movl $SYS_exit, %eax
    movq ret_exit_in_clone@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_exit_in_clone:
    jmp clone_loop

FUNCTION stackcheck
    movq %fs:0xfffffffffffffff8, %rax
    cmp %rsp, 0x8(%rax)
    ja checker
    int $0x3
checker:
    cmp    (%rax),%rsp
    ja checker_ret
checker_ret:
    retq

FUNCTION exit
    movq 0x8(%rsp), %rax
    movl $0x0, (%rax)
    movl $0x0, %edi
    movl $SYS_exit, %eax
    movq ret_exit@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_exit:
    int $0x3
    jmp loop
loop:
    jmp loop

FUNCTION sigaltstack
    movq 0x8(%rsp), %rdi
    movq 0x10(%rsp), %rsi
    movq $SYS_sigaltstack, %rax
    movq ret_sigaltstack@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_sigaltstack:
    cmp $0xfffffffffffff001,%rax
    jbe sgstk_ret
    movl $0xf1,0xf1
    retq
sgstk_ret:
    retq

FUNCTION arch_prctl
    subq $0x28, %rsp
    movq %rbp, 0x20(%rsp)
    lea 0x20(%rsp), %rbp
    add $0x8, %rdi
    movq %rdi, %rsi
    movq $0x1002, %rdi
    movq $SYS_arch_prctl, %rax
    movq ret_arch_prctl@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_arch_prctl:
    cmp $0xfffffffffffff001,%rax
    jbe settls_loop
    movl $0xf1, 0xf1
settls_loop:
    movq 0x20(%rsp), %rbp
    add $0x28, %rsp
    retq

FUNCTION gettid
    movl $SYS_gettid, %eax
    movq ret_gettid@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_gettid:
    movl %eax, 0x8(%rsp)
    retq 

FUNCTION futex
    movq 0x8(%rsp), %rdi
    movq 0x10(%rsp), %rsi
    movl 0x14(%rsp), %edx
    movq 0x18(%rsp), %r10
    movq 0x20(%rsp), %r8
    movl 0x28(%rsp), %r9d
    movl $SYS_futex, %eax
    movq ret_futex@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_futex:
    movl %eax, 0x30(%rsp)
    retq 

FUNCTION sched_getaffinity
    movq 0x8(%rsp), %rdi
    movq 0x10(%rsp), %rsi
    movq 0x18(%rsp), %rdx
    movl $SYS_sched_getaffinity, %eax
    movq ret_sched_getaffinity@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_sched_getaffinity:
    movl %eax, 0x20(%rsp)
    retq 

FUNCTION exit_group
    movl 0x8(%rsp), %edi
    movl $SYS_exit_group, %eax
    movq ret_exit_group@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_exit_group:
    retq

FUNCTION pselect6
    subq $0x18, %rsp
    movq %rbp, 0x10(%rsp)
    lea 0x10(%rsp), %rbp
    movl $0x0, %edx
    movl 0x20(%rsp), %eax
    movl $0xf4240, %ecx
    div %ecx
    movq %rax, (%rsp)
    movl $0x3e8, %eax
    mul %edx
    movq %rax, 0x8(%rsp)
    movl $0x0, %edi
    movl $0x0, %esi
    movl $0x0, %edx
    movl $0x0, %r10d
    movq %rsp, %r8
    movl $0x0, %r9d
    movl $SYS_pselect6, %eax
    movq ret_pselect6@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_pselect6:
    movq 0x10(%rsp), %rbp
    addq $0x18, %rsp
    retq 

FUNCTION syscall
    movq rtentersyscall@GOTPCREL(%rip), %rcx
    movq (%rcx), %rcx
    callq *%rcx
    movq 0x10(%rsp), %rdi
    movq 0x18(%rsp), %rsi
    movq 0x20(%rsp), %rdx
    movq $0x0, %r10
    movq $0x0, %r8
    movq $0x0, %r9
    movq 0x8(%rsp), %rax
    movq ret_syscall@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_syscall:
    cmp $0xfffffffffffff001, %rax
    jbe syscall_wrapper_ok
    movq $0xffffffffffffffff, 0x28(%rsp)
    movq $0x0, 0x30(%rsp)
    neg %rax
    movq %rax, 0x38(%rsp)
    retq
syscall_wrapper_ok:
    movq %rax, 0x28(%rsp)
    movq %rdx, 0x30(%rsp)
    movq $0x0, 0x38(%rsp)
    movq rtexitsyscall@GOTPCREL(%rip), %rcx
    movq (%rcx), %rcx
    callq *%rcx
    retq

FUNCTION syscall6
    movq rtentersyscall@GOTPCREL(%rip), %rcx
    movq (%rcx), %rcx
    callq *%rcx
    movq 0x10(%rsp), %rdi
    movq 0x18(%rsp), %rsi
    movq 0x20(%rsp), %rdx
    movq 0x28(%rsp), %r10
    movq 0x30(%rsp), %r8
    movq 0x38(%rsp), %r9
    movq 0x8(%rsp), %rax
    movq ret_syscall6@GOTPCREL(%rip), %rcx
    jmp *syscall_wrapper@GOTPCREL(%rip)
ret_syscall6:
    cmp $0xfffffffffffff001,%rax
    jbe ok6
    movq $0xffffffffffffffff, 0x40(%rsp)
    movq $0x0, 0x48(%rsp)
    neg %rax
    movq %rax, 0x50(%rsp)
    movq rtexitsyscall@GOTPCREL(%rip), %rcx
    movq (%rcx), %rcx
    callq *%rcx
    retq
ok6:
    movq %rax, 0x40(%rsp)
    movq %rdx, 0x48(%rsp)
    movq $0x0, 0x50(%rsp)
    movq rtexitsyscall@GOTPCREL(%rip), %rcx
    movq (%rcx), %rcx
    callq *%rcx
    retq
