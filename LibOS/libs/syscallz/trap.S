.section .text

.weak syscall_wrapper
.type syscall_wrapper, @function

.global __sysz_trap
.p2align 4,0xcc
.type __sysz_trap,@function

__sysz_trap:
    popq %rcx
    jmpq *syscall_wrapper@GOTPCREL(%rip)
