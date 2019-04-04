#include <generated-offsets-build.h>

#include <stddef.h>

#include <shim_defs.h>
#include <shim_internal.h>
#include <shim_tls.h>
#include <shim_thread.h>
#include <shim_types.h>


void dummy(void)
{
    /* PAL_CONTEXT */
    OFFSET_T(PAL_CONTEXT_RAX, PAL_CONTEXT, rax);
    OFFSET_T(PAL_CONTEXT_RSP, PAL_CONTEXT, rsp);
    OFFSET_T(PAL_CONTEXT_RIP, PAL_CONTEXT, rip);
    OFFSET_T(PAL_CONTEXT_EFL, PAL_CONTEXT, efl);
    OFFSET_T(PAL_CONTEXT_CSGSFS, PAL_CONTEXT, csgsfs);

    /* shim_tcb_t */
#ifdef SHIM_TCB_USE_GS
    OFFSET_T(SHIM_TCB_OFFSET, PAL_TCB, libos_tcb);
#else
    OFFSET_T(SHIM_TCB_OFFSET, __libc_tcb_t, shim_tcb);
#endif
    OFFSET_T(TCB_SELF, shim_tcb_t, self);
    OFFSET_T(TCB_TP, shim_tcb_t, tp);
    OFFSET_T(TCB_REGS, shim_tcb_t, context.regs);
    OFFSET(SHIM_REGS_RSP, shim_regs, rsp);
    OFFSET(SHIM_REGS_R15, shim_regs, r15);
    OFFSET(SHIM_REGS_RIP, shim_regs, rip);
#ifdef SHIM_SYSCALL_STACK
    OFFSET_T(TCB_SYSCALL_STACK, shim_tcb_t, syscall_stack);
#endif
    OFFSET_T(TCB_FLAGS, shim_tcb_t, flags);
    DEFINE(SHIM_REGS_SIZE, sizeof(struct shim_regs));

    /* struct shim_thread */
    OFFSET(THREAD_HAS_SIGNAL, shim_thread, has_signal);

    /* definitions */
    DEFINE(SIGFRAME_SIZE, sizeof(struct sigframe));
    DEFINE(FP_XSTATE_SIZE, sizeof(struct _libc_fpstate));
    DEFINE(FP_XSTATE_MAGIC2_SIZE, FP_XSTATE_MAGIC2_SIZE);

    /* definitions */
    DEFINE(RED_ZONE_SIZE, RED_ZONE_SIZE);
}
