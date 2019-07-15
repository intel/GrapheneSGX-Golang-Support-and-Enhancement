/* Copyright (C) 2014 Stony Brook University
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
 * shim_signal.c
 *
 * This file contains codes to handle signals and exceptions passed from PAL.
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_checkpoint.h>
#include <shim_signal.h>
#include <shim_unistd.h>

#include <pal.h>

static struct shim_signal **
allocate_signal_log (struct shim_thread * thread, int sig)
{
    if (!thread->signal_logs)
        return NULL;

    struct shim_signal_log * log = &thread->signal_logs[sig - 1];
    int head, tail, old_tail;

    do {
        head = atomic_read(&log->head);
        old_tail = tail = atomic_read(&log->tail);

        if (head == tail + 1 || (!head && tail == (MAX_SIGNAL_LOG - 1)))
            return NULL;

        tail = (tail == MAX_SIGNAL_LOG - 1) ? 0 : tail + 1;
    } while (atomic_cmpxchg(&log->tail, old_tail, tail) == tail);

    debug("signal_logs[%d]: head=%d, tail=%d (counter = %ld)\n", sig - 1,
          head, tail, thread->has_signal.counter + 1);

    atomic_inc(&thread->has_signal);

    shim_tcb_t * shim_tcb = thread->shim_tcb;
    set_bit(SHIM_FLAG_SIGPENDING, &shim_tcb->flags);

    debug("signal set_bit thread: %p shim_tcb: %p &tcb->flags: %p tcb->flags 0x%lx "
          "tcb->tid %d counter = %ld\n",
          thread, thread->tcb, &shim_tcb->flags, shim_tcb->flags, shim_tcb->tid,
          thread->has_signal.counter);

    return &log->logs[old_tail];
}

static struct shim_signal *
fetch_signal_log (struct shim_thread * thread, int sig)
{
    struct shim_signal_log * log = &thread->signal_logs[sig - 1];
    struct shim_signal * signal = NULL;
    int head, tail, old_head;

    while (1) {
        old_head = head = atomic_read(&log->head);
        tail = atomic_read(&log->tail);

        if (head == tail)
            return NULL;

        if (!(signal = log->logs[head]))
            return NULL;

        log->logs[head] = NULL;
        head = (head == MAX_SIGNAL_LOG - 1) ? 0 : head + 1;

        if (atomic_cmpxchg(&log->head, old_head, head) == old_head)
            break;

        log->logs[old_head] = signal;
    }

    debug("signal_logs[%d]: head=%d, tail=%d\n", sig -1, head, tail);

    atomic_dec(&thread->has_signal);

    return signal;
}

static void
__handle_one_signal (shim_tcb_t * tcb, int sig, struct shim_signal * signal,
                     PAL_PTR event, PAL_CONTEXT * context);

static void __store_info (siginfo_t * info, struct shim_signal * signal)
{
    if (info)
        memcpy(&signal->info, info, sizeof(siginfo_t));
}

void __store_context (shim_tcb_t * tcb, PAL_CONTEXT * pal_context,
                      struct shim_signal * signal)
{
    ucontext_t * context = &signal->context;

    if (tcb && tcb->context.regs && tcb->context.regs->orig_rax) {
        struct shim_context * ct = &tcb->context;

        if (ct->regs) {
            struct shim_regs * regs = ct->regs;
            context->uc_mcontext.gregs[REG_RIP] = regs->rip;
            context->uc_mcontext.gregs[REG_EFL] = regs->rflags;
            context->uc_mcontext.gregs[REG_R15] = regs->r15;
            context->uc_mcontext.gregs[REG_R14] = regs->r14;
            context->uc_mcontext.gregs[REG_R13] = regs->r13;
            context->uc_mcontext.gregs[REG_R12] = regs->r12;
            context->uc_mcontext.gregs[REG_R11] = regs->r11;
            context->uc_mcontext.gregs[REG_R10] = regs->r10;
            context->uc_mcontext.gregs[REG_R9]  = regs->r9;
            context->uc_mcontext.gregs[REG_R8]  = regs->r8;
            context->uc_mcontext.gregs[REG_RCX] = regs->rcx;
            context->uc_mcontext.gregs[REG_RDX] = regs->rdx;
            context->uc_mcontext.gregs[REG_RSI] = regs->rsi;
            context->uc_mcontext.gregs[REG_RDI] = regs->rdi;
            context->uc_mcontext.gregs[REG_RBX] = regs->rbx;
            context->uc_mcontext.gregs[REG_RBP] = regs->rbp;
            context->uc_mcontext.gregs[REG_RSP] = regs->rsp;
        }

        signal->context_stored = true;
        return;
    }

    if (pal_context) {
        memcpy(context->uc_mcontext.gregs, pal_context, sizeof(PAL_CONTEXT));
        signal->context_stored = true;
    }
}

void deliver_signal (PAL_PTR event, siginfo_t * info, PAL_CONTEXT * context)
{
    shim_tcb_t * tcb = shim_get_tls();
    assert(tcb);

    // Signals should not be delivered before the user process starts
    // or after the user process dies.
    if (!tcb->tp || !cur_thread_is_alive())
        return;

    struct shim_thread * cur_thread = (struct shim_thread *) tcb->tp;
    int sig = info->si_signo;

    int64_t preempt = __disable_preempt(tcb);

    struct shim_signal * signal = __alloca(sizeof(struct shim_signal));
    /* save in signal */
    memset(signal, 0, sizeof(struct shim_signal));
    __store_info(info, signal);
    __store_context(tcb, context, signal);
    signal->pal_context = context;

    if ((preempt & ~SIGNAL_DELAYED) > 1 ||
        __sigismember(&cur_thread->signal_mask, sig) ||
        event == NULL /* send to self */) {
        struct shim_signal ** signal_log = NULL;
        if ((signal = malloc_copy(signal,sizeof(struct shim_signal))) &&
            (signal_log = allocate_signal_log(cur_thread, sig))) {
            *signal_log = signal;
            (*signal_log)->pal_context = NULL;
        }
        if (signal && !signal_log) {
            SYS_PRINTF("signal queue is full (TID = %u, SIG = %d)\n",
                       tcb->tid, sig);
            free(signal);
        }
    } else {
        if (!__handle_signal(tcb, sig, event, context))
            __handle_one_signal(tcb, sig, signal, event, context);
    }

    __enable_preempt(tcb);
}

#define ALLOC_SIGINFO(signo, code, member, value)           \
    ({                                                      \
        siginfo_t * _info = __alloca(sizeof(siginfo_t));    \
        memset(_info, 0, sizeof(siginfo_t));                \
        _info->si_signo = (signo);                          \
        _info->si_code = (code);                            \
        _info->member = (value);                            \
        _info;                                              \
    })

#ifdef __x86_64__
#define IP rip
#else
#define IP eip
#endif

static inline bool context_is_internal(PAL_CONTEXT * context)
{
    return context &&
        (void *) context->IP >= (void *) &__code_address &&
        (void *) context->IP < (void *) &__code_address_end;
}

static inline bool is_signal_allowed(const PAL_CONTEXT * context)
{
    if (context == NULL)
        return false;

    const void * ip = (const void *)context->IP;
    return (((void *) &__syscallas_signal_allowed_0_begin <= ip &&
             ip < (void *) &__syscallas_signal_allowed_0_end) ||
            ((void *) &__syscallas_signal_allowed_1_begin <= ip &&
             ip < (void *) &__syscallas_signal_allowed_1_end) ||
            ((void *) &__syscallas_signal_allowed_2_begin <= ip &&
             ip < (void *) &__syscallas_signal_allowed_2_end) ||
            ((void *) &__syscallas_signal_allowed_3_begin <= ip &&
             ip < (void *) &__syscallas_signal_allowed_3_end));
}

static void print_regs(PAL_CONTEXT * ctx)
{
    MASTER_LOCK();
    debug("rax: 0x%08lx rcx: 0x%08lx rdx: 0x%08lx rbx: 0x%08lx\n",
          ctx->rax, ctx->rcx, ctx->rdx, ctx->rbx);
    debug("rsp: 0x%08lx rbp: 0x%08lx rsi: 0x%08lx rdi: 0x%08lx\n",
          ctx->rsp, ctx->rbp, ctx->rsi, ctx->rdi);
    debug("r8 : 0x%08lx r9 : 0x%08lx r10: 0x%08lx r11: 0x%08lx\n",
          ctx->r8, ctx->r9, ctx->r10, ctx->r11);
    debug("r12: 0x%08lx r13: 0x%08lx r14: 0x%08lx r15: 0x%08lx\n",
          ctx->r12, ctx->r13, ctx->r14, ctx->r15);
    debug("rflags: 0x%08lx rip: 0x%08lx +0x%08lx\n",
          ctx->efl, ctx->rip,
          (void *) ctx->rip - (void *) &__load_address);
    debug("csgsfs: 0x%08lx err: 0x%08lx trapno %ld odlmask 0x%08lx cr2: 0x%08lx\n",
          ctx->csgsfs, ctx->err, ctx->trapno, ctx->oldmask, ctx->cr2);
    MASTER_UNLOCK();
}

static inline void internal_fault(const char* errstr,
                                  PAL_NUM addr, PAL_CONTEXT * context)
{
    IDTYPE tid = get_cur_tid();
    if (context_is_internal(context))
        debug("%s at 0x%08lx (IP = +0x%lx, VMID = %u, TID = %u)\n", errstr,
              addr, (void *) context->IP - (void *) &__load_address,
              cur_process.vmid, is_internal_tid(tid) ? 0 : tid);
    else
        debug("%s at 0x%08lx (IP = 0x%08lx, VMID = %u, TID = %u)\n", errstr,
              addr, context ? context->IP : 0,
              cur_process.vmid, is_internal_tid(tid) ? 0 : tid);

    print_regs(context);
    PAUSE();
}

static void arithmetic_error_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    debug("divzero_upcall rsp: %08lx rip %08lx\n", context->rsp, context->rip);
    if (is_internal_tid(get_cur_tid()) || context_is_internal(context)) {
        internal_fault("Internal arithmetic fault", arg, context);
    } else {
        if (context)
            debug("arithmetic fault at 0x%08lx\n", context->IP);

        deliver_signal(event, ALLOC_SIGINFO(SIGFPE, FPE_INTDIV,
                                            si_addr, (void *) arg), context);
    }
    DkExceptionReturn(event);
}

static void memfault_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    debug("memfault_upcall rsp: %08lx rip %08lx +0x%08lx\n",
          context->rsp, context->rip,
          (void *) context->rip - (void *) &__load_address);
    shim_tcb_t * tcb = shim_get_tls();
    assert(tcb);

    if (tcb->test_range.cont_addr && arg
        && (void *) arg >= tcb->test_range.start
        && (void *) arg <= tcb->test_range.end) {
        assert(context);
        context->rip = (PAL_NUM) tcb->test_range.cont_addr;
        goto ret_exception;
    }

    if (is_internal_tid(get_cur_tid()) || context_is_internal(context)) {
        internal_fault("Internal memory fault", arg, context);
        goto ret_exception;
    }

    if (context)
        debug("memory fault at 0x%08lx (IP = 0x%08lx)\n", arg, context->IP);

    print_regs(context);
    debug("inst: 0x%08lx +0x%08lx\n", context->IP,
          (void *) context->rip - (void *) &__load_address);
    debug_hex((unsigned long*)context->IP, 32);

    struct shim_vma_val vma;
    int signo = SIGSEGV;
    int code;
    if (!arg) {
        code = SEGV_MAPERR;
    } else if (!lookup_vma((void *) arg, &vma)) {
        if (vma.flags & VMA_INTERNAL) {
            internal_fault("Internal memory fault with VMA", arg, context);
            goto ret_exception;
        }
        if (vma.file && vma.file->type == TYPE_FILE) {
            /* DEP 3/3/17: If the mapping exceeds end of a file (but is in the VMA)
             * then return a SIGBUS. */
            uintptr_t eof_in_vma = (uintptr_t) vma.addr + vma.offset + vma.file->info.file.size;
            if (arg > eof_in_vma) {
                signo = SIGBUS;
                code = BUS_ADRERR;
            } else if ((context->err & 4) && !(vma.flags & PROT_WRITE)) {
                /* DEP 3/3/17: If the page fault gives a write error, and
                 * the VMA is read-only, return SIGSEGV+SEGV_ACCERR */
                signo = SIGSEGV;
                code = SEGV_ACCERR;
            } else {
                /* XXX: need more sophisticated judgement */
                signo = SIGBUS;
                code = BUS_ADRERR;
            }
        } else {
            code = SEGV_ACCERR;
        }
    } else {
        code = SEGV_MAPERR;
    }

    deliver_signal(event, ALLOC_SIGINFO(signo, code, si_addr, (void *) arg),
                   context);

ret_exception:
    DkExceptionReturn(event);
}

/*
 * Helper function for test_user_memory / test_user_string; they behave
 * differently for different PALs:
 *
 * - For Linux-SGX, the faulting address is not propagated in memfault
 *   exception (SGX v1 does not write address in SSA frame, SGX v2 writes
 *   it only at a granularity of 4K pages). Thus, we cannot rely on
 *   exception handling to compare against tcb.test_range.start/end.
 *   Instead, traverse VMAs to see if [addr, addr+size) is addressable;
 *   before traversing VMAs, grab a VMA lock.
 *
 * - For other PALs, we touch one byte of each page in [addr, addr+size).
 *   If some byte is not addressable, exception is raised. memfault_upcall
 *   handles this exception and resumes execution from ret_fault.
 *
 * The second option is faster in fault-free case but cannot be used under
 * SGX PAL. We use the best option for each PAL for now. */
static bool is_sgx_pal(void) {
    static struct atomic_int sgx_pal = { .counter = 0 };
    static struct atomic_int inited  = { .counter = 0 };

    if (!atomic_read(&inited)) {
        /* Ensure that is_sgx_pal is updated before initialized */
        atomic_set(&sgx_pal, strcmp_static(PAL_CB(host_type), "Linux-SGX"));
        MB();
        atomic_set(&inited, 1);
    }
    MB();

    return atomic_read(&sgx_pal) != 0;
}

/*
 * 'test_user_memory' and 'test_user_string' are helper functions for testing
 * if a user-given buffer or data structure is readable / writable (according
 * to the system call semantics). If the memory test fails, the system call
 * should return -EFAULT or -EINVAL accordingly. These helper functions cannot
 * guarantee further corruption of the buffer, or if the buffer is unmapped
 * with a concurrent system call. The purpose of these functions is simply for
 * the compatibility with programs that rely on the error numbers, such as the
 * LTP test suite. */
bool test_user_memory (void * addr, size_t size, bool write)
{
    if (!size)
        return false;

    if (!access_ok(addr, size))
        return true;

    /* SGX path: check if [addr, addr+size) is addressable (in some VMA) */
    if (is_sgx_pal())
        return !is_in_adjacent_vmas(addr, size);

    /* Non-SGX path: check if [addr, addr+size) is addressable by touching
     * a byte of each page; invalid access will be caught in memfault_upcall */
    shim_tcb_t * tcb = shim_get_tls();
    assert(tcb && tcb->tp);
    __disable_preempt(tcb);

    bool  has_fault = true;

    /* Add the memory region to the watch list. This is not racy because
     * each thread has its own record. */
    assert(!tcb->test_range.cont_addr);
    tcb->test_range.cont_addr = &&ret_fault;
    tcb->test_range.start = addr;
    tcb->test_range.end   = addr + size - 1;

    /* Try to read or write into one byte inside each page */
    void * tmp = addr;
    while (tmp <= addr + size - 1) {
        if (write) {
            *(volatile char *) tmp = *(volatile char *) tmp;
        } else {
            *(volatile char *) tmp;
        }
        tmp = ALIGN_UP(tmp + 1);
    }

    has_fault = false; /* All accesses have passed. Nothing wrong. */

ret_fault:
    /* If any read or write into the target region causes an exception,
     * the control flow will immediately jump to here. */
    tcb->test_range.cont_addr = NULL;
    tcb->test_range.start = tcb->test_range.end = NULL;
    __enable_preempt(tcb);
    return has_fault;
}

/*
 * This function tests a user string with unknown length. It only tests
 * whether the memory is readable.
 */
bool test_user_string (const char * addr)
{
    if (!access_ok(addr, 1))
        return true;

    size_t size, maxlen;
    const char * next = ALIGN_UP(addr + 1);

    /* SGX path: check if [addr, addr+size) is addressable (in some VMA). */
    if (is_sgx_pal()) {
        /* We don't know length but using unprotected strlen() is dangerous
         * so we check string in chunks of 4K pages. */
        do {
            maxlen = next - addr;

            if (!access_ok(addr, maxlen) || !is_in_adjacent_vmas((void*) addr, maxlen))
                return true;

            size = strnlen(addr, maxlen);
            addr = next;
            next = ALIGN_UP(addr + 1);
        } while (size == maxlen);

        return false;
    }

    /* Non-SGX path: check if [addr, addr+size) is addressable by touching
     * a byte of each page; invalid access will be caught in memfault_upcall. */
    shim_tcb_t * tcb = shim_get_tls();
    assert(tcb && tcb->tp);
    __disable_preempt(tcb);

    bool has_fault = true;

    assert(!tcb->test_range.cont_addr);
    tcb->test_range.cont_addr = &&ret_fault;

    do {
        /* Add the memory region to the watch list. This is not racy because
         * each thread has its own record. */
        tcb->test_range.start = (void *) addr;
        tcb->test_range.end = (void *) (next - 1);

        maxlen = next - addr;

        if (!access_ok(addr, maxlen))
            return true;
        *(volatile char *) addr; /* try to read one byte from the page */

        size = strnlen(addr, maxlen);
        addr = next;
        next = ALIGN_UP(addr + 1);
    } while (size == maxlen);

    has_fault = false; /* All accesses have passed. Nothing wrong. */

ret_fault:
    /* If any read or write into the target region causes an exception,
     * the control flow will immediately jump to here. */
    tcb->test_range.cont_addr = NULL;
    tcb->test_range.start = tcb->test_range.end = NULL;
    __enable_preempt(tcb);
    return has_fault;
}

void __attribute__((weak)) syscall_wrapper(void)
{
    /*
     * work around for link.
     * syscalldb.S is excluded for libsysdb_debug.so so it fails to link
     * due to missing syscall_wrapper.
     */
}

static void illegal_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    struct shim_vma_val vma;

    if (!is_internal_tid(get_cur_tid()) &&
        !context_is_internal(context) &&
        !(lookup_vma((void *) arg, &vma)) &&
        !(vma.flags & VMA_INTERNAL)) {
        if (context)
            debug("illegal instruction at 0x%08lx\n", context->IP);

        uint8_t * rip = (uint8_t*)context->IP;
        /*
         * Emulate syscall instruction (opcode 0x0f 0x05);
         * syscall instruction is prohibited in
         *   Linux-SGX PAL and raises a SIGILL exception and
         *   Linux PAL with seccomp and raise SIGSYS exception.
         */
#if 0
        if (rip[-2] == 0x0f && rip[-1] == 0x05) {
            /* TODO: once finished, remove "#if 0" above. */
            /*
             * SIGSYS case (can happen with Linux PAL with seccomp)
             * rip points to the address after syscall instruction
             * %rcx: syscall instruction must put an
             *       instruction-after-syscall in rcx
             */
            context->rax = siginfo->si_syscall; /* PAL_CONTEXT doesn't
                                                 * include a member
                                                 * corresponding to
                                                 * siginfo_t::si_syscall yet.
                                                 */
            context->rcx = (long)rip;
            context->r11 = context->efl;
            context->rip = (long)&syscall_wrapper;
        } else
#endif
        if (rip[0] == 0x0f && rip[1] == 0x05) {
            /*
             * SIGILL case (can happen in Linux-SGX PAL)
             * %rcx: syscall instruction must put an instruction-after-syscall
             *       in rcx. See the syscall_wrapper in syscallas.S
             * TODO: check SIGILL and ILL_ILLOPN
             */
            debug("sigill (rip = %p %p)\n", rip, rip + 2);
            context->rcx = (long)rip + 2;
            context->r11 = context->efl;
            context->rip = (long)&syscall_wrapper;
            // uc->uc_mcontext->gregs[REG_RCX] = (long)rip + 2;
            // uc->uc_mcontext->gregs[REG_R11] = (long)context->efl;
            // uc->uc_mcontext->gregs[REG_RIP] = (long)&syscall_wrapper;
        } else {
            deliver_signal(event, ALLOC_SIGINFO(SIGILL, ILL_ILLOPC,
                                                si_addr, (void *) arg), context);
        }
    } else {
        internal_fault("Internal illegal fault", arg, context);
    }
    DkExceptionReturn(event);
}

static void quit_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    __UNUSED(arg);
    debug("quit_upcall rsp: %08lx rip %08lx +0x%08lx\n",
          context->rsp, context->rip,
          (void *) context->rip - (void *) &__load_address);
    if (!is_internal_tid(get_cur_tid())) {
        deliver_signal(event, ALLOC_SIGINFO(SIGTERM, SI_USER, si_pid, 0), context);
    }
    DkExceptionReturn(event);
}

static void suspend_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    __UNUSED(arg);
    debug("suspend_upcall rsp: %08lx rip %08lx +0x%08lx\n",
          context->rsp, context->rip,
          (void *) context->rip - (void *) &__load_address);
    if (!is_internal_tid(get_cur_tid())) {
        deliver_signal(event, ALLOC_SIGINFO(SIGINT, SI_USER, si_pid, 0), context);
    }
    DkExceptionReturn(event);
}

static void resume_upcall (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    __UNUSED(arg);
    debug("resume_upcall rsp: %08lx rip %08lx +0x%08lx\n",
          context->rsp, context->rip,
          (void *) context->rip - (void *) &__load_address);
    shim_tcb_t * tcb = shim_get_tls();
    if (!tcb || !tcb->tp)
        return;

    if (!is_internal_tid(get_cur_tid())) {
        assert(tcb);
        int64_t preempt = __disable_preempt(tcb);

        if ((preempt & ~SIGNAL_DELAYED) > 1) {
            debug("delaying signal preempt %ld delay: 0x%lx\n",
                  (preempt & ~SIGNAL_DELAYED), (preempt & SIGNAL_DELAYED));
            __preempt_set_delayed(tcb);
        } else {
            //PAL_EVENT * event = (PAL_EVENT *) eventp;
            debug("resume_upcall rsp: %08lx rip %08lx +0x%08lx tid: %d\n",
                  context->rsp, context->rip,
                  (void *) context->rip - (void *) &__load_address,
                  get_cur_tid());

            __handle_signal(tcb, 0, event, context);
        }
        __enable_preempt(tcb);
    }
    DkExceptionReturn(event);
}

int init_signal (void)
{
    DkSetExceptionHandler(&arithmetic_error_upcall,     PAL_EVENT_ARITHMETIC_ERROR);
    DkSetExceptionHandler(&memfault_upcall,    PAL_EVENT_MEMFAULT);
    DkSetExceptionHandler(&illegal_upcall,     PAL_EVENT_ILLEGAL);
    DkSetExceptionHandler(&quit_upcall,        PAL_EVENT_QUIT);
    DkSetExceptionHandler(&suspend_upcall,     PAL_EVENT_SUSPEND);
    DkSetExceptionHandler(&resume_upcall,      PAL_EVENT_RESUME);
    return 0;
}

__sigset_t * get_sig_mask (struct shim_thread * thread)
{
    if (!thread)
        thread = get_cur_thread();

    assert(thread);

    return &(thread->signal_mask);
}

__sigset_t * set_sig_mask (struct shim_thread * thread,
                           const __sigset_t * set)
{
    if (!thread)
        thread = get_cur_thread();

    assert(thread);

    if (set)
        memcpy(&thread->signal_mask, set, sizeof(__sigset_t));

    return &thread->signal_mask;
}

static void (*default_sighandler[NUM_SIGS]) (int, siginfo_t *, void *);

static unsigned int fpstate_size_get(const struct _libc_fpstate * fpstate)
{
    if (fpstate == NULL)
        return 0;

    const struct _fpx_sw_bytes * sw = &fpstate->sw_reserved;
    if (sw->magic1 == FP_XSTATE_MAGIC1 &&
        sw->xstate_size < sw->extended_size &&
        *((__typeof__(FP_XSTATE_MAGIC2)*)((void*)fpstate + sw->xstate_size)) ==
        FP_XSTATE_MAGIC2)
        return sw->extended_size;

    return sizeof(struct swregs_state);
}

static void direct_call_if_sighandler_kill(
    int sig, siginfo_t * info, void (*handler) (int, siginfo_t *, void *));

static void * __get_signal_stack(
    struct shim_thread * thread, void * current_stack)
{
    const stack_t * ss = &thread->signal_altstack;
    if (ss->ss_flags & SS_DISABLE)
        return current_stack;
    if (ss->ss_sp < current_stack &&
        current_stack <= ss->ss_sp + ss->ss_size)
        return current_stack;

    return ss->ss_sp + ss->ss_size;
}

static void * aligndown_sigframe(void * sp)
{
    return ALIGN_DOWN_PTR(sp, 16UL) - 8;
}

static void __setup_sig_frame(
    shim_tcb_t * tcb, int sig, struct shim_signal * signal,
    PAL_PTR eventp, PAL_CONTEXT * context,
    void (*handler) (int, siginfo_t *, void *), void (*restorer) (void))
{
    __UNUSED(tcb);
    __UNUSED(eventp);
    direct_call_if_sighandler_kill(sig, &signal->info, handler);

    //PAL_EVENT * event = (PAL_EVENT *) eventp;
    //struct shim_thread * thread = (struct shim_thread *) tcb->tp;

    //ucontext_t * uc = event->uc;
    //struct _libc_fpstate * fpstate = uc->uc_mcontext.fpregs;
    struct _libc_xregs_state * xregs_state =
        (struct _libc_xregs_state * )context->fpregs;
    struct _libc_fpstate * fpstate = &xregs_state->fpstate;
    unsigned int fpstate_size = fpstate_size_get(fpstate);

#if 0
    //unsigned long sp = uc->uc_mcontext.gregs[REG_RSP];
    void * sp = context->rsp;
    sp -= RED_ZONE_SIZE;  /* redzone */
#else
    void * sp = __get_signal_stack(tcb->tp, (void *)context->rsp);
    if (sp == (void *)context->rsp)
        sp -= RED_ZONE_SIZE;  /* redzone */
#endif
    fpregset_t user_fp = ALIGN_DOWN_PTR(sp - fpstate_size, 64UL);
    struct sigframe * user_sigframe =
        aligndown_sigframe((void*)user_fp - sizeof(struct sigframe));
    assert(&user_sigframe->uc == ALIGN_UP_PTR(&user_sigframe->uc, 16UL));
    user_sigframe->restorer = restorer;
    //memcpy(&user_sigframe->uc, uc, sizeof(*uc));    //XXX
    user_sigframe->uc.uc_flags = UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS;
    user_sigframe->uc.uc_link = NULL;
    memcpy(&user_sigframe->uc.uc_mcontext.gregs, context,
           sizeof(user_sigframe->uc.uc_mcontext.gregs));
    stack_t * stack = &user_sigframe->uc.uc_stack;
#if 0
    /* For now sigaltstack isn't supported */
    stack->ss_sp = 0;
    stack->ss_flags = SS_DISABLE;
    stack->ss_size = 0;
#else
    *stack = tcb->tp->signal_altstack;
#endif
    memcpy(&user_sigframe->info, &signal->info, sizeof(signal->info));
    if (fpstate_size > 0) {
        user_sigframe->uc.uc_flags |= UC_FP_XSTATE;
        memcpy(user_fp, fpstate, fpstate_size);
        user_sigframe->uc.uc_mcontext.fpregs = user_fp;
    } else {
        user_sigframe->uc.uc_flags &= UC_FP_XSTATE;
        user_sigframe->uc.uc_mcontext.fpregs = NULL;
    }
    //user_sigframe->uc.uc_sigmask; // XXX TODO
    // memcpy(&user_sigframe->uc.uc_sigmask, &uc->uc_sigmask,
    //        sizeof(user_sigframe->uc.uc_sigmask));

#if 0
    PAL_CONTEXT * pal_context = signal->pal_context;
    if (pal_context) {
        pal_context->rsp = (long)user_sigframe;
        pal_context->rip = (long)handler;
        pal_context->rdi = signal->info.si_signo;
        pal_context->rsi = (long)&user_sigframe->info;
        pal_context->rdx = (long)&user_sigframe->uc;
        pal_context->rax = 0;
    }

    gregset_t * gregs = &uc->uc_mcontext.gregs;
    (*gregs)[REG_RSP] = (long)user_sigframe;
    (*gregs)[REG_RIP] = (long)handler;
    (*gregs)[REG_RDI] = (long)signal->info.si_signo;
    (*gregs)[REG_RSI] = (long)&user_sigframe->info;
    (*gregs)[REG_RDX] = (long)&user_sigframe->uc;
    (*gregs)[REG_RAX] = 0;
#endif

    // _DkExceptionReturn overwrite uc.uc_mcontext.gregs
    // PAL_CONTEXT == greg_t
    //memcpy(&event->context, gregs, sizeof(PAL_CONTEXT));
    context->rsp = (long)user_sigframe;
    context->rip = (long)handler;
    context->rdi = (long)signal->info.si_signo;
    context->rsi = (long)&user_sigframe->info;
    context->rdx = (long)&user_sigframe->uc;
    context->rax = 0;

    // keep fpu state to user signal handler
    // uc->uc_mcontext.fpregs = NULL;
    // uc->uc_flags &= ~UC_FP_XSTATE;
    context->fpregs = NULL;

    debug("deliver signal handler to user stack %p (%d, %p, %p)\n",
          handler, sig, &signal->info, &signal->context);
}

static void get_signal_handler(struct shim_thread * thread, int sig,
                               void (**handler) (int, siginfo_t *, void *),
                               void (**restorer) (void))
{
    struct shim_signal_handle * sighdl = &thread->signal_handles[sig - 1];
    *handler = NULL;
    *restorer = NULL;

    lock(&thread->lock);

    if (sighdl->action) {
        struct __kernel_sigaction * act = sighdl->action;
        /* This is a workaround. The truth is that many program will
           use sa_handler as sa_sigaction, because sa_sigaction is
           not supported in amd64 */
#ifdef __i386__
        *handler = (void (*) (int, siginfo_t *, void *)) act->_u._sa_handler;
        if (act->sa_flags & SA_SIGINFO)
            sa_handler = act->_u._sa_sigaction;
#else
        *handler = (void (*) (int, siginfo_t *, void *)) act->k_sa_handler;
#endif
        *restorer = act->sa_restorer;
        if (act->sa_flags & SA_RESETHAND) {
            sighdl->action = NULL;
            free(act);
        }
    }

    unlock(&thread->lock);
}

static void
__handle_one_signal (shim_tcb_t * tcb, int sig, struct shim_signal * signal,
                     PAL_PTR event, PAL_CONTEXT * context)
{
    struct shim_thread * thread = (struct shim_thread *) tcb->tp;
    void (*handler) (int, siginfo_t *, void *) = NULL;
    void (*restorer) (void) = NULL;

    if (signal->info.si_signo == SIGCP) {
        join_checkpoint(thread, SI_CP_SESSION(&signal->info));
        return;
    }

    debug("%s handled\n", signal_name(sig));
    /*
     * check if we're in LibOS or Pal before get_signal_handler() which
     * acquires thread->lock. It may cause deadlock if we tries to lock
     * from host signal handler.
     */
    if (context == NULL ||
        ((context_is_internal(context) &&
          !is_signal_allowed(context)) ||
         DkInPal(context))) {

        /* TODO queue signal without malloc() */

        /*
         * host signal handler is called during PAL or LibOS.
         * It means thread is in systeam call emulation. actual signal
         * delivery is done by deliver_signal_on_sysret()
         */
        debug("appending signal for trigger syscall return  "
              "%p (%d, %p, %p)\n", handler, sig, &signal->info,
              &signal->context);
        debug("waking up for signal "
              "thread: %p tcb: %p, tcb->flags: %p 0x%lx tid: %d\n",
              thread, tcb, &tcb->flags, tcb->flags, tcb->tid);
        set_bit(SHIM_FLAG_SIGPENDING, &thread->shim_tcb->flags);
        return;
    }

    get_signal_handler(thread, sig, &handler, &restorer);
    if ((void *) handler == (void *) 1) /* SIG_IGN */
        return;

    if (!handler && !(handler = default_sighandler[sig - 1]))
        return;

    /* if the context is never stored in the signal, it means the
       signal is handled during system calls, and before the thread
       is resumed. */
    if (!signal->context_stored)
        __store_context(tcb, NULL, signal);

    __setup_sig_frame(tcb, sig, signal, event, context,
                      handler, restorer);
}

int __handle_signal (shim_tcb_t * tcb, int sig,
                     PAL_PTR event, PAL_CONTEXT * context)
{
    if (event == NULL || context == NULL) {
        /* TODO: implement here. Deliver signal to user program */
        if (tcb->flags & SHIM_FLAG_SIGPENDING)
            debug("FIXME __handle_signal flags 0x%lx\n", tcb->flags);
        __preempt_clear_delayed(tcb);
        return 0;
    }

#if 0
    if (event != NULL &&
        ((context_is_internal(&event->context) &&
          !is_signal_allowed(&event->context)) ||
         DkInPal(&event->context))) {
        debug("__handle_signal: in libos. just returning "
              "rip 0x%08lx +0x%08lx\n",
              event->context.rip, (void *) event->context.rip - (void *) &__load_address);
        return 0;
    }
#else
    if (context != NULL &&
        ((context_is_internal(context) &&
          !is_signal_allowed(context)) ||
         DkInPal(context))) {
        debug("__handle_signal: in libos. just returning "
              "rip 0x%08lx +0x%08lx\n",
              context->rip,
              (void *) context->rip - (void *) &__load_address);
        return 0;
    }
#endif

    struct shim_thread * thread = (struct shim_thread *) tcb->tp;
    int begin_sig = 1, end_sig = NUM_KNOWN_SIGS;

    if (sig)
        end_sig = (begin_sig = sig) + 1;

    sig = begin_sig;

    __preempt_clear_delayed(tcb);
    while (atomic_read(&thread->has_signal)) {
        struct shim_signal * signal = NULL;

        __preempt_clear_delayed(tcb);
        for ( ; sig < end_sig ; sig++)
            if (!__sigismember(&thread->signal_mask, sig) &&
                (signal = fetch_signal_log(thread, sig)))
                break;

        if (!signal)
            break;

        if (!signal->context_stored)
            __store_context(tcb, NULL, signal);

        __handle_one_signal(tcb, sig, signal, event, context);
        free(signal);
        DkThreadYieldExecution();
        if (event != NULL && context != NULL)
            return 1;
    }

    return 0;
}

void handle_sysret_signal(void)
{
    shim_tcb_t * tcb = shim_get_tls();
    struct shim_thread * thread = (struct shim_thread *) tcb->tp;
    struct shim_regs * regs = tcb->context.regs;
    debug("sysret signal: regs %p stack: %lx rip: %lx orig_rax: %lx rcx: 0x%lx\n",
          regs, regs? regs->rsp: 0, regs? regs->rip: 0,
          regs? regs->orig_rax: 0, tcb->context.regs? tcb->context.regs->rcx: 0);

    debug("thread: %p tcb: %p &flags: %p flags: 0x%lx (counter = %ld) stack: %p\n",
          thread, tcb, &tcb->flags, tcb->flags, thread->has_signal.counter,
          &tcb);

    clear_bit(SHIM_FLAG_SIGPENDING, &tcb->flags);
    /* This doesn't take user signal mask into account.
       peek_signal_log would be needed. not fetch_signal_log */
    if (atomic_read(&thread->has_signal))
        set_bit(SHIM_FLAG_SIGPENDING, &tcb->flags);
}

void handle_signal (bool delayed_only)
{
    shim_tcb_t * tcb = shim_get_tls();
    assert(tcb);

    struct shim_thread * thread = (struct shim_thread *) tcb->tp;

    /* Fast path */
    if (!thread || !atomic_read(&thread->has_signal))
        return;

    debug("handle signal (counter = %ld)\n", atomic_read(&thread->has_signal));

    int64_t preempt = __disable_preempt(tcb);

    if ((preempt & ~SIGNAL_DELAYED) > 1) {
        debug("signal delayed (%ld)\n", preempt & ~SIGNAL_DELAYED);
        __preempt_set_delayed(tcb);
        set_bit(SHIM_FLAG_SIGPENDING, &tcb->flags);
        __enable_preempt(tcb);
    } else {
        do {
            if (!delayed_only || (preempt & SIGNAL_DELAYED))
                __handle_signal(tcb, 0, NULL, NULL);
            preempt = atomic_cmpxchg(&tcb->context.preempt, 1, 0);
        } while (preempt != 1);
    }

    debug("__enable_preempt: %s:%d\n", __FILE__, __LINE__);
}

static void __setup_next_sig_frame(
    shim_tcb_t * tcb, int sig, struct shim_signal * signal,
    ucontext_t * user_uc,
    void (*handler) (int, siginfo_t *, void *), void (*restorer) (void))
{
    __UNUSED(tcb);
    __UNUSED(signal);
    struct sigframe * user_sigframe = (struct sigframe*)(((void *)user_uc) - 8);

    user_sigframe->restorer = restorer;
    struct shim_regs * regs = tcb->context.regs;
    regs->rsp = (unsigned long)user_sigframe;
    regs->rip = (unsigned long)handler;
    regs->rdi = (unsigned long)sig;
    regs->rsi = (unsigned long)&user_sigframe->info;
    regs->rdx = (unsigned long)&user_sigframe->uc;

    // TODO signal mask

    // TODO initialize more fp registers.
    __asm__ __volatile__("fninit\n");
}

struct sig_deliver
{
    int sig;
    struct shim_signal * signal;
    void (*handler) (int, siginfo_t *, void *);
    void (*restorer) (void);
};

static bool __get_signal_to_deliver(struct sig_deliver * deliver)
{
    deliver->signal = NULL;
    struct shim_thread * thread = get_cur_thread();

    while (atomic_read(&thread->has_signal)) {
        struct shim_signal * signal = NULL;
        /* signul number starts from 1 */
        int sig;
        for (sig = 1 ; sig < NUM_KNOWN_SIGS ; sig++)
            if (!__sigismember(&thread->signal_mask, sig) &&
                (signal = fetch_signal_log(thread, sig)))
                break;

        if (!signal)
            break;

        void (*handler) (int, siginfo_t *, void *);
        void (*restorer) (void);
        get_signal_handler(thread, sig, &handler, &restorer);
        if ((void *) handler == (void *) 1) /* SIG_IGN */
            continue;

        if (!handler && !(handler = default_sighandler[sig - 1]))
            continue;

        deliver->sig = sig;
        deliver->signal = signal;
        deliver->handler = handler;
        deliver->restorer = restorer;
        return true;
    }
    return false;
}


int handle_next_signal(ucontext_t * user_uc)
{
    struct sig_deliver deliver;
    if (__get_signal_to_deliver(&deliver)) {
        __setup_next_sig_frame(shim_get_tls(), deliver.sig, deliver.signal,
                               user_uc, deliver.handler, deliver.restorer);
        free(deliver.signal);
        return 1;
    }
    return 0;
}

/*
 * 16-byte alignment on ucontext_t on signal frame
 * align struct shim_regs to 8 (mod 16) bytes
 * => align sigframe->us to 16 bytes
 */
_Static_assert(
    (((8 + sizeof(struct shim_regs)) + offsetof(struct sigframe, uc)) % 16) == 0,
    "signal stack frame isn't aligned to 16 byte on calling deliver_signal_on_sysret");

bool deliver_signal_on_sysret(void * stack, uint64_t syscall_ret)
{
    shim_tcb_t * tcb = shim_get_tls();

    struct sig_deliver deliver;
    struct shim_regs * tmp = tcb->context.regs;
    debug("regs: %p sp: %08lx ip: %08lx stack: %p &tcb %p tcb %p\n",
          tmp, tmp->rsp, tmp->rip, stack, &tcb, tcb);

    clear_bit(SHIM_FLAG_SIGPENDING, &tcb->flags);
    /* FIXME: sigsuspend, sigwait, sigwaitinfo, pselect, ppoll are
     * broken because signal mask was changed when blocking and
     * is restored on returning from system call.
     * So we miss the signal which is masked in user space and
     * unmasked during blocking.
     */
    if (!__get_signal_to_deliver(&deliver)) {
        debug("no deliverable signal\n");
        return false;
    }

    int sig = deliver.sig;
    struct shim_signal * signal = deliver.signal;
    void (*handler) (int, siginfo_t *, void *) = deliver.handler;
    void (*restorer) (void) = deliver.restorer;
    direct_call_if_sighandler_kill(sig, &signal->info, handler);

#ifdef SHIM_SYSCALL_STACK
    bool rewind_syscall_stack = false;
    if ((void*)tcb->context.regs->rip == &syscall_wrapper_after_syscalldb) {
        rewind_syscall_stack = true;
        struct shim_regs* regs = tcb->context.regs;
        assert((unsigned long)tcb->tp->syscall_stack < regs->rsp);
        assert(regs->rsp <=
               (unsigned long)tcb->tp->syscall_stack +
               SHIM_THREAD_SYSCALL_STACK_SIZE);
        /* see syscall_wrapper()
         * signal frame needs to be created basedon actual user stack frame.
         * Not on syscall stack.
         * So emulate switching back to user stack first.
         */
        regs->rsp = tcb->context.regs->r11;
        regs->rip = tcb->context.regs->rcx;
        debug("syscall stack regs: %p sp: %08lx ip: %08lx stack: %p &tcb %p tcb %p %p\n",
              regs, regs->rsp, regs->rip, stack, &tcb, tcb,
              &syscall_wrapper_after_syscalldb);
    }
#endif

#if 0
    struct shim_regs * regs = stack;
    stack += sizeof(*regs);
    struct sigframe * user_sigframe = stack;
#else
    /* on syscall entry, red zone is already allocated. */
    void * sp = __get_signal_stack(tcb->tp, stack);
    bool switch_stack = (sp != stack);
    struct shim_regs * regs;
    struct sigframe * user_sigframe;
    if (switch_stack) {
        regs = tcb->context.regs;

        /* See .Lsignal_pending @ syscallas.S */
        sp -= sizeof(struct sigframe) + FP_XSTATE_MAGIC2_SIZE + 64;
        sp -= fpu_xstate_size;
        sp = aligndown_sigframe(sp);
        stack = sp;
        user_sigframe = stack;
#ifdef SHIM_SYSCALL_STACK
    } else if(rewind_syscall_stack) {
        switch_stack = true;

        regs = tcb->context.regs;

        sp = (void*)regs->rsp;
        sp -= RED_ZONE_SIZE;
        /* See .Lsignal_pending @ syscallas.S */
        sp -= sizeof(struct sigframe) + FP_XSTATE_MAGIC2_SIZE + 64;
        sp -= fpu_xstate_size;
        sp = aligndown_sigframe(sp);
        stack = sp;
        user_sigframe = stack;
#endif
    } else {
        regs = stack;
        /* move up context.regs on stack*/
        memcpy(regs, tcb->context.regs, sizeof(*regs));
        tcb->context.regs = regs;

        stack += sizeof(*regs);
        user_sigframe = stack;
    }
#endif
    assert(&user_sigframe->uc == ALIGN_UP_PTR(&user_sigframe->uc, 16UL));
    stack += sizeof(*user_sigframe);
    stack = ALIGN_UP_PTR(stack, 64UL);
    struct _libc_fpstate * user_fpstate = stack;

    debug("regs: %p sigframe: %p uc: %p fpstate: %p\n",
          regs, user_sigframe, &user_sigframe->uc, user_fpstate);

#if 0
    /* move up context.regs on stack*/
    memcpy(regs, tcb->context.regs, sizeof(*regs));
    tcb->context.regs = regs;
#endif

    /* setup sigframe */
    user_sigframe->restorer = restorer;

    ucontext_t * user_uc = &user_sigframe->uc;
    user_uc->uc_flags = UC_FP_XSTATE;
    user_uc->uc_link = NULL;
#if 0
    user_uc->uc_stack.ss_sp = 0;
    user_uc->uc_stack.ss_size = 0;
    user_uc->uc_stack.ss_flags = SS_DISABLE;
#else
    user_uc->uc_stack = tcb->tp->signal_altstack;
#endif

    gregset_t * gregs = &user_uc->uc_mcontext.gregs;
    (*gregs)[REG_R8] = regs->r8;
    (*gregs)[REG_R9] = regs->r9;
    (*gregs)[REG_R10] = regs->r10;
    (*gregs)[REG_R11] = regs->r11;
    (*gregs)[REG_R12] = regs->r12;
    (*gregs)[REG_R13] = regs->r13;
    (*gregs)[REG_R14] = regs->r14;
    (*gregs)[REG_R15] = regs->r15;
    (*gregs)[REG_RDI] = regs->rdi;
    (*gregs)[REG_RSI] = regs->rsi;
    (*gregs)[REG_RBP] = regs->rbp;
    (*gregs)[REG_RBX] = regs->rbx;
    (*gregs)[REG_RDX] = regs->rdx;
    (*gregs)[REG_RAX] = syscall_ret;
    (*gregs)[REG_RCX] = regs->rcx;
    (*gregs)[REG_RSP] = regs->rsp;
    (*gregs)[REG_RIP] = regs->rip;
    (*gregs)[REG_EFL] = regs->rflags;
    union csgsfs sr = {
        .cs = 0x33, // __USER_CS(5) | 0(GDT) | 3(RPL)
        .fs = 0,
        .gs = 0,
        .ss = 0x2b, // __USER_DS(6) | 0(GDT) | 3(RPL)
    };
    (*gregs)[REG_CSGSFS] = sr.csgsfs;

    (*gregs)[REG_ERR] = signal->info.si_errno;
    (*gregs)[REG_TRAPNO] = signal->info.si_code;
    (*gregs)[REG_OLDMASK] = 0;
    (*gregs)[REG_CR2] = (long)signal->info.si_addr;

    user_uc->uc_mcontext.fpregs = user_fpstate;
    memset(user_fpstate, 0, fpu_xstate_size);

    long lmask = -1;
    long hmask = -1;
    assert(user_fpstate == ALIGN_DOWN_PTR(user_fpstate, 64UL));
    __asm__ volatile("xsave64 (%0)"
                     :: "r"(user_fpstate), "m"(*user_fpstate),
                      "a"(lmask), "d"(hmask)
                     : "memory");
    struct _fpx_sw_bytes * user_sw = &user_fpstate->sw_reserved;
    user_sw->magic1 = FP_XSTATE_MAGIC1;
    user_sw->extended_size = fpu_xstate_size + FP_XSTATE_MAGIC2_SIZE;
    user_sw->xstate_size = fpu_xstate_size;
    *((__typeof__(FP_XSTATE_MAGIC2)*)((void*)user_fpstate + user_sw->xstate_size))
        = FP_XSTATE_MAGIC2;

    // TODO initialize by XRESTORE64
    __asm__ volatile("fninit");

    // TODO. get current sigmask and mask signal
    // XXX sigaction();
    __sigemptyset(&user_uc->uc_sigmask);

    free(signal);

#if 0
    // setup to return to signal handler
    // tcb->context.sp = (void *)user_sigframe;
    // tcb->context.ret_ip = (void *)handler;
    regs->rip = (unsigned long)handler;
    regs->rdi = (unsigned long)sig;
    regs->rsi = (unsigned long)&user_sigframe->info;
    regs->rdx = (unsigned long)&user_sigframe->uc;
#else
    if (switch_stack) {
        /* gave up preserving registers for now.
         * Directly switch stack and jump to signal handler.
         * This behavior is different from Linux kernel.
         * TODO: switch stack and return to let .Lret_signal @ syscallas.S
         *       handle it to preserve registers to match linux kernel
         *       behavior.
         *       It doesn't matter for normal application in practice?
         */
        __asm__ volatile (
            "movq %%rbx, %%rsp\n"
            "jmpq *%%rcx\n"
            ::
             "D"((long)sig),
             "S"((unsigned long)&user_sigframe->info),
             "d"((unsigned long)&user_sigframe->uc),
             "a"(0),
             "c"((long)handler), "b"(user_sigframe));
        /* NOTREACHED */
    } else {
        // setup to return to signal handler
        // tcb->context.sp = (void *)user_sigframe;
        // tcb->context.ret_ip = (void *)handler;
        regs->rip = (unsigned long)handler;
        regs->rdi = (unsigned long)sig;
        regs->rsi = (unsigned long)&user_sigframe->info;
        regs->rdx = (unsigned long)&user_sigframe->uc;
    }
#endif

    return true;
}

void append_signal (struct shim_thread * thread, int sig, siginfo_t * info,
                    bool wakeup)
{
    struct shim_signal * signal = malloc(sizeof(struct shim_signal));
    if (!signal)
        return;

    /* save in signal */
    if (info) {
        __store_info(info, signal);
        signal->context_stored = false;
    } else {
        memset(signal, 0, sizeof(struct shim_signal));
    }

    struct shim_signal ** signal_log = allocate_signal_log(thread, sig);

    if (signal_log) {
        *signal_log = signal;
    } else {
        SYS_PRINTF("signal queue is full (TID = %u, SIG = %d)\n",
                   thread->tid, sig);
        free(signal);
    }
    if (wakeup) {
        debug("resuming thread %u\n", thread->tid);
        thread_wakeup(thread);
        DkThreadResume(thread->pal_handle);
    }
}

static void sighandler_kill (int sig, siginfo_t * info, void * ucontext)
{
    __UNUSED(ucontext);
    debug("killed by %s\n", signal_name(sig));

    if (!info->si_pid)
        switch(sig) {
            case SIGTERM:
            case SIGINT:
                shim_do_kill(-1, sig);
                break;
        }

    try_process_exit(0, sig);
    DkThreadExit();
}

/* We don't currently implement core dumps, but put a wrapper
 * in case we do in the future */
static void sighandler_core (int sig, siginfo_t * info, void * ucontext)
{
    sighandler_kill(sig, info, ucontext);
}

static void direct_call_if_sighandler_kill(
    int sig, siginfo_t * info, void (*handler) (int, siginfo_t *, void *))
{
    /* we know sighandler_kill only kill the thread
     * without using info and context */
    if (handler == &sighandler_kill) {
        debug("direct calling sighandler_kill\n");
        // this thread exits.
        handler(sig, info, NULL);
    }
}

static void (*default_sighandler[NUM_SIGS]) (int, siginfo_t *, void *) =
    {
        /* SIGHUP */    &sighandler_kill,
        /* SIGINT */    &sighandler_kill,
        /* SIGQUIT */   &sighandler_kill,
        /* SIGILL */    &sighandler_kill,
        /* SIGTRAP */   &sighandler_core,
        /* SIGABRT */   &sighandler_kill,
        /* SIGBUS */    &sighandler_kill,
        /* SIGFPE */    &sighandler_kill,
        /* SIGKILL */   &sighandler_kill,
        /* SIGUSR1 */   NULL,
        /* SIGSEGV */   &sighandler_kill,
        /* SIGUSR2 */   NULL,
        /* SIGPIPE */   &sighandler_kill,
        /* SIGALRM */   &sighandler_kill,
        /* SIGTERM */   &sighandler_kill,
        /* SIGSTKFLT */ NULL,
        /* SIGCHLD */   NULL,
        /* SIGCONT */   NULL,
        /* SIGSTOP */   NULL,
        /* SIGTSTP */   NULL,
        /* SIGTTIN */   NULL,
        /* SIGTTOU */   NULL,
    };
