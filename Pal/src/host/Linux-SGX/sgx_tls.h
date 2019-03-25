#ifndef __SGX_TLS_H__
#define __SGX_TLS_H__

/*
 * Beside the classic thread local storage (like ustack, thread, etc.) the TLS
 * area is also used to pass parameters needed during enclave or thread
 * initialization. Some of them are thread specific (like tcs_offset) and some
 * of them are identical for all threads (like enclave_size).
 */
struct enclave_tls {
    PAL_TCB common;
    struct {
        /* privateto Pal/Linux-SGX */
        uint64_t enclave_size;
        uint64_t tcs_offset;
        uint64_t initial_stack_offset;
        uint64_t sig_stack_low;
        uint64_t sig_stack_high;
#define SGX_TLS_FLAGS_ASYNC_EVENT_PENDING_BIT   (0)
#define SGX_TLS_FLAGS_EVENT_EXECUTING_BIT       (1)
#define SGX_TLS_FLAGS_ASYNC_ENVET_PENDING       (1UL << SGX_TLS_FLAGS_ASYNC_ENVET_PENDING_BIT)
#define SGX_TLS_FLAGS_EVENT_EXECUTING           (1UL << SGX_TLS_FLAGS_ENVET_EXECUTING_BIT)
        uint64_t flags;
#define PAL_EVENT_MASK(event)   (1UL << (event))
#define PAL_ASYNC_EVENT_MASK                    \
        (PAL_EVENT_MASK(PAL_EVENT_QUIT) |       \
         PAL_EVENT_MASK(PAL_EVENT_SUSPEND) |    \
         PAL_EVENT_MASK(PAL_EVENT_RESUME))
        uint64_t pending_async_event;
        struct atomic_int event_nest;
        struct ocall_marker_buf * ocall_marker;
        void *   aep;
        void *   ssa;
        sgx_arch_gpr_t * gpr;
        void *   exit_target;
        void *   fsbase;
        void *   stack;
        void *   ustack_top;
        void *   ustack;
        struct pal_handle_thread * thread;
        uint64_t ocall_prepared;
        uint64_t ecall_called;
        uint64_t ready_for_exceptions;
        uint64_t manifest_size;
        void *   heap_min;
        void *   heap_max;
        void *   exec_addr;
        uint64_t exec_size;
    };
};

#ifndef DEBUG
extern uint64_t dummy_debug_variable;
#endif

# ifdef IN_ENCLAVE
#  define GET_ENCLAVE_TLS(member)                                   \
    ({                                                              \
        struct enclave_tls * tmp;                                   \
        uint64_t val;                                               \
        _Static_assert(sizeof(tmp->member) == 8,                    \
                       "sgx_tls member should have 8bytes type");   \
        __asm__ ("movq %%gs:%c1, %q0": "=r" (val)                   \
             : "i" (offsetof(struct enclave_tls, member)));         \
        (__typeof(tmp->member)) val;                                \
    })
#  define SET_ENCLAVE_TLS(member, value)                            \
    do {                                                            \
        struct enclave_tls * tmp;                                   \
        _Static_assert(sizeof(tmp->member) == 8,                    \
                       "sgx_tls member should have 8bytes type");   \
        _Static_assert(sizeof(value) == 8,                          \
                       "only 8 bytes type can be set to sgx_tls");  \
        __asm__ ("movq %q0, %%gs:%c1":: "r" (value),                \
             "i" (offsetof(struct enclave_tls, member)));           \
    } while (0)

static inline struct enclave_tls * get_enclave_tls(void)
{
    return (struct enclave_tls*)pal_get_tcb();
}
# endif

#endif /* __SGX_TLS_H__ */
