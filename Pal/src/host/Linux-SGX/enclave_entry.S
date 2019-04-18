#include "sgx_arch.h"
#include "asm-offsets.h"

# In some cases, like bogus parameters passed to enclave_entry, it's tricky to
# return cleanly (passing the correct return address to EEXIT, OCALL_EXIT can
# be interrupted, etc.). Since those cases should only ever happen with a
# malicious urts, just go into an endless loop.
.macro FAIL_LOOP
.Lfail_loop\@:
	jmp .Lfail_loop\@
.endm

.macro WRFSBASE_RBX
	.byte 0xf3, 0x48, 0x0f, 0xae, 0xd3 /* WRFSBASE %RBX */
.endm

	.extern ecall_table
	.extern enclave_ecall_pal_main

	.global enclave_entry
	.type enclave_entry, @function

enclave_entry:
	# On EENTER, RAX is the current SSA index (aka CSSA),
	# RBX is the address of TCS, RCX is the address of AEP.
	# Other registers are not trusted.

	# x86-64 sysv abi requires %rFLAGS.DF = 0 on entry to function call.
	cld

	cmpq $0, %rax
	jne .Lprepare_resume

	# The following code is hardened to defend attacks from untrusted host.
	# Any states given by the host instead of the ISA must be assumed
	# potentially malicious.
	#
	# For instance, Jo Van Bulck contributed a detailed vulnerability report
	# in https://github.com/oscarlab/graphene/issues/28. (Fixed)
	# Brief description of the vulnerabilities:
	# The previous implementation does not check the index of entry
	# functions (RDI at enclave entry) given by the untrusted PAL.
	# An attacker can cause overflow/underflow to jump to random
	# locaion in enclaves. Moreover, we used a specific index
	# (RETURN_FROM_OCALL) to tell if the control flow is returned
	# from a OCALL in the untrusted PAL. Attackers can manipulate RDI
	# to deceive the trusted PAL.

	# This thread can be interrupted but then the above check branches to
	# .Lprepare_resume. So the outside can't re-enter the checks below in
	# the middle.

	# Only jump to .Lreturn_from_ocall if we have prepared the stack for
	# it.
	cmpq $0, %gs:SGX_OCALL_PREPARED
	jne .Lreturn_from_ocall

	movq %rcx, %gs:SGX_AEP

	# Ecalls are only used to start a thread (either the main or an
	# additional thread). So per thread we should only get exactly one
	# ecall. Enforce this here.
	cmpq $0, %gs:SGX_ECALL_CALLED
	je 1f
	FAIL_LOOP
1:
	movq $1, %gs:SGX_ECALL_CALLED

	# PAL convention:
	# RDI - ECALL number
	# RSI - prointer to ecall arguments
	# RDX - exit target
	# RCX (former RSP) - The untrusted stack
	# R8  - enclave base

	# calculate enclave base = RBX (trusted) - %gs:SGX_TCS_OFFSET
	subq %gs:SGX_TCS_OFFSET, %rbx
	movq %rbx, %r8

	# push untrusted stack address to RCX
	movq %rsp, %rcx

	# switch to enclve stack: enclave base + %gs:SGX_INITIAL_STACK_OFFSET
	addq %gs:SGX_INITIAL_STACK_OFFSET, %rbx
	movq %rbx, %rsp

	# clear the rest of register states
	xorq %rax, %rax
	xorq %rbx, %rbx
	xorq %r9,  %r9
	xorq %r10, %r10
	xorq %r11, %r11
	xorq %r12, %r12
	xorq %r13, %r13
	xorq %r14, %r14
	xorq %r15, %r15

	# register states need to be carefully checked, so we move the handling
	# to handle_ecall() in enclave_ecalls.c
	callq handle_ecall

	# handle_ecall will only return when invalid parameters has been passed.
	FAIL_LOOP

.Lprepare_resume:
	# PAL convention:
	# RDI - external event

	# Nested exceptions at the host-OS level are disallowed:
	# - Synchronous exceptions are assumed to never happen during
	#   prepare_resume;
	# - Asynchronous signals are not nested by benign host OS because
	#   we mask asynchronous signals on signal handler.
	# If malicious host OS injects a nested signal, CSSA != 1 and we go
	# into FAIL_LOOP. Currently this check is assertion only because it
	# is also enforced by EENTER since enclave is created with NSSA=2.
	cmpq $1, %rax
	je 1f
	FAIL_LOOP
1:

	# get some information from GPR
	movq %gs:SGX_GPR, %rbx

	movq %rdi, %rsi
	xorq %rdi, %rdi
	movl SGX_GPR_EXITINFO(%rbx), %edi
	testl $0x80000000, %edi
	jnz .Lhandle_exception

	movl %esi, %edi
	# use external event - only the first 8 bits count
	andl $0xff, %edi
	cmpl $0, %edi
	jne .Lhandle_exception

	# clear the registers
	xorq %rdi, %rdi
	xorq %rsi, %rsi

	# exit address in RDX, mov it to RBX
	movq %rdx, %rbx

	jmp .Lclear_and_eexit

.Lhandle_exception:
	# If this enclave thread has not been initialized yet, we should not
	# try to call an event handler yet.
	cmpq $0, %gs:SGX_READY_FOR_EXCEPTIONS
	jne 1f
	FAIL_LOOP
1:

	## There is a race between host signal delivery and restoring %rsp
	## in this entry code. We must be careful to setup %rsp.
	##
	## Race scenario
	## 1. We are inside the enclave but %rsp isn't restored yet to something
	##    inside the enclave. That's for example the case when returning from
	##    an ocall.
	## 2. The enclave gets interrupted. The not restored %rsp is pushed into
	##    SGX_GPR_RSP by the processor.
	## 3. The host enters the enclave again and indicated that there's a new
	##    signal.
	## 4. The code after .Lhandle_exception pushes stuff on the untrusted
	##    stack (because SGX_GPR_RSP points there) and then diverts %rip to
	##    execute the event handler after ERESUME (which will use the untrusted
	##    stack).
	##
	## The solution is to have a "fallback" value stored in SGX_STACK.
	## If SGX_STACK == 0, then %rsp was correctly restored during
	## Lreturn_from_ocall and the interrupt happened after that, so the CPU
	## pushed the restored %rsp into SGX_GPR_RSP, thus we can safely use
	## SGX_GPR_RSP.
	## However, if SGX_STACK != 0, this indicates that the interrupt came
	## before xchgq %rsp, %gs:SGX_STACK and %rsp was not yet restored,
	## so the CPU pushed some untrusted %rsp into SGX_GPR_RSP. Thus, we
	## cannot trust value in SGX_GPR_RSP and should fall-back to using
	## SGX_STACK (which was updated with the last known good in-enclave
	## %rsp before EEXIT in sgx_ocall).
	##
	## The SGX_STACK swap logic does not need to be atomic because nested
	## exceptions are disallowed by SGX due to TCS.NSSA == 2
	## (thus, .Lhandle_exception logic cannot be nested)

	movq %gs:SGX_STACK, %rsi
	cmpq $0, %rsi
	je .Lsetup_exception_handler

	# Assertion:
	# SGX_OCALL_PREPARED set to 1 before SGX_STACK is set to enclave stack.
	# SGX_OCALL_PREPARED set to 0 after SGX_STACK is set to 0.
	cmpq $0, %gs:SGX_OCALL_PREPARED
	jne 1f
	FAIL_LOOP
1:
	# At this point, we are in the exception handler,
	# SGX_STACK=<trusted pointer to enclave stack>, SGX_OCALL_PREPARED=1,
	# i.e. we are interrupted during handling of enclave's
	# sgx_ocall/return_from_ocall assembly code.
	#
	# Triggering the exception handler while SGX_STACK/SGX_OCALL_PREPARED
	# != 0 would be problematic because it could itself issue nested ocalls.
	# This would mean the SGX_OCALL_PREPARED and SGX_STACK logic would need to
	# handle nesting.
	#
	# Instead if we're in such situation, we emulate it as if %rip reached to
	# the safe point, .Lreturn_from_ocall_after_clear_ocall_prepared.
	#
	# Ocall sequence:
	#  0. call sgx_ocall()
	#  1. .Locall_before_set_ocall_prepared:
	#  2. SGX_OCALL_PREPARED=1
	#  3. .Locall_after_set_ocall_prepared:
	#  4. SGX_STACK=%rsp: save trusted stack
	#  5. EEXIT
	#  6. untrusted PAL which issues real host system call
	#  7. EENTER (and start from enclave_entry)
	#  8. .Lreturn_from_ocall:
	#  9. (%rsp, SGX_STACK) = (SGX_STACK, 0): restore trusted stack
	# 11. .Lreturn_from_ocall_before_clear_ocall_prepared:
	# 12. SGX_OCALL_PREPARED=0
	# 13. .Lreturn_from_ocall_after_clear_ocall_prepared:
	# 14. call _DkHandleExternalEvent() if interrupted
	# 15. return from sgx_ocall() to the caller
	#
	# It is also required that sgx_ocall() be atomic regarding to async exception.
	# When host async signal arrives, sgx_ocall() should result in EINTR.
	#
	# There are three possibilities when exactly host async signal arrives:
	# A. before exiting enclave to perform host syscall
	# B. after exiting enclave and before re-entering enclave
	#    (i.e., during untrusted execution of host syscall)
	# C. after re-entering enclave but before returning to sgx_ocall().
	#
	# Note that Case A didn't even issue host syscall, Case B may have
	# interrupted host syscall (but maybe interrupt came after successful
	# host syscall), and Case C was interrupted after successful host
	# syscall. In Case C, the result of host system call must be preserved
	# to be replayed in later invocation.
	#
	# On host async signal we treat these cases as follows:
	# A. right-before EEXIT(0. - 4. in above sequence):
	#	 - set PAL_ERROR_INTERRUPTED and forward %rip to exception handler
	# B. during untrusted PAL(5. - 6. in above sequence):
	#	 - code in _DkTerminateSighandler() must handle this case
	#	 TODO: fix _DkTerminateSighandler() to not lose the result of successful
	#		   system call.
	# C. right-after EENTER(7. - 15. in above sequence):
	#	 - ocall succeeded, forward %rip to exception handler

	# Find out which of cases A, B, or C happened:
	# - copy rip at which the enclave was interrupted into %rax,
	# - copy the boundaries between cases A, B, and C into %r11,
	# - compare enclave's rip against these boundaries (%rax vs %r11).
	movq SGX_GPR_RIP(%rbx), %rax
	leaq .Locall_about_to_eexit_begin(%rip), %r11
	cmpq %r11, %rax
	jb 2f
	leaq .Locall_about_to_eexit_end(%rip), %r11
	cmpq %r11, %rax
	jae 2f

	# Case A. We are right-before EEXIT for ocall in between
	# [.Locall_about_to_eexit_begin, .Locall_about_to_eexit_end)
	# Skip EEXIT as if ocall returned PAL_ERROR_INTERRUPTED.
	# If there is registered signal handler for the current exception,
	# _DkHandleExternalEvent() will be called (and thus we need to save
	# %rdi = <external event>) before returning from ocall.
	movq $-PAL_ERROR_INTERRUPTED, %rdi # return value for .Lreturn_from_ocall
	# fallthrough to Case C.

	# This code cannot land in Case B because:
	# (1) this code path (.Lhandle_exception) is triggered only if we haven't
	# yet exited the enclave when signal arrived, and
	# (2) in Case B, we exited the enclave and signal arrived while in
	# untrusted code. The two conditions cannot be true at the same time,
	# so Case B never happens here (Case B results in return_from_ocall code
	# path below).

2:
	# Case C. We are right-after EENTER returning from successful ocall.
	# Move %rip to .Lreturn_from_ocall_after_clear_ocall_prepared and let
	# _DkHandleExternalEvent() handle the exception.
	# SGX_GPR_RDI(%rbx): don't touch successful ocall result.
	movq %rdi, SGX_GPR_RSI(%rbx) # external event for .Lreturn_from_ocall
	leaq .Lreturn_from_ocall_after_clear_ocall_prepared(%rip), %rax
	movq %rax, SGX_GPR_RIP(%rbx)
	movq %rsi, SGX_GPR_RSP(%rbx)
	movq $0, %gs:SGX_STACK
	movq $0, %gs:SGX_OCALL_PREPARED
	xorq %r11, %r11
	jmp .Leexit_exception

.Lsetup_exception_handler:
	# Avoid overwriting SGX_OCALL_PREPARED after exception handler when
	# SGX_OCALL_PREPARED is set,
	# - if saved %rip == .Locall_after_set_ocall_prepared
	#   rewind movq $1, %gs:SGX_OCALL_PREPARED
	# - if saved %rip == .Lreturn_from_ocall_before_clear_ocall_prepared
	#   emulate movq $0, %gs:SGX_OCALL_PREPARED
	leaq .Locall_after_set_ocall_prepared(%rip), %rax
	cmpq %rax, SGX_GPR_RIP(%rbx)
	jne 3f
	leaq .Locall_before_set_ocall_prepared(%rip), %rax
	movq %rax, SGX_GPR_RIP(%rbx)
	movq $0, %gs:SGX_OCALL_PREPARED
	jmp 4f
3:

	leaq .Lreturn_from_ocall_before_clear_ocall_prepared(%rip), %rax
	cmpq %rax, SGX_GPR_RIP(%rbx)
	jne 4f
	leaq .Lreturn_from_ocall_after_clear_ocall_prepared(%rip), %rax
	movq %rax, SGX_GPR_RIP(%rbx)
	movq $0, %gs:SGX_OCALL_PREPARED
4:

	# %rbx SGX_GPR base address from TLS
	movq SGX_GPR_RSP(%rbx), %rsi

	movq %gs:SGX_SIG_STACK_LOW, %rax
	cmpq %rax, %rsi
	jbe .Lout_of_signal_stack
	movq %gs:SGX_SIG_STACK_HIGH, %rax
	cmpq %rax, %rsi
	ja .Lout_of_signal_stack
	jmp .Lon_signal_stack

.Lout_of_signal_stack:
	movq %gs:SGX_SIG_STACK_HIGH, %rsi
        /* staring from new stack. there is no red zone used.
         * offset it below calculation */
	addq $RED_ZONE_SIZE, %rsi

	/* 8 is to avoid redzone clobber */
#define STACK_PADDING_SIZE	(PAL_FP_XSTATE_MAGIC2_SIZE + 8)
#define STACK_FRAME_SUB \
	(SGX_CONTEXT_SIZE + RED_ZONE_SIZE + STACK_PADDING_SIZE)
.Lon_signal_stack:
	movq xsave_size@GOTPCREL(%rip), %rax
	movl (%rax), %eax
	addq $STACK_FRAME_SUB, %rax
	subq %rax, %rsi
	# Align xsave area to 64 bytes after sgx_context_t
	# SGX_CONTEXT_SIZE = sizeof(sgx_context_t) = 144
	# PAL_XSTATE_ALIGN = 64
	# SGX_CONTEXT_XSTATE_ALIGN_SUB=SGX_CONTEXT_SIZE % PAL_XSTATE_ALIGN = 16
	# unfortunatley gas doesn't understand
	# $(SGX_CONTEXT_SIZE % PAL_XSTATE_ALIGN)
	andq $~(PAL_XSTATE_ALIGN - 1), %rsi
	subq $SGX_CONTEXT_XSTATE_ALIGN_SUB, %rsi

	# we have exitinfo in RDI, swap with the one on GPR
	# and dump into the context
	xchgq %rdi, SGX_GPR_RDI(%rbx) # 1st argument for _DkExceptionHandler()
	movq %rdi, SGX_CONTEXT_RDI(%rsi)

	# dump the rest of context
	movq SGX_GPR_RAX(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RAX(%rsi)
	movq SGX_GPR_RCX(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RCX(%rsi)
	movq SGX_GPR_RDX(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RDX(%rsi)
	movq SGX_GPR_RBX(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RBX(%rsi)
	movq SGX_GPR_RSP(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RSP(%rsi)
	movq SGX_GPR_RBP(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RBP(%rsi)
	movq SGX_GPR_RSI(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RSI(%rsi)
	/* rdi is saved above */
	movq SGX_GPR_R8(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R8(%rsi)
	movq SGX_GPR_R9(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R9(%rsi)
	movq SGX_GPR_R10(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R10(%rsi)
	movq SGX_GPR_R11(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R11(%rsi)
	movq SGX_GPR_R12(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R12(%rsi)
	movq SGX_GPR_R13(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R13(%rsi)
	movq SGX_GPR_R14(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R14(%rsi)
	movq SGX_GPR_R15(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R15(%rsi)
	movq SGX_GPR_RFLAGS(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RFLAGS(%rsi)
	movq SGX_GPR_RIP(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RIP(%rsi)

	movq %rsi, SGX_GPR_RSP(%rbx)
	# Pass pointer to sgx_context_t to _DkExceptionHandler
	movq %rsi, SGX_GPR_RSI(%rbx) ## 2nd argument for _DkExceptionHandler()

	/* TODO: save EXINFO in MISC region */

	# x86-64 sysv abi requires 16B alignment of stack before call instruction
	# which implies a (8 mod 16)B alignment on function entry (due to implicit
	# push %rip).
	# Align the stack for _DkExceptionHandler according to this requirement.
	andq $STACK_ALIGN, %rsi
	subq $8, %rsi
	movq %rsi, SGX_GPR_RSP(%rbx)

	# clear rflags to conform the ABI which requires RFLAGS.DF = 0
	movq $0, SGX_GPR_RFLAGS(%rbx)

	# new RIP is the exception handler
	leaq _DkExceptionHandler(%rip), %rdi
	movq %rdi, SGX_GPR_RIP(%rbx)

.Leexit_exception:
	# FP registers are saved on entry of _DkExceptionHandler()

	# clear the registers
	xorq %rdi, %rdi
	xorq %rsi, %rsi

	# exit address in RDX, mov it to RBX
	movq %rdx, %rbx
	jmp .Lclear_and_eexit

#############################################################################
	.global sgx_ocall
	.type sgx_ocall, @function

sgx_ocall:
	##
	## input:
	## %rdi: code
	## %rsi: void * ms
	##
	## sgx_context_t:
	##   rax = 0: place holder
	##   rcx
	##   ...
	##   rflags
	##   rip
	## xsave area
	##   xregs
	## (padding)
	## ---
	## previous rbp
	## previous rip: pushed by callq
	##

	.cfi_startproc
	pushq %rbp
	.cfi_adjust_cfa_offset 8
	movq %rsp, %rbp
	.cfi_offset %rbp, -16
	.cfi_def_cfa_register %rbp

	## switch to signal stack if not yet.
	movq %gs:SGX_SIG_STACK_LOW, %rax
	cmpq %rax, %rsp
	jbe .Lout_of_signal_stack_ocall
	movq %gs:SGX_SIG_STACK_HIGH, %rax
	cmpq %rax, %rsp
	ja .Lout_of_signal_stack_ocall
	jmp .Lon_signal_stack_ocall

.Lout_of_signal_stack_ocall:
	movq %gs:SGX_SIG_STACK_HIGH, %rsp

.Lon_signal_stack_ocall:

	movq xsave_size@GOTPCREL(%rip), %rax
	movl (%rax), %eax
	addq $STACK_PADDING_SIZE, %rax
	subq %rax, %rsp
	andq $~(PAL_XSTATE_ALIGN - 1), %rsp

	pushq %rdx
	pushq %rdi
	movq %rsp, %rdi
	addq $2 * 8, %rdi	/* adjust pushq %rdx; pushq %rdi above */
	callq save_xregs
	popq %rdi
	popq %rdx

	movq 8(%rbp), %rax
	pushq %rax	# previous RIP
	pushfq

	# Under GDB, single-stepping sets Trap Flag (TP) of EFLAGS,
	# thus TP=1 is stored on pushfq above. Upon consequent popfq,
	# TP is 1, resulting in spurious trap. Reset TP here.
	andq $~0x100, (%rsp)

	pushq %r15
	pushq %r14
	pushq %r13
	pushq %r12
	pushq %r11
	pushq %r10
	pushq %r9
	pushq %r8
	pushq %rdi
	pushq %rsi
	movq (%rbp), %rax
	pushq %rax	# previous RBP
	leaq 16(%rbp), %rax
	pushq %rax	# previous RSP
	pushq %rbx
	pushq %rdx
	pushq %rcx
	pushq $0        # place holder for RAX

.Locall_before_set_ocall_prepared:
	movq $1, %gs:SGX_OCALL_PREPARED
.Locall_after_set_ocall_prepared:
	movq %rsp, %gs:SGX_STACK

.Locall_about_to_eexit_begin:
	# From here .Lhandle_exception can mess out with state (%rip and %rsp).
	# We therefore need to be extremely careful when making changes here.
	#
	# It's ok to use the untrusted stack and exit target below without
	# checks since the processor will ensure that after exiting enclave
	# mode in-enclave memory can't be accessed.

	movq %gs:SGX_USTACK, %rsp
	andq $STACK_ALIGN, %rsp

#ifdef DEBUG
	# Push %rip of some code inside __morestack() on untrusted stack.
	# At sgx_entry(), GDB deduces saved_rip by looking at CFA-8 = %rsp.
	leaq .Lfor_cfa_debug_info(%rip), %r8
	pushq %r8
#endif

	movq %gs:SGX_EXIT_TARGET, %rbx
	.cfi_endproc
	# fallthrough

	# Clear other registers and similar state and then call EEXIT
	#
	# Arguments for EEXIT/untrusted code (not cleared):
	#
	#     %rbx: exit target
	#     %rsp: untrusted stack
	#     %rdi, %rsi: (optional) arguments to untrusted code.
.Lclear_and_eexit:

#ifdef DEBUG
	# Enclave and untrusted stacks are split (segmented). GDB refuses to
	# unwind such stacks because it looks like stack frames "jump" back
	# and forth. Luckily, GDB special-cases stack frames for a function
	# with hardcoded name "__morestack". Declare this dummy function
	# to make GDB happy.

	.global __morestack
	.type __morestack, @function
__morestack:
#endif

	.cfi_startproc

	# Clear "extended" state (FPU aka x87, SSE, AVX, ...).
	movq %rdi, %r10
	movq SYNTHETIC_STATE@GOTPCREL(%rip), %rdi
	leaq 1f(%rip), %r11
	jmp __restore_xregs
1:
	movq %r10, %rdi

	# %rax is argument to EEXIT
	# %rbx is argument to EEXIT
	# %rcx is set to AEP by EEXIT
	xorq %rdx, %rdx
	# %rsi, %rdi are arguments to the untrusted code

#ifdef DEBUG
.Lfor_cfa_debug_info:
	# Leave %rbp pointing to OCALL function on trusted stack.
#else
	# In non-debug mode, clear %rbp to not leak trusted stack address.
	xorq %rbp, %rbp
#endif

	# %rsp points to untrusted stack
	xorq %r8, %r8
	xorq %r9, %r9
	xorq %r10, %r10
	xorq %r11, %r11
	xorq %r12, %r12
	xorq %r13, %r13
	xorq %r14, %r14
	subq %r15, %r15 # use sub to set flags to a fixed value

	movq $EEXIT, %rax
	ENCLU
.Locall_about_to_eexit_end:

	ud2 # We should never get here.
	.cfi_endproc

.Lreturn_from_ocall:
	# PAL convention:
	# RDI - return value
	# RSI - external event (if there is any)

	# restore the stack
	movq %gs:SGX_STACK, %rsp
	movq $0, %gs:SGX_STACK
.Lreturn_from_ocall_before_clear_ocall_prepared:
	movq $0, %gs:SGX_OCALL_PREPARED
.Lreturn_from_ocall_after_clear_ocall_prepared:

	## sgx_context_t::rax = %rdi
	movq %rdi, SGX_CONTEXT_RAX(%rsp) # return value

	# restore FSBASE if necessary
	movq %gs:SGX_FSBASE, %rbx
	cmpq $0, %rbx
	je .Lno_fsbase
	WRFSBASE_RBX
.Lno_fsbase:
	movq %rsi, %rdi	## %rdi = PAL_NUM event <- RSI
	movq %rsp, %rsi	## %rsi = sgx_context_t * uc
	movq %rsp, %rdx
	addq $SGX_CONTEXT_SIZE, %rdx ## %rdx = PAL_XREGS_STATE * xregs_state
	callq _DkHandleExternalEvent
	## NOTREACHED

	# void __restore_sgx_context (sgx_context_t *uc)
	# __attribute__((noreturn))
	.global __restore_sgx_context
	.type __restore_sgx_context, @function
__restore_sgx_context:
	movq %rdi, %rsp

	popq %rax
	popq %rcx
	popq %rdx
	popq %rbx
	addq $8, %rsp /* don't popq RSP yet */
	popq %rbp
	popq %rsi
	popq %rdi
	popq %r8
	popq %r9
	popq %r10
	popq %r11
	popq %r12
	popq %r13

	/* store saved %rip at -REDZONE-8(%saved rsp).
	 * notice sizeof(sgx_context_t) = 144 > 128 = RED_ZONE_SIZE.
	 */
	## see the definition of sgx_context_t
	## currently %rsp is pointing to %r14
	movq SGX_CONTEXT_RSP - SGX_CONTEXT_R14(%rsp), %r14 # %r14 = saved %rsp
	movq SGX_CONTEXT_RIP - SGX_CONTEXT_R14(%rsp), %r15 # %r15 = saved %rip
	movq %r15, - RED_ZONE_SIZE - 8(%r14)

	popq %r14
	popq %r15

	/* avoid to clobber red zone */
	subq $(RED_ZONE_SIZE + 8), SGX_CONTEXT_RSP - SGX_CONTEXT_RFLAGS(%rsp)
	popfq
	movq SGX_CONTEXT_RSP - SGX_CONTEXT_RIP(%rsp), %rsp
	retq $RED_ZONE_SIZE

	# void save_xregs(uint64_t xsave_area)
	.global save_xregs
	.type save_xregs, @function
save_xregs:
	fwait
	movq xsave_enabled@GOTPCREL(%rip), %rax
	movl (%rax), %eax
	cmpl $0, %eax
	jz 1f

	## clear xsave header
	movq $0, XSAVE_HEADER_OFFSET + 0 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 1 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 2 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 3 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 4 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 5 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 6 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 7 * 8(%rdi)

	movl $0xffffffff, %eax
	movl $0xffffffff, %edx
	xsave64 (%rdi)
	retq
1:
	fxsave64 (%rdi)
	retq


	# void __restore_xregs(uint64_t xsave_area)
	#   %rdi: input: pointer to xsave_area
	#	%r11: return address: not to use stack
	#   %rax, %rdx: clobered
	.global __restore_xregs
	.type __restore_xregs, @function
__restore_xregs:
	movq xsave_enabled@GOTPCREL(%rip), %rax
	movl (%rax), %eax
	cmpl $0, %eax
	jz 1f

	movl $0xffffffff, %eax
	movl $0xffffffff, %edx
	xrstor64 (%rdi)
	jmp *%r11
1:
	fxrstor64 (%rdi)
	jmp *%r11


	# void restore_xregs(uint64_t xsave_area)
	.global restore_xregs
	.type restore_xregs, @function
restore_xregs:
	popq %r11
	jmp __restore_xregs
