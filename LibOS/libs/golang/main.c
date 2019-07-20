#include "main.h"

#include <includes.h>
#include <symtab/symtab.h>

#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>

/* This is a Go variable (as opposed to a C variable or function).
 * GDB tells us all we need to know:
 *      (gdb) ptype runtime.buildVersion
 *      type = struct string {
 *          uint8 *str;
 *          int len;
 *      }
 *      (gdb) info address runtime.buildVersion
 *      Symbol "runtime.buildVersion" is static storage at address 0x522310
 *      (gdb) p 'runtime.buildVersion' # GDB knows...
 *      $1 = 0x4b27a4 "go1.10.7"
 * The ELF symbol length is 16 bytes on x86-64, thus the first 8 bytes is the
 * string location, and the second is the length. If you just dereference .str
 * you will find yourself in the middle of a large string table that contains
 * no inner NUL bytes. Fun ;)
 */
struct syminfo buildVersion_sym = {.name = "runtime.buildVersion"};

/* Points to function byte code for a specific Go version. */
static const struct golang* gofuncs;

/* Used by syscall wrapper code. */
struct syminfo rtstackcheck_sym   = {.name = "runtime.stackcheck"};
struct syminfo rtentersyscall_sym = {.name = "runtime.entersyscall"};
struct syminfo rtexitsyscall_sym  = {.name = "runtime.exitsyscall"};

/* Collect all in an array for easy lookup. */
static struct syminfo* symbols[] = {&buildVersion_sym, &rtstackcheck_sym, &rtentersyscall_sym,
                                    &rtexitsyscall_sym};
static const size_t symbols_n    = sizeof(symbols) / sizeof(*symbols);

struct symwrap {
    void* jmpto;
    struct syminfo sym;
};

/* Function symbols for JMP injection. */
/* TODO add Go version identification */
static struct symwrap funcs[] = {
    {.jmpto = &syscall_wrapper_clone, .sym = {.name = "runtime.clone"}},
    {.jmpto = &syscall_wrapper_exit_group, .sym = {.name = "runtime.exit"}},
    {.jmpto = &syscall_wrapper_futex, .sym = {.name = "runtime.futex"}},
    {.jmpto = &syscall_wrapper_gettid, .sym = {.name = "runtime.gettid"}},
    {.jmpto = &syscall_wrapper_mincore, .sym = {.name = "runtime.mincore"}},
    {.jmpto = &syscall_wrapper_sched_yield, .sym = {.name = "runtime.osyield"}},
    {.jmpto = &syscall_wrapper_rt_sigprocmask, .sym = {.name = "runtime.rtsigprocmask"}},
    /* runtime.sbrk0 does not exist in 1.11.5 but does in 1.10.7 */
    /* {.jmpto = &syscall_wrapper_brk, .sym = {.name = "runtime.sbrk0"}}, */
    {.jmpto = &syscall_wrapper_sched_getaffinity, .sym = {.name = "runtime.sched_getaffinity"}},
    {.jmpto = &syscall_wrapper_arch_prctl, .sym = {.name = "runtime.settls"}},
    {.jmpto = &syscall_wrapper_sigaltstack, .sym = {.name = "runtime.sigaltstack"}},
    {.jmpto = &syscall_wrapper_mmap, .sym = {.name = "runtime.sysMmap"}},
    {.jmpto = &syscall_wrapper_munmap, .sym = {.name = "runtime.sysMunmap"}},
    {.jmpto = &syscall_wrapper_rt_sigaction, .sym = {.name = "runtime.sysSigaction"}},
    {.jmpto = &syscall_wrapper_pselect6, .sym = {.name = "runtime.usleep"}},
    {.jmpto = &syscall_wrapper_write, .sym = {.name = "runtime.write"}},
    {.jmpto = &syscall_wrapper_syscall6, .sym = {.name = "syscall.Syscall6"}},
    {.jmpto = &syscall_wrapper_syscall, .sym = {.name = "syscall.Syscall"}},
};
static const size_t funcs_n = sizeof(funcs) / sizeof(*funcs);

static bool init(void) {
    struct syminfo** sym = NULL;
    struct symwrap* wrap = NULL;

    for (sym = symbols; sym < &symbols[symbols_n]; sym++)
        if (!symtab_lookup_symbol((*sym)->name, *sym))
            return false;

    rtstackcheck   = (uint64_t)rtstackcheck_sym.addr;
    rtentersyscall = (uint64_t)rtentersyscall_sym.addr;
    rtexitsyscall  = (uint64_t)rtexitsyscall_sym.addr;

    for (wrap = funcs; wrap < &funcs[funcs_n]; wrap++)
        if (!symtab_lookup_symbol(wrap->sym.name, &wrap->sym))
            return false;

    const struct go_string* gostr = buildVersion_sym.addr;

    for (int i = 0; i < GOLANG_N && !gofuncs; i++)
        if (0 == strncmp(GOLANG[i]->version, (const char*)gostr->str, gostr->len))
            gofuncs = GOLANG[i];

    return !!gofuncs;
}

/* Overwrite front of function with x86-64 instructions which jump to
 * a new location (the syscall wrapper).
 */
static bool inject_jmp(struct symwrap* wrap) {
    uint8_t mov[10], jmp[2];
    const size_t len = sizeof(mov) + sizeof(jmp);

    /* make sure we fit either within the symbol or padding space */
    if (len > wrap->sym.len && len > GO_FUNC_ALIGN_AMD64)
        return false;

    /* MOV r64, imm64
     *      = movabsq imm64,r64 (AT&T; move absolute quad)
     *      = REX.W + B8+rd io
     *          rd = register, see ISDM Ch 2.1; RAX = 0, RCX = 1, ...
     *          io = immediate operand, 8 bytes, absolute address
     *      = 48 b9 xx xx xx xx xx xx xx xx (xx = 8B, little endian)
     */
    mov[0] = 0x48;
    mov[1] = 0xb8 + 1;
    *((uint64_t*)&mov[2]) = (uint64_t)wrap->jmpto;

    /* JMP r/m64
     *      = jmp *rcx (AT&T); jmp [rcx] (Intel)
     *      = FF /4
     *          MOD 11           (reg itself holds addr)
     *          R/M      001     (RAX = 000, RCX = 001, ..)
     *          REG   100        (/4)
     *          (see ISDM Ch 2.1 Table 2.2)
     *      = ff e1
     */
    jmp[0] = 0xff;
    jmp[1] = 0xe1;

    uint8_t* pos = (uint8_t*)wrap->sym.addr;
    memcpy(pos, mov, sizeof(mov));
    pos += sizeof(mov);
    memcpy(pos, jmp, sizeof(jmp));

    return true;
}

/* Compare function bytecode to ensure we are replacing the function as-is
 * from the Go language sources. Certain instructions which use `call` refer
 * to offsets that vary from binary to binary, because of choices of the
 * linker while arranging functions in the text section.
 */
static bool cmp_func(const struct golang_fn* gofn, const struct symwrap* wrap) {
    if (gofn->ncalls == 0)
        return 0 == memcmp(gofn->bytes, wrap->sym.addr, gofn->len);
    const void *g = gofn->bytes, *w = wrap->sym.addr;
    for (size_t i = 0; i < gofn->ncalls; i++) {
        if (0 != memcmp(g, w, gofn->calls[i].offset - (g - gofn->bytes)))
            return false;
        size_t hop = gofn->calls[i].offset + gofn->calls[i].len;
        g += hop;
        w += hop;
    }
    if ((g - gofn->bytes) < gofn->len)
        if (0 != memcmp(g, w, gofn->len - (size_t)g))
            return false;
    return true;
}

static bool patch_funcs(void) {
    struct symwrap* wrap;
    for (wrap = funcs; wrap < &funcs[funcs_n]; wrap++) {
        const struct golang_fn* gofn = NULL;
        for (size_t i = 0; i < gofuncs->nfns && !gofn; i++)
            if (0 == strcmp(wrap->sym.name, gofuncs->fns[i].name))
                gofn = &(gofuncs->fns[i]);
        if (!gofn) /* FIXME fn should be found by this point */
            continue;
        if (gofn->len != wrap->sym.len || !cmp_func(gofn, wrap) || !inject_jmp(wrap))
            return false;
    }
    return true;
}

static void run(void) {
    if (!patch_heap())
        pal_printf("libgolang: Error: failed to patch Go heap size\n");
    else if (!patch_funcs())
        pal_printf("libgolang: Error: failed to patch Go functions\n");
    else
        pal_printf("libgolang: Successfully patched\n");
}

void __init(void) {
    if (init())
        run();
    else
        pal_printf(
            "libgolang: Error: Go not detected,"
            " or version not supported\n");
}
