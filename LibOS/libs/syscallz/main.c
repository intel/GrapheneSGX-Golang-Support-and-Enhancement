#include "main.h"

#include <includes.h>
#include <symtab/symtab.h>

#define as(x) (__typeof__(x))

static const size_t MAX_SYSCALL_NR = 1024UL;

/* SYSCALL */
static const uint8_t X86_INSTR_SYSCALL[2] = { 0x0f, 0x05 };

/* NOP */
static const uint8_t X86_INSTR_NOP[1] = { 0x90 };

/* CALL r/m64
 *      = FF /2
 *          MOD 11           (reg itself holds addr)
 *          R/M      000     (RAX = 000, RCX = 001, ..)
 *          REG   010        (/2)
 *          (see ISDM Ch 2.1 Table 2.2)
 *      = ff d0 = call rax (Intel) callq *%rax (AT&T)
 */
static const uint8_t X86_INSTR_CALL_RAX[2] = { 0xff, 0xd0 };

/* MOV r64, imm64
 *      = REX.W + B8+rd io
 *          rd = register, see ISDM Ch 2.1; RAX = 0, RCX = 1, ...
 *          io = immediate operand, 8 bytes, absolute address
 *      = 48 b9 xx xx xx xx xx xx xx xx (xx = 1B, total 8B in little endian)
 *      = movabsq imm64,rcx (AT&T) movabs rcx,imm64 (Intel)
 */
static const uint8_t X86_INSTR_MOV_RCX_IMM64[10] = { 0x48, 0xb8 + 1 };

/* JMP r/m64
 *      = FF /4
 *          MOD 11           (reg itself holds addr)
 *          R/M      001     (RAX = 000, RCX = 001, ..)
 *          REG   100        (/4)
 *          (see ISDM Ch 2.1 Table 2.2)
 *      = ff e1 = jmp rcx (Intel) jmp *%rcx (AT&T)
 */
static const uint8_t X86_INSTR_JMP_RCX[2] = { 0xff, 0xe1 };

static bool PATCHED = false;

static void
install_slide(void) {

    /* Write NOPs to top of page (the 'slide'). */
    volatile uint8_t *instr = as(instr) 0x0;
    while (instr <= as(instr) MAX_SYSCALL_NR)
        *instr++ = X86_INSTR_NOP[0];

    /* Redirect control flow to trap handler after slide (the 'bounce'). */
    /* RCX and R11 are available; Linux x86-64 ABI says syscall destroys them */

    uint8_t mov[sizeof(X86_INSTR_MOV_RCX_IMM64)];
    memcpy(mov, X86_INSTR_MOV_RCX_IMM64, sizeof(X86_INSTR_MOV_RCX_IMM64));
    *((uint64_t *) &mov[2]) = (uint64_t) __sysz_trap;

    volatile uint8_t *p = as(p) (MAX_SYSCALL_NR + 1);
    for (size_t i = 0; i < sizeof(mov); i++)
        *p++ = mov[i];
    for (size_t i = 0; i < sizeof(X86_INSTR_JMP_RCX); i++)
        *p++ = X86_INSTR_JMP_RCX[i];
}

static bool
patch_syscall(size_t offset) {
    void *r = text_section + offset;
    const uint8_t *pos = as(pos) (pal_control.executable_range.start + (size_t)r);
    if (0 != memcmp((void*)pos, X86_INSTR_SYSCALL, sizeof(X86_INSTR_SYSCALL))) {
        lprintf("Error: syscall expected at %p\n", pos);
        lprintf("found instead:\n");
        for (size_t i = 0; i < 16; i++)
            lprintf("%02x ", pos[i]);
        lprintf("\n");
        lprintf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
                pos[0], pos[1], pos[2], pos[3],
                pos[4], pos[5], pos[6], pos[7]);
        lprintf("pal_control.executable_range.start = %p\n",
                pal_control.executable_range.start);
        return false;
    }
    memcpy((void*)pos, X86_INSTR_CALL_RAX, sizeof(X86_INSTR_CALL_RAX));
    return true;
}

#ifdef SYSZ_LOAD_MANIFEST
/* Implement a dumb allocator for the sole purpose of parsing the
 * manifest file to extract the offsets file path.  Manifest file
 * state is assumed to fit within a page or two.
 */
struct malloc_state {
    bool init;
    size_t start, pos, len;
};
static struct malloc_state MALLOC = {.init = false};
static const size_t MALLOC_MIN = 1UL << 12;

static bool
mallocx_init(void) {
    void *map = NULL;
    size_t len = alignup(MALLOC_MIN);

    if (MALLOC.init)
        return false;

    if (!(map = DkVirtualMemoryAlloc(NULL, len, 0, PAL_PROT_READ)))
        return false;

    MALLOC.start = MALLOC.pos = (size_t)map;
    MALLOC.len = len;
    MALLOC.init = true;

    return true;
}

void *
mallocx(size_t size) {
    size_t pos = (MALLOC.pos += size);
    if (pos - MALLOC.start > MALLOC.len) {
        lprintf("Error: malloc oom (manifest file too big?)\n");
        return NULL;
    }
    return (void*)pos;
}

void
freex(__attribute__((unused)) void *ptr) { }

static void
mallocx_release(void) {
    if (MALLOC.init) {
        DkVirtualMemoryFree(MALLOC.start, MALLOC.len);
        MALLOC.init = false;
    }
}

static struct config_store *MANIFEST = NULL;
#endif

static bool
patch_application(void) {
    if (!text_section) {
        lprintf("Error: location of .text unknown;"
                " was libsymtab.so loaded?\n");
        return false;
    }

    install_slide();

    size_t file_len = 0UL, map_len = 0UL;
    void *map = NULL;
    PAL_HANDLE handle = NULL;
    PAL_STREAM_ATTR attr = {0};

#ifdef SYSZ_LOAD_MANIFEST
    if (!MANIFEST) {
        struct config_store *config;
        int ret;

        if (!(config = mallocx(sizeof(*config))))
            return false;

        config->raw_data = pal_control.manifest_preload.start;
        config->raw_size = pal_control.manifest_preload.end - config->raw_data;
        config->malloc = mallocx;
        config->free = freex;

        /* FIXME read_config relies on implementations of `warn` and
         * `__abort` which are in Pal, and are not exported.
         * This code will build but NOT link.
         */
        const char *errstring = NULL;
        if ((ret = read_config(config, NULL, &errstring)) < 0) {
            lprintf("error: reading manifest: %s\n", errstring);
            return false;
        }
        MANIFEST = config;
    }

    /* Load the offsets file and release manifest state */

    char uri[URI_MAX] = {0};

    int ret;
    if (0 >= (ret = get_config(MANIFEST, MANIFEST_KEY_OFFSETS, uri, sizeof(uri))))
        goto done;
#else
    const char *uri = "file:syscall_offsets.dat";
#endif

    if (!(handle = DkStreamOpen(uri, PAL_ACCESS_RDONLY, 0, 0, 0)))
        goto done;

    if (HANDLE_HDR(handle)->type != pal_type_file)
        goto done;

    if (!DkStreamAttributesQuery(uri, &attr))
        goto done;

    if (0 == (file_len = attr.pending_size))
        goto done;

    map_len = alignup(file_len);
    if (!(map = DkStreamMap(handle, NULL, PAL_PROT_READ, 0, map_len)))
        goto done;

    /* Go through each offset, and patch instructions */

    char *p = map, *next = NULL;
    while (1) {
        long val = strtol(p, &next, 0);
        if (p == next)
            break;
        if (!patch_syscall(val))
            return false;
        p = next;
    }

    PATCHED = true;

done:
    if (map)
        DkVirtualMemoryFree(map, map_len);
    if (handle)
        DkObjectClose(handle);
    return PATCHED;
}

void
__init(void) {
#ifdef LOAD_MALLOC
    if (!mallocx_init() || !patch_application())
        lprintf("error: something broke."
                " Your app may be in an inconsistent state");
    mallocx_release();
#else
    if (!patch_application())
        lprintf("error: something broke."
                " Your app may be in an inconsistent state");
#endif
}
