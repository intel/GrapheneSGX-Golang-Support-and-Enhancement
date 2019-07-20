/* About this file: Due to limitations in SGX (v1) we cannot add
 * 'infinite' pages to the EPC.  Go heap management allocates a large
 * virtual buffer, then allocates or releases physical page backing
 * manually. We cannot add the virtual allocation in its entirety,
 * thus must shrink this to prevent heap allocation into pages not
 * added in the EPC.  SGX (v2) supports dynamic page management in the
 * EPC and also a larger page limit for the EPC. Systems with SGX (v2)
 * need not apply these patches once Graphene supports dynamic page
 * management, and this file can thus be made obsolete.
 *
 * TODO Current implementation only supports go1.10.7
 */

#include "main.h"

#include <includes.h>

#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>

struct syminfo rtsysReserve_sym = {.name = "runtime.sysReserve"};
struct syminfo rtmallocinit_sym = {.name = "runtime.mallocinit"};

// Both instructions should be the same length.
// ISDM says instr decoder stops at 15 bytes
struct patch {
    struct syminfo* sym;
    size_t offset;
    uint8_t orig_instr[15];
    uint8_t new_instr[15];
    size_t len;
};

// go1.10.7 instructions to patch for fixing the heap size
// TODO add documentation beyond instruction disassembly
struct patch INSTR[] = {
    {.sym    = &rtmallocinit_sym,
     .offset = 393,
     // mov     qword ptr [rsp + 0x10], 0x20000000
     .orig_instr = {0x48, 0xC7, 0x44, 0x24, 0x10, 0, 0, 0, 0x20},
     // mov     qword ptr [rsp + 0x10],   0x100000
     .new_instr = {0x48, 0xC7, 0x44, 0x24, 0x10, 0, 0, 0x10, 0},
     .len       = 9},
    {.sym    = &rtmallocinit_sym,
     .offset = 0x11e,
     // movabs  rbx, 0x420000000
     .orig_instr = {0x48, 0xBB, 0, 0, 0, 0x20, 0x04, 0, 0, 0},
     // movabs  rbx,   0x2100000
     .new_instr = {0x48, 0xBB, 0, 0, 0x10, 0x02, 0, 0, 0, 0},
     .len       = 10},
    {.sym    = &rtmallocinit_sym,
     .offset = 0x261,
     // movabs  rdi, 0x420002000
     .orig_instr = {0x48, 0xBF, 0, 0x20, 0, 0x20, 0x04, 0, 0, 0},
     // movabs  rdi,   0x2102000
     .new_instr = {0x48, 0xBF, 0, 0x20, 0x10, 0x02, 0, 0, 0, 0},
     .len       = 10},
    {.sym    = &rtmallocinit_sym,
     .offset = 0x2c3,
     // movabs  rdi, 0x420002000
     .orig_instr = {0x48, 0xBF, 0, 0x20, 0, 0x20, 0x04, 0, 0, 0},
     // movabs  rdi,   0x2102000
     .new_instr = {0x48, 0xBF, 0, 0x20, 0x10, 0x02, 0, 0, 0, 0},
     .len       = 10},
    {.sym    = &rtmallocinit_sym,
     .offset = 0xb1,
     // cmp     rax,  0x7f
     .orig_instr = {0x48, 0x83, 0xF8, 0x7F},
     // cmp     rax, -0x9
     .new_instr = {0x48, 0x83, 0xF8, 0xF7},
     .len       = 4},
    {.sym    = &rtsysReserve_sym,
     .offset = 0x26,
     // movabs  rcx,       0x100000000
     .orig_instr = {0x48, 0xB9, 0, 0, 0, 0, 0x01, 0, 0, 0},
     // movabs  rcx, 0x100000100000000
     .new_instr = {0x48, 0xB9, 0, 0, 0, 0, 0x01, 0, 0, 0x01},
     .len       = 10},
};
const size_t INSTR_N = sizeof(INSTR) / sizeof(*INSTR);

static bool patch_instruction(struct patch* p) {
    if (!p || !p->sym || !p->sym->addr)
        return false;
    uint8_t* pos = (uint8_t*)p->sym->addr + p->offset;
    if (0 != memcmp(pos, p->orig_instr, p->len))
        return false;
    memcpy(pos, p->new_instr, p->len);
    return true;
}

static bool check_goversion(void) {
    struct go_string* gostr = (struct go_string*)buildVersion_sym.addr;
    return 0 == strncmp((const char*)gostr->str, "go1.10.7", gostr->len);
}

bool patch_heap(void) {
    if (check_goversion()) {
        if (!symtab_lookup_symbol(rtsysReserve_sym.name, &rtsysReserve_sym))
            return false;
        if (!symtab_lookup_symbol(rtmallocinit_sym.name, &rtmallocinit_sym))
            return false;
        for (struct patch* p = INSTR; p < &INSTR[INSTR_N]; p++)
            if (!patch_instruction(p))
                return false;
    }
    return true;
}
