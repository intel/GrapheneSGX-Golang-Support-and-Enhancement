#ifndef __GOLANG_MAIN_H__
#define __GLOANG_MAIN_H__

#include "funcs.h"
#include "wrappers.h"

#include <includes.h>
#include <symtab/symtab.h>
/*
 * The function alignment we assume to be true for Go binaries is 16
 * bytes. This helps us know how much _real_ space is available for
 * code injection, even if the function itself is just a few bytes. In
 * other words, we may also use the padding space between functions.
 *
 * If 'funcAlign' ever changes, we'll need to update this.
 *
 * Reference: go/src/cmd/link/internal/amd64/l.go
 */
static const size_t GO_FUNC_ALIGN_AMD64 = 16;

#define CALLS_PER_FN 16

struct callq {
    off_t offset;
    size_t len;
};

struct golang_fn {
    const char* name;
    const void* bytes;
    size_t len;
    size_t ncalls;
    struct callq calls[CALLS_PER_FN];
};

struct golang {
    const char* version;
    size_t nfns;
    const struct golang_fn fns[];
};

struct go_string {
    uint8_t* str;
    uint64_t len;
};

extern struct syminfo buildVersion_sym;

extern uint64_t rtstackcheck;
extern uint64_t rtentersyscall;
extern uint64_t rtexitsyscall;

bool patch_heap(void);

#endif
