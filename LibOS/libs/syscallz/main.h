#ifndef __SYSCALLZ_MAIN_H__
#define __SYSCALLZ_MAIN_H__

#define LIBRARY_NAME            "libsyscallz"
#define PRINT_PREFIX            LIBRARY_NAME ": "

#define MANIFEST_TRUSTED_FILES  "sgx.trusted_files"
#define MANIFEST_KEY_OFFSETS    MANIFEST_TRUSTED_FILES ".syscallz_offsets"

/* FIXME Use DBG_SGX to toggle output? */
#define lprintf(fmt, ...) \
    pal_printf(PRINT_PREFIX fmt, ##__VA_ARGS__)

void __sysz_trap(void);
#endif
