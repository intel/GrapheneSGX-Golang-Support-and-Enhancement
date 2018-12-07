/* Copyright (C) 2018 Intel Corporation
                      Isaku Yamahata <isaku.yamahata at gmail.com>
                                     <isaku.yamahata at intel.com>
   All Rights Reserved.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <shim_internal.h>

static void __dump_regs(const struct shim_regs * regs)
{
    debug_printf("registers\n");
    debug_printf("orig_rax %08lx rsp %08lx rip %08lx\n",
                 regs->orig_rax, regs->rsp, regs->rip);
    debug_printf("r15 %08lx r14 %08lx r13 %08lx r12 %08lx\n",
                 regs->r15, regs->r14, regs->r13, regs->r12);
    debug_printf("r11 %08lx r10 %08lx r09 %08lx r08 %08lx\n",
                 regs->r11, regs->r10, regs->r9, regs->r8);
    debug_printf("rcx %08lx rdx %08lx rsi %08lx rdi %08lx\n",
                 regs->rcx, regs->rdx, regs->rsi, regs->rdi);
    debug_printf("rbx %08lx rbp %08lx\n",
                 regs->rbx, regs->rbp);
}

void __debug_regs(const char * file, const int line, const char * func,
                  const struct shim_regs * regs)
{
    debug_printf("%s:%d:%s\n", file, line, func);
    __dump_regs(regs);
}

void __debug_context(const char * file, const int line, const char * func,
                     const struct shim_context * context)
{
    const struct shim_regs * regs = context->regs;
    debug_printf("%s:%d:%s ", file, line, func);
    debug_printf("context %p resg %p\n", context, regs);
    if (regs) {
        __dump_regs(regs);
    }
}

void __debug_hex(const char * file, const int line, const char * func,
                 unsigned long * addr, int count)
{
    debug_printf("%s:%d:%s\n", file, line, func);
    while (count >= 4) {
        debug_printf("%p: %08lx %08lx %08lx %08lx\n",
                     addr,
                     addr[0], addr[1], addr[2], addr[3]);
        addr += 4;
        count -= 4;
    }
    if (count > 0) {
        debug_printf("%p: ", addr);
        for (int i = 0; i < count; i++) {
            debug_printf("%08lx", addr[i]);
        }
        debug_printf("\n");
    }
}

