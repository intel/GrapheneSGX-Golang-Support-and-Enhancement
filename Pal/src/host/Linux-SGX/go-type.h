#ifndef GO_TYPE_H
#define GO_TYPE_H   1

struct go_stack {
    uintptr_t lo;
    uintptr_t hi;
};

struct go_g {
    struct go_stack stack;
    uintptr_t stackguard0;
    uintptr_t stackguard1;
};

static inline struct go_g * get_g(void)
{
    struct go_g *ret;
    __asm__ ("movq %%fs:%c1, %q0": "=r" (ret) : "i" (-8));
    return ret;
}
#endif // GO_TYPE_H
