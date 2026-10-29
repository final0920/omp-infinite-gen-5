/* Self-authored evaluation targets. The reference evaluator is separate. */
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);
#ifndef CASE_KIND
#define CASE_KIND 1
#endif
#ifndef CASE_VALUE
#define CASE_VALUE 4
#endif
__declspec(dllexport) __declspec(noinline) unsigned int eval_fn(unsigned int x, unsigned char *output) {
#if CASE_KIND == 1
    return x < CASE_VALUE ? x + 1 : x - 1;
#elif CASE_KIND == 2
    *output = (unsigned char)(x ^ 0x5a);
    return (x + CASE_VALUE) & 255;
#else
    static const volatile unsigned char program[] = {0x10, 0x20, CASE_VALUE, 0x30, 0xff};
    unsigned int acc = 0, pc = 0;
    for (;;) {
        switch (program[pc++]) {
        case 0x10: acc = x; break;
        case 0x20: { unsigned int delta = program[pc++]; acc = (x & 1) ? acc + delta : acc - delta; break; }
        case 0x30: *output = (unsigned char)(x * 3); break;
        case 0xff: return acc;
        default: return 0xdeadbeef;
        }
    }
#endif
}
void ig5_eval_entry(void) {
    unsigned char output = 0;
    ExitProcess(eval_fn(5, &output));
}
