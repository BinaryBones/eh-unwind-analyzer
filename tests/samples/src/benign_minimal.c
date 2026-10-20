volatile unsigned long long g_sink;
__declspec(noinline) void helper(unsigned long long x) { g_sink = x + 1; }
void start(void) {
    unsigned long long a[4];
    a[0] = 1;
    helper(a[0]);
    for (;;) { }
}
