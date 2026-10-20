volatile unsigned long long g_sink;
__declspec(noinline) unsigned long long f1(unsigned long long x) {
    unsigned long long buf[4];
    buf[0] = x + 3;
    buf[1] = buf[0] ^ 0x55ull;
    g_sink = buf[1];
    return buf[1];
}
__declspec(noinline) unsigned long long f2(unsigned long long x) {
    unsigned long long buf[8];
    buf[0] = f1(x);
    buf[1] = buf[0] + 7;
    g_sink = buf[1];
    return buf[1];
}
void start(void) {
    unsigned long long v = f2(9);
    g_sink = v;
    for (;;) { }
}
