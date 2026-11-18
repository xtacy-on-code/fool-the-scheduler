/* wintest.c - same attacks on windows, all on cpu 0
 * real cpu = QueryProcessCycleTime, reported = GetProcessTimes (task manager)
 * build: x86_64-w64-mingw32-gcc -O2 -o wintest.exe wintest.c -lwinmm
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECONDS 5

static LARGE_INTEGER qpf;
static double now_ms(void)
{
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return c.QuadPart * 1000.0 / qpf.QuadPart;
}

static double cycles_per_ms;
static double thread_cpu_ms(void)
{
    ULONG64 c;
    QueryThreadCycleTime(GetCurrentThread(), &c);
    return c / cycles_per_ms;
}

static void calibrate(void)
{
    ULONG64 c0, c1;
    double t0 = now_ms();
    QueryThreadCycleTime(GetCurrentThread(), &c0);
    volatile unsigned long x = 0;
    while (now_ms() - t0 < 200) x++;
    QueryThreadCycleTime(GetCurrentThread(), &c1);
    cycles_per_ms = (double)(c1 - c0) / (now_ms() - t0);
}


static void burn_cpu_ms(double ms)
{
    double s = thread_cpu_ms();
    volatile unsigned long x = 0;
    while (thread_cpu_ms() - s < ms) x++;
}

static HANDLE ev, helper_go;
static DWORD WINAPI helper(LPVOID p) /* fake device */
{
    (void)p;
    for (;;) {
        WaitForSingleObject(helper_go, INFINITE);
        Sleep(1);
        SetEvent(ev);
    }
    return 0;
}

/* child <cycles_per_ms> <role> [args], parent calibrates since cpu 0 is busy */
static int child(int argc, char **argv)
{
    (void)argc;
    SetProcessAffinityMask(GetCurrentProcess(), 1);
    cycles_per_ms = atof(argv[2]);
    argv++;
    const char *role = argv[2];
    if (!strcmp(role, "hog")) {
        volatile unsigned long x = 0;
        for (;;) x++;
    } else if (!strcmp(role, "sleep")) {
        double r = atof(argv[3]);
        timeBeginPeriod(1);
        for (;;) { burn_cpu_ms(r); Sleep(1); }
    } else if (!strcmp(role, "event")) {
        double r = atof(argv[3]);
        timeBeginPeriod(1);
        ev = CreateEvent(NULL, FALSE, FALSE, NULL);
        helper_go = CreateEvent(NULL, FALSE, FALSE, NULL);
        CreateThread(NULL, 0, helper, NULL, 0, NULL);
        for (;;) { burn_cpu_ms(r); SetEvent(helper_go); WaitForSingleObject(ev, INFINITE); }
    } else if (!strcmp(role, "yield")) {
        double r = atof(argv[3]);
        for (;;) { burn_cpu_ms(r); SwitchToThread(); }
    } else if (!strcmp(role, "dodge")) {
        double frac = atof(argv[3]);
        for (;;) {
            Sleep(1); /* wake just after a tick */
            double t = now_ms();
            double tick = atof(argv[4]);
            volatile unsigned long x = 0;
            while (now_ms() - t < frac * tick) x++;
        }
    }
    return 0;
}


typedef struct { const char *label; char args[64]; } Proc;

static FILE *out;
static char self[MAX_PATH];

static void test(const char *name, Proc *ps, int n)
{
    PROCESS_INFORMATION pi[16];
    for (int i = 0; i < n; i++) {
        char cmd[512];
        snprintf(cmd, sizeof cmd, "\"%s\" child %.1f %s", self, cycles_per_ms, ps[i].args);
        STARTUPINFOA si; memset(&si, 0, sizeof si); si.cb = sizeof si;
        if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi[i])) {
            printf("CreateProcess failed (%lu)\n", GetLastError());
            exit(1);
        }
    }
    Sleep(SECONDS * 1000);
    ULONG64 cyc[16]; double rep[16]; double ctot = 0, rtot = 0;
    for (int i = 0; i < n; i++) {
        SuspendThread(pi[i].hThread);
        QueryProcessCycleTime(pi[i].hProcess, &cyc[i]);
        FILETIME a, b, k, u;
        GetProcessTimes(pi[i].hProcess, &a, &b, &k, &u);
        ULARGE_INTEGER K = { .LowPart = k.dwLowDateTime, .HighPart = k.dwHighDateTime };
        ULARGE_INTEGER U = { .LowPart = u.dwLowDateTime, .HighPart = u.dwHighDateTime };
        rep[i] = (K.QuadPart + U.QuadPart) / 1e4;
        ctot += (double)cyc[i];
        rtot += rep[i];
    }
    for (int i = 0; i < n; i++) {
        TerminateProcess(pi[i].hProcess, 0);
        CloseHandle(pi[i].hProcess); CloseHandle(pi[i].hThread);
    }
    printf("\n%s\n", name);
    for (int i = 0; i < n; i++) {
        int first = 1;
        for (int k = 0; k < i; k++) if (!strcmp(ps[k].label, ps[i].label)) first = 0;
        if (!first) continue;
        double c = 0, r = 0;
        for (int k = 0; k < n; k++) if (!strcmp(ps[k].label, ps[i].label)) { c += cyc[k]; r += rep[k]; }
        double true_share = 100 * c / ctot, rep_share = rtot > 0 ? 100 * r / rtot : 0;
        double true_ms = c / cycles_per_ms;
        printf("  %-10s real CPU %5.1f%%   reported CPU %5.1f%%   (real %.0f ms, reported %.0f ms)\n",
               ps[i].label, true_share, rep_share, true_ms, r);
        fprintf(out, "%s,%s,%.2f,%.2f,%.1f,%.1f\n", name, ps[i].label, true_share, rep_share, true_ms, r);
        fflush(out);
    }
    Sleep(500);
}

int main(int argc, char **argv)
{
    QueryPerformanceFrequency(&qpf);
    if (argc > 1 && !strcmp(argv[1], "child")) return child(argc, argv);

    GetModuleFileNameA(NULL, self, sizeof self);
    DWORD_PTR pm, sm;
    GetProcessAffinityMask(GetCurrentProcess(), &pm, &sm);
    if (sm & ~(DWORD_PTR)1) SetProcessAffinityMask(GetCurrentProcess(), sm & ~(DWORD_PTR)1);
    calibrate();

    DWORD adj, inc; BOOL dis;
    GetSystemTimeAdjustment(&adj, &inc, &dis);
    double tick_ms = inc / 1e4;
    double t = now_ms(); for (int i = 0; i < 20; i++) Sleep(1); double sleep1 = (now_ms() - t) / 20;
    OSVERSIONINFOA vi; memset(&vi, 0, sizeof vi); vi.dwOSVersionInfoSize = sizeof vi;
    typedef LONG (WINAPI *RtlGetVersion_t)(OSVERSIONINFOA *);
    RtlGetVersion_t rgv = (RtlGetVersion_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (rgv) rgv(&vi);

    out = fopen("wintest_results.csv", "w");
    fprintf(out, "# windows %lu.%lu build %lu, tick %.3f ms, Sleep(1) %.3f ms, %.0f cycles/ms\n",
            vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber, tick_ms, sleep1, cycles_per_ms);
    fprintf(out, "test,group,real_share,reported_share,real_ms,reported_ms\n");
    printf("Windows %lu.%lu build %lu | clock tick %.3f ms | Sleep(1) takes %.3f ms\n",
           vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber, tick_ms, sleep1);
    printf("Each test runs %d s with everything pinned to CPU 0. Please do not use the PC meanwhile.\n", SECONDS);

    char a[64];
    { Proc p[] = { {"hogA", "hog"}, {"hogB", "hog"} }; test("baseline_2_hogs", p, 2); }

    double runs[] = { 2, 10, 25 };
    for (int i = 0; i < 3; i++) {
        snprintf(a, sizeof a, "sleep %.0f", runs[i]);
        { Proc p[] = { {"honest", "hog"}, {"attacker", ""} }; strcpy(p[1].args, a);
          char nm[64]; snprintf(nm, sizeof nm, "iotrick_sleep_run%.0fms", runs[i]); test(nm, p, 2); }
        snprintf(a, sizeof a, "event %.0f", runs[i]);
        { Proc p[] = { {"honest", "hog"}, {"attacker", ""} }; strcpy(p[1].args, a);
          char nm[64]; snprintf(nm, sizeof nm, "iotrick_event_run%.0fms", runs[i]); test(nm, p, 2); }
        snprintf(a, sizeof a, "yield %.0f", runs[i]);
        { Proc p[] = { {"honest", "hog"}, {"attacker", ""} }; strcpy(p[1].args, a);
          char nm[64]; snprintf(nm, sizeof nm, "iotrick_yield_run%.0fms", runs[i]); test(nm, p, 2); }
    }
    { Proc p[] = { {"victim", "hog"}, {"army", "hog"}, {"army", "hog"}, {"army", "hog"}, {"army", "hog"} };
      test("army_4_vs_1", p, 5); }

    double tick = sleep1 > 2 ? sleep1 : tick_ms;
    double fr[] = { 0.5, 0.8, 0.9 };
    for (int i = 0; i < 3; i++) {
        snprintf(a, sizeof a, "dodge %.2f %.3f", fr[i], tick);
        Proc p[] = { {"honest", "hog"}, {"dodger", ""} }; strcpy(p[1].args, a);
        char nm[64]; snprintf(nm, sizeof nm, "tickdodge_%.0fpct", fr[i] * 100); test(nm, p, 2);
    }
    { Proc p[] = { {"dodger", ""} }; snprintf(p[0].args, sizeof p[0].args, "dodge 0.90 %.3f", tick);
      test("tickdodge_alone_90pct", p, 1); }

    fclose(out);
    printf("\nDone. Results saved to wintest_results.csv - send that file back.\n");
    printf("Press Enter to close.");
    getchar();
    return 0;
}
