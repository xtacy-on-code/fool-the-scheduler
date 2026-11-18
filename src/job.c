/* job.c - test workloads
 * job <id> cpu <ms> | inter <burst> <io> [n] | attack <run> <io> [total]
 * io = tell usched on fd 3 ("B id ms"), then sleep
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#define SCHED_FD 3

static int id = -1;
static int have_sched = 0;

static double cpu_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

/* spin until we actually got ms of cpu */
static void burn(double ms)
{
    double start = cpu_ms();
    volatile unsigned long x = 0;
    while (cpu_ms() - start < ms)
        x++;
}

static void do_io(double ms)
{
    if (have_sched) {
        char msg[64];
        int n = snprintf(msg, sizeof msg, "B %d %.3f\n", id, ms);
        if (write(SCHED_FD, msg, n) != n) { }
    }
    struct timespec ts = { (time_t)(ms / 1000), (long)((ms - (long)(ms / 1000) * 1000) * 1e6) };
    nanosleep(&ts, NULL);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: job <id> cpu|inter|attack args...\n");
        return 1;
    }
    id = atoi(argv[1]);
    have_sched = fcntl(SCHED_FD, F_GETFD) != -1;
    /* stop right after exec, usched sends SIGCONT */
    if (getenv("FTS_STOP"))
        raise(SIGSTOP);
    const char *kind = argv[2];

    if (!strcmp(kind, "cpu")) {
        burn(argc > 3 ? atof(argv[3]) : 1e9);
    } else if (!strcmp(kind, "inter")) {
        double b = atof(argv[3]), io = atof(argv[4]);
        long count = argc > 5 ? atol(argv[5]) : 0;
        for (long i = 0; count == 0 || i < count; i++) {
            burn(b);
            do_io(io);
        }
    } else if (!strcmp(kind, "attack")) {
        double run = atof(argv[3]), io = atof(argv[4]);
        double total = argc > 5 ? atof(argv[5]) : 0;
        while (total == 0 || cpu_ms() < total) {
            burn(run);  /* just under the slice */
            do_io(io);   /* fake io -> stays on top */
        }
    } else {
        fprintf(stderr, "job: unknown kind %s\n", kind);
        return 1;
    }
    return 0;
}
