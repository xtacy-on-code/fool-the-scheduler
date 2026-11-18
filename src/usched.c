/* usched.c - user space scheduler for real processes
 * jobs pinned to cpu 0, only the picked one gets SIGCONT, rest are SIGSTOPped.
 * jobs report io on a pipe so we know when they block.
 *
 * usched -p rr|mlfq|stride|linux [-q ms] [-L n] [-B ms] [-A] [-G] [-S] [-T ms]
 *        [-e events.csv] [-s summary.csv] [-v] workload
 *   -A slide 18 accounting, -B boost period, -G per user, -S own session (linux)
 * workload line: name group arrival tickets [every=ms count=n] kind args
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAXJOBS   2048
#define MAXGROUPS 16
#define MAXLEVELS 8
#define STRIDE1   1000000.0

typedef enum { NEW, READY, RUNNING, BLOCKED, DONE } State;
static const char *state_name[] = { "NEW", "READY", "RUNNING", "BLOCKED", "DONE" };

typedef struct {
    char name[40];
    int group, tickets;
    double arrival;
    char *argv[16];
    pid_t pid;
    clockid_t clk;
    State st;
    double cpu0;          /* cpu clock at t0 */
    double cpu;           /* ms of cpu during the run */
    int level;
    double used_level;    /* for -A */
    double pass;          /* stride */
    long seq;             /* queue order */
    double wake;
    double ready_since;
    int fresh_ready;      /* arrived/woke, not preempted */
    double first_run, finish;
    double resp_sum; long resp_n; double resp_max;
    long dispatches;
    double exit_cpu;      /* from rusage */
} Job;

typedef struct {
    char name[40];
    int level;
    double used_level, pass;
    int tickets, used;
    double cpu;
    long last_run;        /* groups take turns */
} Group;

static Job jobs[MAXJOBS];
static Group groups[MAXGROUPS];
static int njobs, ngroups;

static char policy[16] = "mlfq";
static double q = 8, boost = 0, duration = 5000;
static int levels = 3, accounting = 0, group_mode = 0, sessions = 0, live = 0;
static const char *events_path, *summary_path, *workload_path;
static FILE *events;

static double t0;
double fmod_ms(double ms);
static double ru_ms(struct rusage *r)
{
    return r->ru_utime.tv_sec * 1e3 + r->ru_utime.tv_usec / 1e3 + r->ru_stime.tv_sec * 1e3 + r->ru_stime.tv_usec / 1e3;
}
static long seq_counter;
static int msg_fd = -1, sig_fd = -1;

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6 - t0;
}
static double clk_ms(clockid_t c)
{
    struct timespec t;
    if (clock_gettime(c, &t) != 0) return -1;
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static int group_index(int g, const char *name)
{
    if (g < 0 || g >= MAXGROUPS) { fprintf(stderr, "group must be 0..%d\n", MAXGROUPS - 1); exit(1); }
    if (groups[g].name[0] == 0) {
        snprintf(groups[g].name, sizeof groups[g].name, "%s", name);
        char *h = strchr(groups[g].name, '#'); if (h) *h = 0;
    }
    if (g + 1 > ngroups) ngroups = g + 1;
    return g;
}

static void load_workload(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); exit(1); }
    char line[512];
    while (fgets(line, sizeof line, f)) {
        char *tok[24]; int nt = 0;
        for (char *p = strtok(line, " \t\n"); p && nt < 24; p = strtok(NULL, " \t\n")) tok[nt++] = p;
        if (nt == 0 || tok[0][0] == '#') continue;
        if (nt < 5) { fprintf(stderr, "bad workload line\n"); exit(1); }
        double every = 0; int count = 1, k = 4;
        while (k < nt && (!strncmp(tok[k], "every=", 6) || !strncmp(tok[k], "count=", 6))) {
            if (!strncmp(tok[k], "every=", 6)) every = atof(tok[k] + 6);
            else count = atoi(tok[k] + 6);
            k++;
        }
        for (int c = 0; c < count; c++) {
            if (njobs >= MAXJOBS) { fprintf(stderr, "too many jobs\n"); exit(1); }
            Job *j = &jobs[njobs];
            memset(j, 0, sizeof *j);
            if (count > 1) snprintf(j->name, sizeof j->name, "%s#%d", tok[0], c);
            else snprintf(j->name, sizeof j->name, "%s", tok[0]);
            j->group = group_index(atoi(tok[1]), tok[0]);
            j->arrival = atof(tok[2]) + c * every;
            j->tickets = atoi(tok[3]);
            if (j->tickets <= 0) j->tickets = 100;
            int a = 0;
            j->argv[a++] = "job";
            char *idbuf = malloc(16); snprintf(idbuf, 16, "%d", njobs);
            j->argv[a++] = idbuf;
            for (int t = k; t < nt && a < 15; t++) j->argv[a++] = strdup(tok[t]);
            j->argv[a] = NULL;
            j->first_run = j->finish = -1;
            j->st = NEW;
            njobs++;
        }
    }
    fclose(f);
    for (int g = 0; g < ngroups; g++) groups[g].tickets = 0;
    for (int i = 0; i < njobs; i++) groups[jobs[i].group].tickets = jobs[i].tickets;
}

static int *lvl(Job *j) { return group_mode ? &groups[j->group].level : &j->level; }
static double *used_lvl(Job *j) { return group_mode ? &groups[j->group].used_level : &j->used_level; }
static double quantum_of(int level) { return q * (1 << level); }

/* should a run before b */
static int better(Job *a, Job *b)
{
    if (!strcmp(policy, "mlfq")) {
        int la = *lvl(a), lb = *lvl(b);
        if (la != lb) return la < lb;
    } else if (!strcmp(policy, "stride")) {
        double pa = group_mode ? groups[a->group].pass : a->pass;
        double pb = group_mode ? groups[b->group].pass : b->pass;
        if (pa != pb) return pa < pb;
    }
    if (group_mode && a->group != b->group)  /* same level: users take turns */
        return groups[a->group].last_run < groups[b->group].last_run;
    return a->seq < b->seq;
}

static Job *pick(void)
{
    Job *best = NULL;
    for (int i = 0; i < njobs; i++)
        if (jobs[i].st == READY && (!best || better(&jobs[i], best))) best = &jobs[i];
    return best;
}

static double slice_for(Job *j)
{
    if (!strcmp(policy, "mlfq")) {
        double full = quantum_of(*lvl(j));
        if (accounting) {
            double left = full - *used_lvl(j);
            return left > 0.05 ? left : 0.05;
        }
        return full;
    }
    return q;
}

/* bill job for used ms */
static void charge(Job *j, double used, int full_slice)
{
    if (!strcmp(policy, "mlfq")) {
        int *L = lvl(j);
        double *U = used_lvl(j);
        if (accounting) {
            *U += used;
            if (*U >= quantum_of(*L) - 0.05) { /* allotment gone */
                if (*L < levels - 1) (*L)++;
                *U = 0;
            }
        } else if (full_slice) { /* naive: full slice */
            if (*L < levels - 1) (*L)++;
        }
    } else if (!strcmp(policy, "stride")) {
        if (group_mode) groups[j->group].pass += STRIDE1 * used / groups[j->group].tickets;
        else j->pass += STRIDE1 * used / j->tickets;
    }
}

static double min_pass(int skip_group)
{
    double m = -1;
    for (int i = 0; i < njobs; i++) {
        Job *j = &jobs[i];
        if (j->st != READY && j->st != RUNNING) continue;
        if (group_mode && j->group == skip_group) continue;
        double p = group_mode ? groups[j->group].pass : j->pass;
        if (m < 0 || p < m) m = p;
    }
    return m;
}

static void make_ready(Job *j, int fresh)
{
    if (j->st == NEW && !strcmp(policy, "stride")) {
        double m = min_pass(j->group);
        if (m > 0) {
            if (group_mode) { if (groups[j->group].pass < m) groups[j->group].pass = m; }
            else j->pass = m;
        }
    }
    j->st = READY;
    j->seq = ++seq_counter;
    j->ready_since = now();
    j->fresh_ready = fresh;
}

static void do_boost(void)
{
    for (int i = 0; i < njobs; i++) { jobs[i].level = 0; jobs[i].used_level = 0; }
    for (int g = 0; g < ngroups; g++) { groups[g].level = 0; groups[g].used_level = 0; }
}

static void spawn_all(int pipe_w)
{
    cpu_set_t set;
    CPU_ZERO(&set); CPU_SET(0, &set);
    for (int i = 0; i < njobs; i++) {
        pid_t p = fork();
        if (p < 0) { perror("fork"); exit(1); }
        if (p == 0) {
            sched_setaffinity(0, sizeof set, &set); /* cpu 0 only */
            dup2(pipe_w, 3);
            setenv("FTS_STOP", "1", 1);
            sigset_t none; sigemptyset(&none); sigprocmask(SIG_SETMASK, &none, NULL);
            execv("./job", jobs[i].argv);
            execvp("job", jobs[i].argv);
            perror("exec job"); _exit(127);
        }
        jobs[i].pid = p;
        int st;
        waitpid(p, &st, WUNTRACED);
        if (!WIFSTOPPED(st)) { fprintf(stderr, "job %d did not start\n", i); exit(1); }
        clock_getcpuclockid(p, &jobs[i].clk);
    }
}

static void log_event(double ts, double te, Job *j, int level, const char *why, double used)
{
    if (events)
        fprintf(events, "%.3f,%.3f,%ld,%s,%d,%d,%s,%.3f\n", ts, te, (long)(j - jobs), j->name, j->group, level, why, used);
}

/* read io msgs, 1 if run blocked */
static char mbuf[8192]; static int mlen;
static int read_messages(Job *run)
{
    int blocked_running = 0;
    for (;;) {
        ssize_t n = read(msg_fd, mbuf + mlen, sizeof mbuf - 1 - mlen);
        if (n <= 0) break;
        mlen += n;
    }
    mbuf[mlen] = 0;
    char *start = mbuf, *nl;
    while ((nl = strchr(start, '\n'))) {
        *nl = 0;
        int id; double ms;
        if (sscanf(start, "B %d %lf", &id, &ms) == 2 && id >= 0 && id < njobs) {
            Job *j = &jobs[id];
            double t = now();
            if (j == run) { blocked_running = 1; j->wake = t + ms; }
            else if (j->st == READY) { j->st = BLOCKED; j->wake = t + ms; }  /* late msg */
        }
        start = nl + 1;
    }
    mlen = strlen(start);
    memmove(mbuf, start, mlen);
    return blocked_running;
}

static void reap_done(Job *j, int status)
{
    (void)status;
    j->st = DONE;
    j->finish = now();
}

/* reap, 1 if run exited */
static int check_children(Job *run)
{
    struct signalfd_siginfo si;
    while (read(sig_fd, &si, sizeof si) == sizeof si) {}
    int run_exited = 0;
    for (;;) {
        int st;
        struct rusage ru;
        pid_t p = wait4(-1, &st, WNOHANG, &ru);
        if (p <= 0) break;
        for (int i = 0; i < njobs; i++)
            if (jobs[i].pid == p) {
                jobs[i].exit_cpu = ru_ms(&ru);
                if (&jobs[i] == run) run_exited = 1;
                else reap_done(&jobs[i], st);
                jobs[i].pid = -jobs[i].pid;
            }
    }
    return run_exited;
}

static double next_event_time(double tend)
{
    double t = tend;
    for (int i = 0; i < njobs; i++) {
        if (jobs[i].st == NEW && jobs[i].arrival < t) t = jobs[i].arrival;
        if (jobs[i].st == BLOCKED && jobs[i].wake < t) t = jobs[i].wake;
    }
    return t;
}

static double next_boost = 0;
static void admit_and_wake(void)
{
    double t = now();
    for (int i = 0; i < njobs; i++) {
        if (jobs[i].st == NEW && jobs[i].arrival <= t) make_ready(&jobs[i], 1);
        else if (jobs[i].st == BLOCKED && jobs[i].wake <= t) make_ready(&jobs[i], 1);
    }
    if (boost > 0 && t >= next_boost) { do_boost(); next_boost += boost; }
}

static int should_preempt(Job *run)
{
    if (strcmp(policy, "mlfq")) return 0;
    for (int i = 0; i < njobs; i++)
        if (jobs[i].st == READY && *lvl(&jobs[i]) < *lvl(run)) return 1;
    return 0;
}

/* live view (-v) */
static double last_draw = -1e9;
static void draw(Job *run, int force)
{
    if (!live) return;
    double t = now();
    if (!force && t - last_draw < 150) return;
    last_draw = t;
    double tot = 0, gcpu[MAXGROUPS] = {0};
    for (int i = 0; i < njobs; i++) {
        double c = jobs[i].cpu;
        if (jobs[i].st == RUNNING || (jobs[i].pid > 0 && jobs[i].st != NEW && jobs[i].st != DONE)) {
            double v = clk_ms(jobs[i].clk);
            if (v >= 0) c = v - jobs[i].cpu0;
        }
        gcpu[jobs[i].group] += c; tot += c;
    }
    printf("\033[H\033[2J");
    printf(" usched  policy=%s%s%s%s  q=%.0fms  t=%6.0f ms\n\n", policy, accounting ? "+accounting" : "",
           boost > 0 ? "+boost" : "", group_mode ? "+groups" : "", q, t);
    if (!strcmp(policy, "mlfq")) {
        for (int L = 0; L < levels; L++) {
            printf("  Q%d (%3.0fms) |", L + 1, quantum_of(L));
            int shown = 0;
            for (int i = 0; i < njobs && shown < 8; i++)
                if ((jobs[i].st == READY || jobs[i].st == RUNNING || jobs[i].st == BLOCKED) && *lvl(&jobs[i]) == L) {
                    printf(" %s%s%s", &jobs[i] == run ? "\033[1;32m*" : "", jobs[i].name, &jobs[i] == run ? "\033[0m" : "");
                    shown++;
                }
            printf("\n");
        }
        printf("\n");
    }
    for (int g = 0; g < ngroups; g++) {
        double share = tot > 0 ? 100 * gcpu[g] / tot : 0;
        int bar = (int)(share / 2.5);
        printf("  %-10s %5.1f%% ", groups[g].name, share);
        for (int b = 0; b < bar; b++) printf("#");
        printf("\n");
    }
    fflush(stdout);
}

static void run_controlled(void)
{
    int pfd[2];
    if (pipe(pfd)) { perror("pipe"); exit(1); }
    msg_fd = pfd[0];
    fcntl(msg_fd, F_SETFL, O_NONBLOCK);
    fcntl(msg_fd, F_SETFD, FD_CLOEXEC);
    spawn_all(pfd[1]);
    close(pfd[1]);

    t0 = 0; t0 = now();
    for (int i = 0; i < njobs; i++) jobs[i].cpu0 = clk_ms(jobs[i].clk);
    next_boost = boost;
    double tend = duration;

    while (now() < tend) {
        admit_and_wake();
        Job *j = pick();
        if (!j) {
            int alive = 0;
            for (int i = 0; i < njobs; i++) if (jobs[i].st != DONE) alive = 1;
            if (!alive) break;
            double wait = next_event_time(tend) - now();
            if (boost > 0 && next_boost - now() < wait) wait = next_boost - now();
            if (wait < 0) wait = 0;
            struct pollfd pf[2] = { { msg_fd, POLLIN, 0 }, { sig_fd, POLLIN, 0 } };
            struct timespec ts = { (time_t)(wait / 1000), (long)(fmod_ms(wait) * 1e6) };
            ppoll(pf, 2, &ts, NULL);
            read_messages(NULL);
            check_children(NULL);
            draw(NULL, 0);
            continue;
        }

        double slice = slice_for(j), ts0 = now();
        int level_at_start = *lvl(j);
        if (j->fresh_ready) {
            double r = ts0 - j->ready_since;
            j->resp_sum += r; j->resp_n++;
            if (r > j->resp_max) j->resp_max = r;
            j->fresh_ready = 0;
        }
        if (j->first_run < 0) j->first_run = ts0;
        j->dispatches++;
        groups[j->group].last_run = ++seq_counter;
        j->st = RUNNING;
        double c_before = clk_ms(j->clk);
        kill(j->pid, SIGCONT);

        const char *why = "QUANTUM";
        int exited = 0;
        for (;;) {
            double t = now();
            double until = ts0 + slice;
            if (t >= until) { why = "QUANTUM"; break; }
            if (t >= tend) { why = "END"; break; }
            double limit = until;
            double ne = next_event_time(tend);
            if (ne < limit) limit = ne;
            if (boost > 0 && next_boost < limit) limit = next_boost;
            double wait = limit - t; if (wait < 0) wait = 0;
            struct pollfd pf[2] = { { msg_fd, POLLIN, 0 }, { sig_fd, POLLIN, 0 } };
            struct timespec tw = { (time_t)(wait / 1000), (long)(fmod_ms(wait) * 1e6) };
            int r = ppoll(pf, 2, &tw, NULL);
            if (r > 0 && (pf[1].revents & POLLIN) && check_children(j)) { exited = 1; why = "EXIT"; break; }
            if (r > 0 && (pf[0].revents & POLLIN) && read_messages(j)) { why = "BLOCK"; break; }
            admit_and_wake();
            if (should_preempt(j)) { why = "PREEMPT"; break; }
            draw(j, 0);
        }

        double used;
        if (!exited) {
            kill(j->pid, SIGSTOP);
            int st;
            struct rusage ru;
            if (wait4(j->pid, &st, WUNTRACED, &ru) == j->pid && !WIFSTOPPED(st)) {
                j->exit_cpu = ru_ms(&ru);
                exited = 1; why = "EXIT"; /* exited just now */
                j->pid = -j->pid;
            }
        }
        double te = now();
        if (!exited) used = clk_ms(j->clk) - c_before;
        else used = j->exit_cpu - c_before;
        if (used < 0) used = 0;
        j->cpu += used;

        if (exited) {
            charge(j, used, 0); /* bill exits too */
            reap_done(j, 0);
        } else if (!strcmp(why, "BLOCK")) {
            charge(j, used, 0);
            j->st = BLOCKED;
        } else {
            int full = !strcmp(why, "QUANTUM");
            charge(j, used, full);
            read_messages(NULL);
            admit_and_wake(); /* new jobs go first */
            if (j->st == RUNNING) make_ready(j, 0);
            if (!strcmp(why, "END")) j->st = READY;
        }
        log_event(ts0, te, j, level_at_start, why, used);
        draw(j, 0);
        read_messages(NULL);
    }
    draw(NULL, 1);

    /* done, kill everyone */
    for (int i = 0; i < njobs; i++) {
        if (jobs[i].pid > 0) {
            kill(jobs[i].pid, SIGKILL);
            kill(jobs[i].pid, SIGCONT);
        }
    }
    while (waitpid(-1, NULL, 0) > 0) {}
}

/* -p linux: just start jobs, kernel decides */
static void run_linux(void)
{
    cpu_set_t set;
    CPU_ZERO(&set); CPU_SET(0, &set);
    int pp[2];
    if (pipe(pp)) { perror("pipe"); exit(1); }
    t0 = 0; t0 = now();
    pid_t leaders[MAXGROUPS];
    for (int g = 0; g < ngroups; g++) {
        leaders[g] = fork();
        if (leaders[g] == 0) {
            close(pp[0]);
            if (sessions) setsid(); /* new autogroup */
            for (int i = 0; i < njobs; i++) {
                if (jobs[i].group != g) continue;
                double w = jobs[i].arrival - now();
                if (w > 0) { struct timespec ts = { (time_t)(w / 1000), (long)(fmod_ms(w) * 1e6) }; nanosleep(&ts, NULL); }
                pid_t p = fork();
                if (p == 0) {
                    sched_setaffinity(0, sizeof set, &set);
                    sigset_t none; sigemptyset(&none); sigprocmask(SIG_SETMASK, &none, NULL);
                    execv("./job", jobs[i].argv);
                    execvp("job", jobs[i].argv);
                    _exit(127);
                }
                int rec[2] = { i, p };
                if (write(pp[1], rec, sizeof rec) != sizeof rec) _exit(1);
            }
            while (wait(NULL) > 0) {}
            _exit(0);
        }
    }
    close(pp[1]);
    fcntl(pp[0], F_SETFL, O_NONBLOCK);
    double tend = duration;
    while (now() < tend) {
        int rec[2];
        while (read(pp[0], rec, sizeof rec) == sizeof rec) {
            Job *j = &jobs[rec[0]];
            j->pid = rec[1];
            j->st = RUNNING;
            clock_getcpuclockid(j->pid, &j->clk);
            j->cpu0 = 0;
            j->first_run = now();
        }
        for (int i = 0; i < njobs; i++)
            if (jobs[i].st == RUNNING) {
                double v = clk_ms(jobs[i].clk);
                if (v >= 0) jobs[i].cpu = v;
            }
        draw(NULL, 0);
        usleep(2000);
    }
    for (int i = 0; i < njobs; i++)
        if (jobs[i].st == RUNNING) {
            double v = clk_ms(jobs[i].clk);
            if (v >= 0) jobs[i].cpu = v;
            kill(jobs[i].pid, SIGKILL);
        }
    for (int g = 0; g < ngroups; g++) kill(leaders[g], SIGKILL);
    while (waitpid(-1, NULL, 0) > 0) {}
}

double fmod_ms(double ms) { return ms - (long)(ms / 1000) * 1000.0; }

static void report(void)
{
    double tot = 0;
    for (int g = 0; g < ngroups; g++) groups[g].cpu = 0;
    for (int i = 0; i < njobs; i++) { groups[jobs[i].group].cpu += jobs[i].cpu; tot += jobs[i].cpu; }
    if (summary_path) {
        FILE *f = fopen(summary_path, "w");
        fprintf(f, "job,name,group,cpu_ms,first_run,finish,resp_avg,resp_max,resp_n,dispatches\n");
        for (int i = 0; i < njobs; i++) {
            Job *j = &jobs[i];
            fprintf(f, "%d,%s,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%ld,%ld\n", i, j->name, j->group, j->cpu,
                    j->first_run, j->finish, j->resp_n ? j->resp_sum / j->resp_n : -1, j->resp_max, j->resp_n, j->dispatches);
        }
        fclose(f);
    }
    printf("RESULT policy=%s acct=%d boost=%.0f groups=%d sessions=%d q=%.1f total_cpu=%.1f wall=%.1f",
           policy, accounting, boost, group_mode, sessions, q, tot, duration);
    for (int g = 0; g < ngroups; g++)
        printf(" %s=%.2f", groups[g].name, tot > 0 ? 100 * groups[g].cpu / tot : 0);
    printf("\n");
}

int main(int argc, char **argv)
{
    int c;
    while ((c = getopt(argc, argv, "p:q:L:B:AGST:e:s:v")) != -1) {
        switch (c) {
        case 'p': snprintf(policy, sizeof policy, "%s", optarg); break;
        case 'q': q = atof(optarg); break;
        case 'L': levels = atoi(optarg); if (levels < 1 || levels > MAXLEVELS) levels = 3; break;
        case 'B': boost = atof(optarg); break;
        case 'A': accounting = 1; break;
        case 'G': group_mode = 1; break;
        case 'S': sessions = 1; break;
        case 'T': duration = atof(optarg); break;
        case 'e': events_path = optarg; break;
        case 's': summary_path = optarg; break;
        case 'v': live = 1; break;
        default: fprintf(stderr, "see the comment at the top of usched.c for usage\n"); return 1;
        }
    }
    if (optind >= argc) { fprintf(stderr, "missing workload file\n"); return 1; }
    workload_path = argv[optind];
    load_workload(workload_path);

    /* scheduler on cpu 1 so it doesn't eat the jobs' cpu */
    cpu_set_t set; CPU_ZERO(&set);
    CPU_SET(sysconf(_SC_NPROCESSORS_ONLN) > 1 ? 1 : 0, &set);
    sched_setaffinity(0, sizeof set, &set);

    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL; sa.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    sig_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);

    if (events_path) {
        events = fopen(events_path, "w");
        fprintf(events, "t_start,t_end,job,name,group,level,reason,used_ms\n");
    }
    if (!strcmp(policy, "linux")) run_linux();
    else if (!strcmp(policy, "rr") || !strcmp(policy, "mlfq") || !strcmp(policy, "stride")) run_controlled();
    else { fprintf(stderr, "unknown policy %s\n", policy); return 1; }
    if (events) fclose(events);
    report();
    (void)state_name;
    return 0;
}
