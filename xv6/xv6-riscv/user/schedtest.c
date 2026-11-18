// schedtest flags boost secs attack_pct [hogs]
// flags: 0 rr, 1 mlfq, 3 +allotment, 7 +precise, 15 +fair
// attacker sleeps over every tick so tick accounting never sees it
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define TICK_US 10000

static void
hog(void)
{
  volatile unsigned long x = 0;
  for (;;)
    x++;
}

static void
attacker(int pct)
{
  uint64 run_us = (uint64)TICK_US * pct / 100;
  volatile unsigned long x = 0;
  for (;;) {
    pause(1); // wake right after a tick
    uint64 t = rtime();
    while (rtime() - t < run_us)
      x++;
  }   // asleep again before the next one
}

int
main(int argc, char *argv[])
{
  if (argc < 5) {
    printf("usage: schedtest flags boost_ticks seconds attack_pct [hogs]\n");
    exit(1);
  }
  int flags = atoi(argv[1]);
  int boost = atoi(argv[2]);
  int secs = atoi(argv[3]);
  int pct = atoi(argv[4]);
  int nhogs = argc > 5 ? atoi(argv[5]) : 2;

  schedctl(flags, boost);
  int pids[8], n = 0;
  for (int i = 0; i < nhogs && n < 7; i++) {
    int pid = fork();
    if (pid == 0)
      hog();
    pids[n++] = pid;
  }
  if (pct > 0) {
    int pid = fork();
    if (pid == 0)
      attacker(pct);
    pids[n++] = pid;
  }

  pause(secs * 100);

  uint64 st[8][4];
  for (int i = 0; i < n; i++)
    pstat(pids[i], st[i]);
  for (int i = 0; i < n; i++)
    kill(pids[i]);
  for (int i = 0; i < n; i++)
    wait(0);
  schedctl(0, 0);

  uint64 tot_us = 0, tot_ticks = 0;
  for (int i = 0; i < n; i++) {
    tot_us += st[i][2];
    tot_ticks += st[i][1];
  }
  for (int i = 0; i < n; i++) {
    int is_att = (pct > 0 && i == n - 1);
    printf("RESULT flags=%d boost=%d pct=%d role=%s true_us=%d ticks=%d level=%d sched=%d true_pm=%d ticks_pm=%d\n",
           flags, boost, pct, is_att ? "attacker" : "honest",
           (int)st[i][2], (int)st[i][1], (int)st[i][0], (int)st[i][3],
           tot_us ? (int)(st[i][2] * 1000 / tot_us) : 0,
           tot_ticks ? (int)(st[i][1] * 1000 / tot_ticks) : 0);
  }
  printf("DONE\n");
  exit(0);
}
