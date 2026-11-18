# Can You Fool a Scheduler?

**Attacking and hardening CPU schedulers — from the lecture's MLFQ to xv6, Linux and Windows**

Optional project, CSL301 Operating Systems, IIT Bhilai — Zala Vedant (B24CS054)

Lecture 7 makes three claims about the Multi-Level Feedback Queue:

* **slide 16** – CPU-bound jobs can **starve**,
* **slide 17** – a process can **fool** MLFQ by doing I/O just before its time slice ends (a DoS),
* **slide 18** – **priority boost** and **better accounting** fix it.

This project tests those claims on real systems instead of on paper, with four attacks
against a dozen scheduler settings in three places:

| Arena | What it is |
|---|---|
| `src/usched.c` | a user-space scheduler that schedules **real Linux processes** (SIGSTOP/SIGCONT, one CPU core): RR, the lecture's MLFQ with every fix as a switch, stride (proportional share), per-user accounting |
| `xv6/` | the lecture's MLFQ **inside the xv6 kernel** (the course's teaching OS), attacked from xv6 user programs and then hardened |
| your machine | Linux's own scheduler (EEVDF), with and without autogroup sessions, native and WSL, and Windows (`windows/wintest.exe`) |

The four attacks: **I/O trick** (slide 17), **flood** (slide 16), **process army** (one user, many
processes), **tick dodge** (run between timer ticks so a tick-sampling kernel never charges you).

The full write-up, with every figure, is in `report/report.pdf`.

## Repository layout

```
src/usched.c          user-space scheduler for real processes (policies, accounting, live view)
src/job.c             workloads: honest CPU job, interactive job, slide-17 attacker
workloads/*.txt       the experiments' job mixes
scripts/run_linux.py  runs every attack against every policy and against Linux itself
scripts/run_xv6.py    boots the patched xv6 in QEMU (1 CPU) and runs the tick-dodge tests
scripts/analyze.py    figures + numbers.json from the raw results
xv6/xv6-riscv/        xv6 with the MLFQ (kernel/proc.c, trap.c, param.h, sysproc.c, user/schedtest.c)
xv6/mlfq.patch        the same changes as a diff against upstream xv6-riscv
windows/wintest.c     Windows test program (prebuilt wintest.exe included)
results/<machine>/    raw CSVs, per-run logs, figures
report/               report source and PDF
```

## Running it

Linux (native Ubuntu or WSL):

```bash
sudo apt install build-essential python3-matplotlib            # once
make
./usched -p mlfq -v -T 6000 workloads/iotrick.txt               # live demo: watch the attacker win
./usched -p mlfq -A -v -T 6000 workloads/iotrick.txt            # ...and lose once accounting is on
python3 scripts/run_linux.py ubuntu-native                      # all experiments, ~10 min
python3 scripts/analyze.py ubuntu-native                        # figures -> results/ubuntu-native/figs
```

xv6:

```bash
sudo apt install qemu-system-misc gcc-riscv64-linux-gnu         # once
python3 scripts/run_xv6.py ubuntu-native                        # all xv6 tests, ~6 min
cd xv6/xv6-riscv && make CPUS=1 qemu                            # or by hand, inside xv6:
#   $ schedtest 1 0 3 90        MLFQ, tick charging: the attacker takes ~90% while charged ~0 ticks
#   $ schedtest 15 0 3 90       precise accounting + fair order: everyone gets 1/3
```

Windows: double-click `windows/wintest.exe` (about 2 minutes, keep the PC idle). It writes
`wintest_results.csv` next to the exe; copy it to `results/windows/`.

### usched options

```
usched -p rr|mlfq|stride|linux [-q ms] [-L levels] [-B boost_ms] [-A] [-G] [-S] [-T ms] [-e events.csv] [-s summary.csv] [-v] WORKLOAD
  -A  slide-18 accounting (demote after the level's allotment, however often you yield)
  -B  rule-5 priority boost every S ms
  -G  account per user (group) instead of per process
  -S  (linux) put every group in its own session, so Linux autogroup can separate them
  -v  live view
```
