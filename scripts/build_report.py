#!/usr/bin/env python3
# report/report.md + pdf from results/<label>/numbers.json
import json, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
labels = sys.argv[1:] or ["sandbox-vm"]
MAIN = labels[0]
RES = os.path.join("results", MAIN)
N = json.load(open(os.path.join(ROOT, RES, "numbers.json")))
machine = open(os.path.join(ROOT, RES, "machine.txt")).read().strip().splitlines()
M = dict(l.split(": ", 1) for l in machine if ": " in l)
REPO = "https://github.com/xtacy-on-code/fool-the-scheduler"
FIG = f"../{RES}/figs"

def p(x, d=0):
    return "n/a" if x is None else f"{x:.{d}f}\\%"

OTHER = labels[1] if len(labels) > 1 else None
N2 = json.load(open(os.path.join(ROOT, "results", OTHER, "numbers.json"))) if OTHER else N
M2 = dict(l.split(": ", 1) for l in open(os.path.join(ROOT, "results", OTHER, "machine.txt")).read().splitlines() if ": " in l) if OTHER else M
import csv as _csv, statistics as _st
CG = {}
_cgp = os.path.join(ROOT, RES, "cgroups.csv")
if os.path.exists(_cgp):
    _r = list(_csv.DictReader(open(_cgp)))
    for mode in ("same-cgroup", "own-cgroups", "own-cgroups+cpu"):
        v = [float(x["share"]) for x in _r if x["mode"] == mode and x["group"] == "victim"]
        if v:
            CG[mode] = _st.mean(v)
io = N["iotrick_attacker"]; fl = N["flood_cpujob"]; ar = N["army_army"]; stm = N["stream_army"]
bo = N["boost"]; sw = N["iosweep"]; xv = N["xv6"]; s13 = N["slide13"]
fr = N.get("flood_resp", {})
xt = xv["tests"]

def spread(name):
    v = xv["spread"].get(name, [])
    return f"{min(v):.0f}-{max(v):.0f}\\%" if v else "n/a"

# Windows section
win = N.get("windows")
if win:
    rows = win["rows"]
    lines = ["| test | group | real CPU share | reported CPU share |", "|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['test'].replace('_', ' ')} | {r['group']} | {float(r['real_share']):.1f}\\% | {float(r['reported_share']):.1f}\\% |")
    def W(t, g, k="real_share"):
        for r in rows:
            if r["test"] == t and r["group"] == g:
                return float(r[k])
        return float("nan")
    io_max = max(W(t, "attacker") for t in {r["test"] for r in rows if r["test"].startswith("iotrick")})
    dodge_real, dodge_rep = W("tickdodge_alone_90pct", "dodger", "real_ms"), W("tickdodge_alone_90pct", "dodger", "reported_ms")
    windows_verdict = f"""
* **The I/O trick fails on Windows.** With every kind of "I/O" (`Sleep`, an event completed by another
  thread, `SwitchToThread`) and every run length, the attacker got **at most {io_max:.0f}\\%**, never more
  than the 50\\% fair share. The longer it runs before giving up the CPU, the more it gets
  ({W('iotrick_sleep_run2ms','attacker'):.0f}\\% at 2 ms, {W('iotrick_sleep_run25ms','attacker'):.0f}\\% at 25 ms with `Sleep`): giving up the CPU is simply
  lost time. Windows' wake-up boosts did not turn into an advantage.
* **The process army works on Windows too:** 4 processes took **{W('army_4_vs_1','army'):.0f}\\%** (per-process
  fairness would give 80\\%). Like Linux, Windows is fair per thread, not per user.
* **The tick dodge fails on Windows.** The dodger got only {W('tickdodge_90pct','dodger'):.0f}\\% against an honest
  process, and Windows' reported CPU time matched the real cycles: running alone, the dodger really
  used {dodge_real:.0f} ms and Windows reported {dodge_rep:.0f} ms. Windows does not charge by sampling
  ticks, so the 2007 attack no longer works on it.
* Default timer: 15.625 ms per tick, `Sleep(1)` really sleeps about 14.9 ms. That is why a
  process that sleeps even 1 ms gives away a whole tick, and why short runs got so little.
"""
    windows_text = f"""Machine: {win['header']}.
{windows_verdict}

![Windows results]({FIG}/windows.png){{ width=100% }}

{chr(10).join(lines)}
"""
else:
    windows_text = """*The Windows program (`windows/wintest.exe`) is built and included, but its results
from the author's laptop were not yet available when this version of the report was generated.*
"""

if CG:
    cg_text = f"""I tested this directly with `scripts/cgroup_army.py` (1 victim process vs a 4-process army, CPU 0, 3 runs each):

| setup | victim's share |
|---|---|
| both users in the same cgroup (default terminal) | {CG.get('same-cgroup', float('nan')):.1f}\\% |
| each user in its own cgroup (`systemd-run --user --scope`) | {CG.get('own-cgroups', float('nan')):.1f}\\% |
| each user in its own cgroup **with the CPU controller on** (`-p CPUWeight=100`) | **{CG.get('own-cgroups+cpu', float('nan')):.1f}\\%** |

Separate cgroups alone changed nothing. The reason was in `/sys/fs/cgroup`: the `app.slice` group
listed only `memory pids` in its `cgroup.subtree_control`, so its child cgroups were not scheduled
as groups. Asking for a CPU weight made systemd add `cpu` there, and the CPU was then split per
cgroup: exactly fair."""
    cg_abstract = (f"Separate cgroups alone did not help either; only cgroups with the CPU controller switched on "
                   f"brought the victim back to {CG.get('own-cgroups+cpu', float('nan')):.0f}\\%.")
else:
    cg_text = "The cgroup test (`scripts/cgroup_army.py`) is included in the repository."
    cg_abstract = ""

# environments
env_text = ""
if len(labels) > 1:
    env_text = f"""
## 5.6 The same experiments on different machines

![Environments]({FIG}/environments.png){{ width=95% }}

The shape of the results is the same on both Linux machines, with one exception: separate sessions
protect against the process army only in the VM (section 5.3).
"""

if CG:
    cg_simple = (f"with both users in the same cgroup the victim got {CG.get('same-cgroup', 0):.0f}\\%, in separate cgroups "
                 f"still {CG.get('own-cgroups', 0):.0f}\\%. The reason was that the cgroup `cpu` controller was not switched on for "
                 f"them. With `-p CPUWeight=100` systemd switches it on, and then the victim got {CG.get('own-cgroups+cpu', 0):.0f}\\%.")
else:
    cg_simple = "see scripts/cgroup_army.py."
def WV(t, g, k="real_share"):
    for r in (win["rows"] if win else []):
        if r["test"] == t and r["group"] == g:
            return float(r[k])
    return float("nan")
w_io = max([WV(r["test"], "attacker") for r in win["rows"] if r["test"].startswith("iotrick")]) if win else float("nan")

md = f"""---
title: "Can You Fool a Scheduler?"
subtitle: "Testing the MLFQ claims from Lecture 7 on real processes, xv6, Linux and Windows"
author: "Zala Vedant (B24CS054) | CSL301 Operating Systems, IIT Bhilai | Optional project"
date: "November 2026"
geometry: margin=2.3cm
fontsize: 11pt
mainfont: DejaVu Serif
monofont: DejaVu Sans Mono
colorlinks: true
urlcolor: blue
header-includes:
  - \\usepackage{{float}}
  - \\floatplacement{{figure}}{{H}}
---

Code and data: <{REPO}>

# Abstract

In Lecture 7 we saw that MLFQ can be fooled: a process that does I/O just before its time slice
ends stays in the top queue forever (slide 17), CPU-bound jobs can starve (slide 16), and priority
boost plus better accounting are supposed to fix this (slide 18). I wanted to see if this really
happens on real processes and not only on paper. I wrote a small scheduler that controls real
Linux processes using signals, added the same MLFQ to the xv6 kernel, and tried the same attacks
on Linux and Windows on my laptop.

The attack works: on the lecture's MLFQ the attacker got {p(io['MLFQ'])} of the CPU when its fair share is
33\\%. Better accounting brings it down to {p(io['MLFQ+acct'])}. Linux ({p(io['Linux'])}) and Windows (at most {w_io:.0f}\\%) were not
fooled by this trick. But both of them can be beaten by just starting many processes: 4 processes
of one user got {p(ar['Linux'])} of the CPU on Linux and {WV('army_4_vs_1', 'army'):.0f}\\% on Windows. In xv6, where time is counted
in timer ticks, the slide-18 fix did not help at all ({p(xt['MLFQ + allotment'])} for the attacker) until I changed
the kernel to count real time.

# 1. Introduction

The scheduler decides who gets the CPU. MLFQ tries to guess which processes are interactive by
watching whether they give up the CPU early. The slides themselves say this guess can be abused.
My questions were:

1. Does the slide-17 trick really work on real processes, and how much CPU can the attacker get?
2. Do the slide-18 fixes (boost and better accounting) stop it?
3. Are there other simple ways to cheat?
4. Can Linux and Windows be fooled the same way?

# 2. What I built

## 2.1 usched: a scheduler for real processes

I could not change the Linux kernel's scheduler, so I wrote a normal program, `usched`, that acts
as the scheduler for a group of child processes (`src/usched.c`, `src/job.c`):

* All jobs are pinned to CPU 0 with `sched_setaffinity`, so there is only one CPU like in our examples.
* Every job is stopped with `SIGSTOP`. The job that the policy picks gets `SIGCONT`, runs for its time
  slice, and is stopped again. So Linux only runs the process that my scheduler chose.
* When a job wants to do "I/O" it first writes a short message into a pipe and then sleeps.
  `usched` reads it and marks the job BLOCKED. This is like a system call telling the kernel.
* `usched` waits with `ppoll()` on the pipe and on SIGCHLD, with a timeout equal to the time slice.
  Whatever happens first ends the slice: time slice over, job blocked, or job exited.
* The CPU time each job really used is read with `clock_getcpuclockid()`.

So each job goes through the states from Lecture 3 (ready, running, blocked, done). The policies are
round robin and the MLFQ from the slides (3 queues, slices 8, 16 and 32 ms) with options for the
priority boost (`-B`), better accounting (`-A`) and counting CPU per user instead of per process
(`-G`). There is also a `linux` mode where `usched` does not schedule at all and Linux decides.

```c
kill(j->pid, SIGCONT);                 /* run the chosen job */
int r = ppoll(pf, 2, &tw, NULL);       /* wait: io message, exit, or slice over */
...
kill(j->pid, SIGSTOP);                 /* take the CPU back */
used = clk_ms(j->clk) - c_before;      /* cpu it really used */
charge(j, used, full_slice);           /* demote or not */
```

The jobs are: an honest CPU-bound job, an interactive job (compute a bit, then I/O), and the
attacker from slide 17 (compute 7 ms of its 8 ms slice, then 1 ms of I/O, forever).

## 2.2 MLFQ in xv6

Our lectures are based on xv6, so I also added the MLFQ to the xv6 kernel (RISC-V version):

* `proc.h`: each process gets a queue level and counters for CPU time.
* `trap.c`: on a timer interrupt the process only gives up the CPU if its slice is used up
  (normal xv6 switches on every tick).
* `proc.c`: `scheduler()` picks the highest queue first, round robin inside a queue, plus boost.
* Three new system calls: `schedctl()` to choose the policy, `pstat()` to read a process's
  statistics and `rtime()` to read the time.
* `user/schedtest.c`: starts two CPU hogs and one attacker.

xv6 only notices time on timer ticks (I set them to 10 ms). The attacker uses this: it sleeps
across every tick and runs only between ticks, so it is never running when a tick happens. If CPU
time is counted per tick, it is never charged.

## 2.3 Windows

`windows/wintest.c` starts the same kind of processes on CPU 0 and measures how much CPU each got,
using the exact cycle counter and also what Windows reports (the numbers Task Manager uses).

## 2.4 Setup

Laptop: {M.get('cpu', '?')}, native Ubuntu with Linux {M.get('kernel', '?')}, and Windows 11 on the same laptop.
I also used a small cloud VM while developing. Each test runs for 3 seconds and is repeated 3 times;
on the laptop the 3 runs almost always agreed within 0.2\\%. Fair share means splitting the CPU
equally between the processes (or users).

# 3. Checking that usched works

Before attacking anything I ran the example from slide 13 (P1 arrives at 0 and needs 100 units,
P2 arrives at 40 and needs 12, queues 8/16/32, with 1 unit = 10 ms). The slide says P2 finishes at
520 ms and P1 at 1120 ms. With real processes P2 finished at {s13['p2_finish_ms']:.1f} ms and P1 at {s13['p1_finish_ms']:.1f} ms, in
the same order and with the same preemption.

![Slide 13 example: slide vs measured]({FIG}/slide13.png){{ width=100% }}

# 4. Results

## 4.1 The I/O trick (slide 17)

One attacker against two honest CPU-bound jobs. Fair share is 33\\%.

![I/O trick]({FIG}/iotrick.png){{ width=100% }}

* MLFQ from the slides: the attacker gets {p(io['MLFQ'])}. It never uses a full slice, so it never moves
  down, and the honest jobs only run during its 1 ms of I/O. So slide 17 is correct.
* Boost alone: {p(io['MLFQ+boost'])}. It lifts the honest jobs up for a short time but the attacker is never demoted.
* Better accounting: {p(io['MLFQ+acct'])}. Now its 7 ms pieces are added up and it moves down like everyone else.
* Round robin ({p(io['RR'])}) and Linux ({p(io['Linux'])}) are not fooled, because giving up the CPU early does not
  give any advantage there. Linux keeps track of how much CPU each process actually used.

I also checked it with a simple formula: if the attacker runs $r$ ms and then does 1 ms of I/O, and
never moves down, it should get $r/(r+1)$ of the CPU.

| $r$ (ms) | {" | ".join(str(r) for r in sw['r'])} |
|---|{"---|" * len(sw['r'])}
| formula (\\%) | {" | ".join(f"{x:.1f}" for x in sw['model'])} |
| measured (\\%) | {" | ".join(f"{x:.1f}" for x in sw['measured'])} |

The measured values are 1-2 points lower because every I/O also costs a switch.

## 4.2 Starvation (slide 16) and the boost

One CPU-bound job against 4 interactive jobs (each computes 3 ms, then waits 9 ms).

![Flood]({FIG}/flood.png){{ width=100% }}

With the plain MLFQ the CPU-bound job gets only {p(fl['MLFQ'], 1)}: it starves, as slide 16 says. Better accounting
saves it ({p(fl['MLFQ+acct'])}), but the interactive jobs then get demoted too and have to wait longer.
The boost period matters a lot:

| boost (ms) | {" | ".join(str(s) for s in bo['S'])} |
|---|{"---|" * len(bo['S'])}
| CPU job (\\%) | {" | ".join(f"{x:.1f}" for x in bo['cpujob_share'])} |
| interactive wait (ms) | {" | ".join(f"{x:.2f}" for x in bo['interactive_resp_ms'])} |

Boosting often helps the CPU-bound job but makes the interactive jobs wait longer, so there is no
perfect value.

## 4.3 Many processes (process army)

Here nothing is tricky: one user just starts 4 CPU-bound processes, the other user has 1.

![Process army]({FIG}/army.png){{ width=100% }}

Every scheduler that is fair per process gives the 4 processes 80\\% (4 out of 5), and Linux too
({p(ar['Linux'])}). Only counting CPU per user (`-G`) gives the victim back its half ({p(100 - ar['MLFQ+groups'])}).

On Linux I tried two things to separate the users:

* Separate terminal sessions: in the VM this gave 50/50, but on my Ubuntu laptop it did not
  change anything (still {p(N['army_sessions'])} for the army).
* Separate cgroups (`systemd-run --user --scope`): {cg_simple}

## 4.4 The tick dodge in xv6

Two CPU hogs and one attacker that runs 90\\% of every tick but sleeps when the tick comes.

![xv6]({FIG}/xv6.png){{ width=100% }}

| xv6 scheduler | attacker real CPU | CPU charged by ticks |
|---|---|---|
{chr(10).join(f"| {k} | {v:.1f}\\% | {xv['charged'][k]:.1f}\\% |" for k, v in xt.items())}

* Even normal xv6 gives the attacker {p(xt['xv6 round robin'])} and charges it almost nothing.
* With the MLFQ, the attacker is never seen running at a tick, so it never moves down: {p(xt['MLFQ (tick charging)'])}.
* The slide-18 fix also fails here ({p(xt['MLFQ + allotment'])}), because the allotment is also counted in ticks.
* When I changed xv6 to charge the real time (read from the RISC-V time register at every switch),
  the attacker moved to the lowest queue ({p(xt['MLFQ + allotment + precise'])}). It was still a bit more than fair, so I also
  made the scheduler pick the process that used the least CPU inside a queue. Then all three got
  {p(xt['MLFQ + allotment + precise + fair'], 1)}.

## 4.5 Windows

* The I/O trick did not work: the attacker never got more than {w_io:.0f}\\% (fair share 50\\%).
* 4 processes against 1 got {WV('army_4_vs_1', 'army'):.0f}\\%, same as Linux.
* The tick dodge did not work either, and the CPU time Windows reported matched the real cycles
  (the dodger really used {WV('tickdodge_alone_90pct', 'dodger', 'real_ms'):.0f} ms and Windows showed {WV('tickdodge_alone_90pct', 'dodger', 'reported_ms'):.0f} ms).

![Windows]({FIG}/windows.png){{ width=100% }}

## 4.6 Summary

| | I/O trick | starvation | process army | tick dodge |
|---|---|---|---|---|
| MLFQ from the slides | fooled | starves | fooled | fooled (xv6) |
| MLFQ + boost | partly | partly | fooled | fooled (xv6) |
| MLFQ + better accounting | ok | ok, interactive slower | fooled | fooled if counted in ticks |
| per-user accounting | ok | ok | ok | - |
| Linux | ok | ok | fooled (ok with cgroups + CPU controller) | ok |
| Windows | ok | - | fooled | ok |

# 5. Problems I ran into

1. My first results for the process army were wrong. Short jobs usually finish inside their slice
   and I only charged CPU at the end of a slice, not when a job exited. Fixed by also charging on exit.
2. My first per-user version still gave the army 80\\%: the levels were per user but inside a queue
   it was still round robin per process. I had to make users take turns.
3. In xv6, after switching to real-time charging, one honest process almost starved. Every tick
   wakes up the waiting test program, which preempts the running process, and the round-robin order
   kept giving the slot after the attacker to the same process. Picking the process with the least
   CPU fixed it.
4. The cloud VM sometimes did not run my process for a few milliseconds, so `usched` thought a
   slice was used up and demoted the attacker by mistake. On the laptop this did not happen.
5. Separate sessions worked in the VM but not on my laptop, and separate cgroups first did not
   work either, until I found the `cpu` controller was not enabled for them.
6. The newest xv6 renamed `sleep` to `pause` and changed `copyout`, so I had to adjust my code.

# 6. Limitations

* `usched` runs in user space and the jobs tell it about their I/O; a real kernel sees the system call.
* Only one CPU.
* The Linux results come from one laptop; other kernels or desktops may behave differently.

# 7. Conclusion

Slide 17 is right: the MLFQ from the lecture can be fooled ({p(io['MLFQ'])} for the attacker), and slide 16's
starvation also happens. The slide-18 fixes work, but only if CPU time is counted properly: in xv6
with tick counting they did nothing. Linux and Windows are not fooled by the I/O trick, but both
give more CPU to a user who simply starts more processes, unless the system groups processes per user.

# References

1. Lecture 6 and Lecture 7 slides, CSL301, IIT Bhilai.
2. R. and A. Arpaci-Dusseau, Operating Systems: Three Easy Pieces, chapters 7 and 8.
3. D. Tsafrir, Y. Etsion, D. Feitelson, "Secretly Monopolizing the CPU Without Superuser Privileges", USENIX Security 2007 (idea for the tick dodge).
4. xv6-riscv, MIT PDOS, <https://github.com/mit-pdos/xv6-riscv>.
5. Linux man pages `sched(7)`, `cgroups(7)`.

# Appendix: how to run

```bash
make
./usched -p mlfq -v -T 6000 workloads/iotrick.txt   # watch the attacker win
./usched -p mlfq -A -v -T 6000 workloads/iotrick.txt   # and lose with accounting
python3 scripts/run_linux.py <name>                    # all Linux tests
python3 scripts/run_xv6.py <name>                      # xv6 tests (qemu)
python3 scripts/analyze.py <name>                      # graphs
```
"""

# plainer style: no bold or italics in the body, fewer slogans
import re
REWRITE = [
    ("Main results. The slide-17 trick works exactly as the slide predicts: against", "What I found: the slide-17 trick works as the slide says. Against"),
    ("*Better accounting is only better if the accounting is accurate.*", "So better accounting only helps if the accounting itself is accurate."),
    ("exactly fair. This is what Linux does.", "which is fair. Linux does basically the same thing."),
    ("# 6. What surprised me and what broke", "# 6. Problems and surprises"),
    ("These are things that actually happened while building and measuring.", "Things that went wrong or surprised me while building and measuring:"),
    ("built into Linux.", "already built into Linux."),
]
def plain(text):
    out, code = [], False
    for line in text.split("\n"):
        if line.startswith("```"):
            code = not code
        if not code and not line.startswith("---") and not line.startswith("title:"):
            line = line.replace("**", "")
            line = re.sub(r"(?<![\w*\\])\*(?=\S)([^*\n]+?)(?<=\S)\*(?![\w*])", r"\1", line)
        out.append(line)
    return "\n".join(out)
for a, b in REWRITE:
    md = md.replace(a, b)
md = plain(md)

os.makedirs(os.path.join(ROOT, "report"), exist_ok=True)
open(os.path.join(ROOT, "report", "report.md"), "w").write(md)
r = subprocess.run(["pandoc", "report.md", "-o", "report.pdf", "--pdf-engine=xelatex"],
                   cwd=os.path.join(ROOT, "report"), capture_output=True, text=True)
print(r.stderr[-2000:] if r.returncode else "report/report.pdf written")
