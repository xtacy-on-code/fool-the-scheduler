#!/usr/bin/env python3
# every attack vs every policy -> results/<label>/shares.csv   usage: run_linux.py label [--reps n] [--quick]
import csv, os, platform, re, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

label = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "linux"
REPS = int(sys.argv[sys.argv.index("--reps") + 1]) if "--reps" in sys.argv else 3
QUICK = "--quick" in sys.argv
DUR = 1500 if QUICK else 3000
OUT = os.path.join("results", label)
os.makedirs(os.path.join(OUT, "runs"), exist_ok=True)

subprocess.run(["make", "-s"], check=True)

rows = []

def run(exp, config, args, workload, rep, extra_tag=""):
    tag = f"{exp}_{config}_{rep}{extra_tag}".replace(" ", "")
    summ = os.path.join(OUT, "runs", tag + "_summary.csv")
    ev = os.path.join(OUT, "runs", tag + "_events.csv")
    cmd = ["./usched", *args.split(), "-T", str(DUR), "-s", summ, "-e", ev, os.path.join("workloads", workload)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    line = [l for l in out.splitlines() if l.startswith("RESULT")]
    if not line:
        print("  !! no result for", cmd)
        return
    shares = dict(re.findall(r" ([A-Za-z_][\w#]*)=([\d.]+)", line[0].split("total_cpu")[1]))
    total = float(re.search(r"total_cpu=([\d.]+)", line[0]).group(1))
    for g, v in shares.items():
        if g == "wall":
            continue
        rows.append(dict(env=label, exp=exp, config=config, rep=rep, group=g, share=float(v),
                         total_cpu=total, summary=summ))
    print(f"  {exp:10s} {config:16s} rep{rep}  " + "  ".join(f"{g}={v}" for g, v in shares.items() if g != "wall"))

POL = {
    "RR":          "-p rr",
    "MLFQ":        "-p mlfq",
    "MLFQ+boost":  "-p mlfq -B 100",
    "MLFQ+acct":   "-p mlfq -A",
    "MLFQ+both":   "-p mlfq -A -B 100",
    "MLFQ+groups": "-p mlfq -A -G",
    "RR+groups":   "-p rr -G",
    "stride":      "-p stride",
    "stride+groups": "-p stride -G",
    "Linux":       "-p linux",
    "Linux+sessions": "-p linux -S",
}

t_start = time.time()
for rep in range(REPS):
    print(f"== repetition {rep + 1}/{REPS}")
    # 0. sanity check: the slide-13 example (1 unit = 10 ms)
    run("slide13", "MLFQ", "-p mlfq -q 80", "slide13.txt", rep)
    # 1-4. every attack against every scheduler
    for exp, wl in [("iotrick", "iotrick.txt"), ("flood", "flood.txt"),
                    ("army", "army.txt"), ("stream", "army_stream.txt")]:
        for c in POL:
            run(exp, c, POL[c], wl, rep)
    # the I/O trick: attacker share as a function of how long it runs before its "I/O"
    for r in [1, 2, 4, 6, 7, 7.5]:
        wl = os.path.join(OUT, "runs", f"iotrick_r{r}.txt")
        with open(wl, "w") as f:
            f.write(f"honest 0 0 100 every=0 count=2 cpu 100000\nattacker 1 0 100 attack {r} 1\n")
        run("iosweep", f"r={r}", "-p mlfq", os.path.relpath(wl, "workloads"), rep)
    # starvation vs the boost period S (slide 18, rule 5)
    for S in [25, 50, 100, 200, 500, 1000]:
        run("boostsweep", f"S={S}", f"-p mlfq -B {S}", "flood.txt", rep)

with open(os.path.join(OUT, "shares.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
with open(os.path.join(OUT, "machine.txt"), "w") as f:
    f.write(f"label: {label}\nkernel: {platform.release()}\n")
    f.write(f"cpus: {os.cpu_count()}\n")
    try:
        model = [l for l in open("/proc/cpuinfo") if l.startswith("model name")][0].split(":")[1].strip()
        f.write(f"cpu: {model}\n")
    except Exception:
        pass
    for p in ["/proc/sys/kernel/sched_autogroup_enabled"]:
        try:
            f.write(f"{p}: {open(p).read().strip()}\n")
        except Exception:
            pass
    f.write(f"date: {time.strftime('%Y-%m-%d %H:%M')}\nruntime_s: {time.time() - t_start:.0f}\n")
print(f"done in {time.time() - t_start:.0f}s -> {OUT}/shares.csv")
