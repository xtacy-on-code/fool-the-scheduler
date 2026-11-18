#!/usr/bin/env python3
# army (4 procs) vs victim (1 proc) on cpu 0: same cgroup / own cgroups / own cgroups + cpu controller
# usage: cgroup_army.py label   (run from a normal desktop terminal)
import csv, os, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
T = 3.0

def cpu_seconds(pid):
    fields = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")   # utime + stime

if len(sys.argv) > 1 and sys.argv[1] == "child":
    name, n, start = sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
    os.sched_setaffinity(0, {0})                      # everyone on CPU 0
    cg = open("/proc/self/cgroup").read().strip()
    while time.time() < start:
        time.sleep(0.005)
    jobs = [subprocess.Popen(["./job", str(i), "cpu", "100000"]) for i in range(n)]
    time.sleep(T)
    total = sum(cpu_seconds(j.pid) for j in jobs)
    for j in jobs:
        j.kill()
        j.wait()
    print(f"CPU {name} {total:.3f} {cg}", flush=True)
    sys.exit(0)

label = sys.argv[1] if len(sys.argv) > 1 else "linux"
subprocess.run(["make", "-s"], check=True)
OUT = os.path.join("results", label)
os.makedirs(OUT, exist_ok=True)

def trial(mode):
    start = time.time() + 1.0
    procs = []
    for name, n in [("victim", 1), ("army", 4)]:
        cmd = [sys.executable, os.path.abspath(__file__), "child", name, str(n), str(start)]
        if mode.startswith("own-cgroups"):
            extra = ["-p", "CPUWeight=100"] if mode.endswith("+cpu") else []
            cmd = ["systemd-run", "--user", "--scope", "--quiet", *extra,
                   f"--unit=fts-{name}-{os.getpid()}-{time.time_ns()}"] + cmd
        procs.append(subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    res, cgs = {}, {}
    for p in procs:
        out, err = p.communicate()
        if err.strip():
            print("  stderr:", err.strip()[:300])
        for line in out.splitlines():
            if line.startswith("CPU"):
                _, nm, v, cg = line.split(" ", 3)
                res[nm], cgs[nm] = float(v), cg
    tot = sum(res.values()) or 1
    return {k: 100 * v / tot for k, v in res.items()}, cgs

def controllers():
    base = f"/sys/fs/cgroup/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service"
    out = {}
    for f in [f"{base}/cgroup.controllers", f"{base}/cgroup.subtree_control", f"{base}/app.slice/cgroup.subtree_control"]:
        try:
            out[f.replace(base, "user@")] = open(f).read().strip()
        except OSError as e:
            out[f.replace(base, "user@")] = f"({e.strerror})"
    return out

print("cgroup controllers before:", controllers())
rows = []
for rep in range(3):
    for mode in ["same-cgroup", "own-cgroups", "own-cgroups+cpu"]:
        shares, cgs = trial(mode)
        print(f"{mode:12s} rep{rep}: " + "  ".join(f"{k}={v:.1f}%" for k, v in shares.items()))
        if rep == 0:
            for k, v in cgs.items():
                print(f"    {k} cgroup: {v}")
        for k, v in shares.items():
            rows.append(dict(env=label, mode=mode, rep=rep, group=k, share=round(v, 2), cgroup=cgs.get(k, "")))

print("cgroup controllers after:", controllers())
with open(os.path.join(OUT, "cgroups.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
print("saved", os.path.join(OUT, "cgroups.csv"))
