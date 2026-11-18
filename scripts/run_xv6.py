#!/usr/bin/env python3
# boots xv6 in qemu (1 cpu) and runs schedtest for each setting -> results/<label>/xv6.csv
# needs qemu-system-misc gcc-riscv64-linux-gnu
import csv, os, re, select, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XV6 = os.path.join(ROOT, "xv6", "xv6-riscv")
label = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "linux"
SECS = int(sys.argv[sys.argv.index("--secs") + 1]) if "--secs" in sys.argv else 4
REPS = int(sys.argv[sys.argv.index("--reps") + 1]) if "--reps" in sys.argv else 3
OUT = os.path.join(ROOT, "results", label)
os.makedirs(OUT, exist_ok=True)

subprocess.run(["make", "-s", "CPUS=1", "kernel/kernel", "fs.img"], cwd=XV6, check=True)

qemu = subprocess.Popen(
    ["qemu-system-riscv64", "-machine", "virt", "-bios", "none", "-kernel", "kernel/kernel",
     "-m", "128M", "-smp", "1", "-nographic", "-global", "virtio-mmio.force-legacy=false",
     "-drive", "file=fs.img,if=none,format=raw,id=x0",
     "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0"],
    cwd=XV6, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

buf = b""
def read_until(token, timeout):
    global buf
    end = time.time() + timeout
    while token.encode() not in buf:
        if time.time() > end:
            raise TimeoutError(f"waiting for {token!r}; got: {buf[-300:]!r}")
        r, _, _ = select.select([qemu.stdout], [], [], 0.5)
        if r:
            buf += os.read(qemu.stdout.fileno(), 4096)
    i = buf.index(token.encode()) + len(token)
    out, buf = buf[:i], buf[i:]
    return out.decode(errors="replace")

def cmd(line, timeout):
    qemu.stdin.write((line + "\n").encode())
    qemu.stdin.flush()
    out = read_until("DONE", timeout)
    read_until("$ ", 10)
    return out

read_until("$ ", 60)
tests = [
    ("xv6 round robin",            0, 0),
    ("MLFQ (tick charging)",       1, 0),
    ("MLFQ + boost",               1, 50),
    ("MLFQ + allotment",           3, 0),
    ("MLFQ + allotment + boost",   3, 50),
    ("MLFQ + allotment + precise", 7, 0),
    ("MLFQ + allotment + precise + fair", 15, 0),
]
rows = []
for rep in range(REPS):
  print(f"== repetition {rep + 1}/{REPS}")
  for name, flags, boost in tests:
    for pct in ([90] if flags != 1 or boost else [50, 80, 90, 95]):
        out = cmd(f"schedtest {flags} {boost} {SECS} {pct} 2", SECS * 3 + 30)
        for m in re.finditer(r"RESULT (.*)", out):
            d = dict(kv.split("=") for kv in m.group(1).split())
            d["test"] = name
            d["rep"] = rep
            rows.append(d)
        a = rows[-1]
        print(f"{name:34s} attack {pct}%: attacker real CPU {int(a['true_pm'])/10:5.1f}%  "
              f"charged by ticks {int(a['ticks_pm'])/10:5.1f}%  level Q{int(a['level'])+1}")
# baseline without attacker
out = cmd(f"schedtest 1 0 {SECS} 0 2", SECS * 3 + 30)
for m in re.finditer(r"RESULT (.*)", out):
    d = dict(kv.split("=") for kv in m.group(1).split()); d["test"] = "MLFQ, no attacker"; rows.append(d)

qemu.stdin.write(b"\x01x")   # ctrl-a x quits qemu
qemu.stdin.flush()
try:
    qemu.wait(5)
except Exception:
    qemu.kill()

keys = ["rep", "test", "flags", "boost", "pct", "role", "true_us", "ticks", "level", "sched", "true_pm", "ticks_pm"]
with open(os.path.join(OUT, "xv6.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=keys)
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in keys})
print("saved", os.path.join(OUT, "xv6.csv"))
