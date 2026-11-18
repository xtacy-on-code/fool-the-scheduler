#!/usr/bin/env python3
# figures + numbers.json from results/<label>/   usage: analyze.py label [label2 ...]
import csv, json, os, statistics as st, sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
labels = [a for a in sys.argv[1:]] or ["sandbox-vm"]
MAIN = labels[0]
RES = os.path.join(ROOT, "results", MAIN)
FIG = os.path.join(RES, "figs")
os.makedirs(FIG, exist_ok=True)

plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
                     "figure.dpi": 150, "savefig.bbox": "tight"})
C_BAD, C_OK, C_NEU, C_ACC = "#c0392b", "#2e8b57", "#7f8c8d", "#2c6fbb"

POLICIES = ["RR", "MLFQ", "MLFQ+boost", "MLFQ+acct", "MLFQ+both", "MLFQ+groups", "Linux"]

def load(label):
    path = os.path.join(ROOT, "results", label, "shares.csv")
    rows = list(csv.DictReader(open(path)))
    d = defaultdict(list)
    for r in rows:
        d[(r["exp"], r["config"], r["group"])].append(float(r["share"]))
    return rows, d

rows, D = load(MAIN)
numbers = {"label": MAIN}

def mean(exp, cfg, grp, d=D):
    v = d.get((exp, cfg, grp))
    return (st.mean(v), st.pstdev(v)) if v else (None, None)

# 1. slide 13
def fig_slide13():
    ev = os.path.join(RES, "runs", "slide13_MLFQ_0_events.csv")
    if not os.path.exists(ev):
        return
    real = list(csv.DictReader(open(ev)))
    expected = [("P1", 0, 80, 0), ("P1", 80, 240, 1), ("P1", 240, 400, 2), ("P2", 400, 480, 0),
                ("P2", 480, 520, 1), ("P1", 520, 1120, 2)]
    fig, ax = plt.subplots(figsize=(8, 2.2))
    colors = {"P1": "#2c6fbb", "P2": "#e67e22"}
    for name, s, e, lv in expected:
        ax.barh(1, e - s, left=s, color=colors[name], edgecolor="white")
        ax.text((s + e) / 2, 1, f"{name}\nQ{lv+1}", ha="center", va="center", fontsize=7, color="white")
    for r in real:
        s, e = float(r["t_start"]), float(r["t_end"])
        ax.barh(0, e - s, left=s, color=colors[r["name"]], edgecolor="white")
        ax.text((s + e) / 2, 0, f"{r['name']}\nQ{int(r['level'])+1}", ha="center", va="center", fontsize=7, color="white")
    ax.set_yticks([0, 1], ["measured\n(real processes)", "slide 13\n(theory)"])
    ax.set_xlabel("time (ms)   [1 slide unit = 10 ms]")
    ax.set_title("Sanity check: the lecture's MLFQ example, run on real Linux processes")
    fig.savefig(os.path.join(FIG, "slide13.png"))
    plt.close(fig)
    p2_end = max(float(r["t_end"]) for r in real if r["name"] == "P2")
    p1_end = max(float(r["t_end"]) for r in real if r["name"] == "P1")
    numbers["slide13"] = {"p2_finish_ms": round(p2_end, 1), "p1_finish_ms": round(p1_end, 1),
                          "p2_expected": 520, "p1_expected": 1120}

# 2. bars per policy
def bars(exp, grp, fair, title, fname, ylabel):
    vals = [(p, *mean(exp, p, grp)) for p in POLICIES if mean(exp, p, grp)[0] is not None]
    if not vals:
        return
    fig, ax = plt.subplots(figsize=(9, 3.2))
    names = [v[0] for v in vals]
    m = [v[1] for v in vals]
    sd = [v[2] for v in vals]
    def fair_for(p):   # with per-user accounting, fairness is per USER (2 users -> 50%)
        return 50.0 if (p.endswith("+groups") or p.endswith("+sessions")) and exp in ("iotrick", "flood") else fair
    col = [C_BAD if (x > fair_for(p) * 1.25 if grp in ("attacker", "army") else x < fair_for(p) * 0.75) else C_OK
           for p, x in zip(names, m)]
    ax.bar(names, m, yerr=sd, color=col, capsize=3)
    ax.axhline(fair, color="black", ls="--", lw=1)
    ax.text(len(names) - 0.5, fair + 1.5, f"fair share {fair:.0f}%", ha="right", fontsize=8)
    for i, x in enumerate(m):
        ax.text(i, x + 2, f"{x:.0f}", ha="center", fontsize=8)
    ax.set_ylabel(ylabel)
    ax.set_ylim(0, 105)
    ax.set_title(title)
    plt.xticks(rotation=30, ha="right")
    fig.savefig(os.path.join(FIG, fname))
    plt.close(fig)
    numbers[f"{exp}_{grp}"] = {n: round(x, 2) for n, x in zip(names, m)}

# 3. I/O trick model
def fig_iosweep():
    rs = [1, 2, 4, 6, 7, 7.5]
    raw = [D.get(("iosweep", f"r={r}", "attacker")) for r in rs]
    if None in raw:
        return
    meas = [st.median(v) for v in raw]          # median: one VM hiccup can demote the attacker (see report)
    model = [100 * r / (r + 1) for r in rs]
    fig, ax = plt.subplots(figsize=(5.5, 3.2))
    ax.plot(rs, model, "o--", color=C_NEU, label="formula  r / (r + b)")
    ax.plot(rs, meas, "o-", color=C_BAD, label="measured on real processes (median of runs)")
    ax.axhline(100 / 3, color="black", ls=":", lw=1)
    ax.text(1, 100 / 3 + 1.5, "fair share 33%", fontsize=8)
    ax.set_xlabel("r = ms the attacker computes before each 1 ms 'I/O'  (time slice 8 ms)")
    ax.set_ylabel("attacker's CPU share (%)")
    ax.set_title("The slide-17 trick: theory vs reality")
    ax.legend(fontsize=8)
    fig.savefig(os.path.join(FIG, "iosweep.png"))
    plt.close(fig)
    numbers["iosweep"] = {"r": rs, "measured": [round(x, 2) for x in meas], "model": [round(x, 2) for x in model],
                          "all_runs": raw}

# 4. boost period
def interactive_response(exp, cfg):
    vals = []
    for r in rows:
        if r["exp"] == exp and r["config"] == cfg and r["group"] == "interactive":
            for s in csv.DictReader(open(r["summary"] if os.path.isabs(r["summary"]) else os.path.join(ROOT, r["summary"]))):
                if s["name"].startswith("interactive") and float(s["resp_avg"]) >= 0:
                    vals.append(float(s["resp_avg"]))
    return st.mean(vals) if vals else None

def fig_boost():
    Ss = [25, 50, 100, 200, 500, 1000]
    share = [mean("boostsweep", f"S={s}", "cpujob")[0] for s in Ss]
    if None in share:
        return
    resp = [interactive_response("boostsweep", f"S={s}") for s in Ss]
    fig, ax = plt.subplots(1, 2, figsize=(9, 3))
    ax[0].plot(Ss, share, "o-", color=C_ACC)
    ax[0].set_xscale("log"); ax[0].set_xlabel("boost period S (ms)"); ax[0].set_ylabel("CPU-bound job's share (%)")
    ax[0].set_title("Less starvation with frequent boosts")
    ax[0].axhline(20, color="black", ls=":", lw=1); ax[0].text(25, 21, "fair share 20%", fontsize=8)
    ax[1].plot(Ss, resp, "o-", color=C_BAD)
    ax[1].set_xscale("log"); ax[1].set_xlabel("boost period S (ms)"); ax[1].set_ylabel("interactive response time (ms)")
    ax[1].set_title("...but interactive jobs wait longer")
    fig.suptitle("Choosing slide 18's boost period S is a trade-off", y=1.02)
    fig.savefig(os.path.join(FIG, "boost.png"))
    plt.close(fig)
    numbers["boost"] = {"S": Ss, "cpujob_share": [round(x, 2) for x in share],
                        "interactive_resp_ms": [round(x, 3) if x else None for x in resp]}
    numbers["flood_resp"] = {p: interactive_response("flood", p) for p in POLICIES}

# 5. the matrix
ATTACKS = [
    ("I/O trick (slide 17)", "iotrick", "honest", 200 / 3),
    ("Flood (slide 16)", "flood", "cpujob", 20.0),
    ("Process army", "army", "victim", 50.0),
    ("Army stream", "stream", "victim", 50.0),
]
def fig_matrix():
    M = np.full((len(ATTACKS), len(POLICIES)), np.nan)
    for i, (_, exp, grp, fair) in enumerate(ATTACKS):
        for j, p in enumerate(POLICIES):
            m = mean(exp, p, grp)[0]
            per_user = p.endswith("+groups") or p.endswith("+sessions")
            f = 50.0 if (per_user and exp in ("iotrick", "flood")) else fair   # fairness per user in those columns
            if m is not None:
                M[i, j] = m / f
    fig, ax = plt.subplots(figsize=(11, 3.3))
    cmap = matplotlib.colors.LinearSegmentedColormap.from_list("rg", [C_BAD, "#f1c40f", C_OK])
    im = ax.imshow(np.clip(M, 0, 1.2), cmap=cmap, vmin=0, vmax=1.0, aspect="auto")
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            if not np.isnan(M[i, j]):
                ax.text(j, i, "100%+" if M[i, j] >= 1.0 else f"{M[i,j]*100:.0f}%", ha="center", va="center", fontsize=8,
                        color="white" if M[i, j] < 0.45 else "black")
    ax.set_xticks(range(len(POLICIES)), POLICIES, rotation=30, ha="right")
    ax.set_yticks(range(len(ATTACKS)), [a[0] for a in ATTACKS])
    ax.set_title("How much of its fair share does the VICTIM still get?  (100% = attack failed, ~0% = victim starved)")
    cb = fig.colorbar(im, ax=ax, fraction=0.02)
    cb.set_ticks([0, 0.5, 1.0], labels=["0%", "50%", "100%+"])
    fig.savefig(os.path.join(FIG, "matrix.png"))
    plt.close(fig)
    numbers["matrix"] = {ATTACKS[i][0]: {POLICIES[j]: (None if np.isnan(M[i, j]) else round(M[i, j] * 100, 1))
                                          for j in range(len(POLICIES))} for i in range(len(ATTACKS))}

# 6. xv6
def fig_xv6():
    path = os.path.join(RES, "xv6.csv")
    if not os.path.exists(path):
        return
    xs = list(csv.DictReader(open(path)))
    order = ["xv6 round robin", "MLFQ (tick charging)", "MLFQ + boost", "MLFQ + allotment",
             "MLFQ + allotment + boost", "MLFQ + allotment + precise",
             "MLFQ + allotment + precise + fair"]
    real, charged, names = [], [], []
    xv6_spread = {}
    for t in order:
        a = [r for r in xs if r["test"] == t and r["role"] == "attacker" and r["pct"] == "90"]
        if a:
            names.append(t)
            real.append(st.mean(int(r["true_pm"]) / 10 for r in a))
            charged.append(st.mean(int(r["ticks_pm"]) / 10 for r in a))
            xv6_spread[t] = [int(r["true_pm"]) / 10 for r in a]
    x = np.arange(len(names))
    fig, ax = plt.subplots(figsize=(9, 3.3))
    ax.bar(x - 0.2, real, 0.4, color=C_BAD, label="CPU it really used (time register)")
    ax.bar(x + 0.2, charged, 0.4, color=C_NEU, label="CPU the kernel charged it (tick sampling)")
    ax.axhline(100 / 3, color="black", ls="--", lw=1); ax.text(-0.45, 35, "fair share 33%", fontsize=8)
    for i, v in enumerate(real):
        ax.text(i - 0.2, v + 1.5, f"{v:.0f}", ha="center", fontsize=8)
    ax.set_xticks(x, [n.replace(" + ", "\n+ ").replace(" (", "\n(").replace("xv6 round robin", "xv6 round\nrobin") for n in names], fontsize=8)
    ax.set_ylabel("attacker's share of CPU (%)"); ax.set_ylim(0, 105)
    ax.set_title("xv6: the tick-dodging attacker (computes 90% of every tick) vs 2 honest processes (mean of runs)")
    ax.legend(fontsize=8, loc="upper left", bbox_to_anchor=(1.0, 1.0))
    fig.savefig(os.path.join(FIG, "xv6.png"))
    plt.close(fig)
    sweep = defaultdict(list)
    for r in xs:
        if r["test"] == "MLFQ (tick charging)" and r["role"] == "attacker":
            sweep[r["pct"]].append(int(r["true_pm"]) / 10)
    honest_fair = [[int(r["true_pm"]) / 10 for r in xs if r["test"] == t and r["role"] == "honest"] for t in names]
    numbers["xv6"] = {"tests": dict(zip(names, [round(x, 1) for x in real])),
                      "charged": dict(zip(names, [round(x, 1) for x in charged])),
                      "spread": xv6_spread, "naive_sweep": dict(sweep),
                      "honest": dict(zip(names, honest_fair))}

# 7. Windows
def fig_windows():
    path = os.path.join(ROOT, "results", "windows", "wintest_results.csv")
    if not os.path.exists(path):
        return
    lines = [l for l in open(path) if not l.startswith("#")]
    head = [l for l in open(path) if l.startswith("#")]
    ws = list(csv.DictReader(lines))
    numbers["windows"] = {"header": head[0].strip("# \n") if head else "", "rows": ws}
    tests = []
    for r in ws:
        if r["group"] in ("attacker", "army", "dodger") and r["test"] not in tests and "alone" not in r["test"]:
            tests.append(r["test"])
    real = [float([r for r in ws if r["test"] == t and r["group"] in ("attacker", "army", "dodger")][0]["real_share"]) for t in tests]
    rep = [float([r for r in ws if r["test"] == t and r["group"] in ("attacker", "army", "dodger")][0]["reported_share"]) for t in tests]
    x = np.arange(len(tests))
    fig, ax = plt.subplots(figsize=(10, 3.4))
    ax.bar(x - 0.2, real, 0.4, color=C_BAD, label="real CPU share (cycles)")
    ax.bar(x + 0.2, rep, 0.4, color=C_NEU, label="reported CPU share (GetProcessTimes / Task Manager)")
    ax.axhline(50, color="black", ls="--", lw=1)
    ax.set_xticks(x, tests, rotation=35, ha="right"); ax.set_ylabel("attacker's share (%)"); ax.set_ylim(0, 105)
    ax.set_title("Windows: the same attacks (fair share 50%, army fair share per user 50%)")
    ax.legend(fontsize=8)
    fig.savefig(os.path.join(FIG, "windows.png"))
    plt.close(fig)

# 8. machines compared
def fig_envs():
    if len(labels) < 2:
        return
    cases = [("iotrick", "MLFQ", "attacker"), ("iotrick", "Linux", "attacker"), ("army", "Linux", "army"),
             ("army", "Linux+sessions", "army"), ("stream", "Linux", "army"), ("flood", "Linux", "cpujob")]
    fig, ax = plt.subplots(figsize=(9, 3.2))
    w = 0.8 / len(labels)
    for k, lab in enumerate(labels):
        _, d = load(lab)
        vals = [mean(e, c, g, d)[0] or 0 for e, c, g in cases]
        ax.bar(np.arange(len(cases)) + k * w, vals, w, label=lab)
    ax.set_xticks(np.arange(len(cases)) + w * (len(labels) - 1) / 2, [f"{e}\n{c}\n({g})" for e, c, g in cases], fontsize=8)
    ax.set_ylabel("CPU share (%)"); ax.legend(fontsize=8)
    ax.set_title("Same experiments on different machines / environments")
    fig.savefig(os.path.join(FIG, "environments.png"))
    plt.close(fig)

fig_slide13()
bars("iotrick", "attacker", 100 / 3, "I/O trick: attacker (7 ms of CPU, then 1 ms 'I/O') vs 2 honest CPU-bound jobs",
     "iotrick.png", "attacker's CPU share (%)")
fig_iosweep()
bars("flood", "cpujob", 20, "Flood: CPU-bound job vs 4 interactive jobs (each wants 25% of the CPU)",
     "flood.png", "CPU-bound job's share (%)")
fig_boost()
bars("army", "army", 50, "Process army: 4 processes of one user vs 1 process of another", "army.png", "army's CPU share (%)")
bars("stream", "army", 50, "Army stream: a fresh 6 ms process every 8 ms vs 1 long job", "stream.png", "army's CPU share (%)")
fig_matrix()
numbers["army_sessions"] = mean("army", "Linux+sessions", "army")[0]
fig_xv6()
fig_windows()
fig_envs()
json.dump(numbers, open(os.path.join(RES, "numbers.json"), "w"), indent=1, default=str)
print("figures in", FIG)
