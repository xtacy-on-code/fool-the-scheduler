#!/bin/sh
# Run everything on this machine:  sh scripts/run_all.sh <machine-name>
# e.g.  sh scripts/run_all.sh ubuntu-native    (about 20 minutes, keep the laptop idle and plugged in)
set -e
NAME=${1:-$(hostname)}
cd "$(dirname "$0")/.."
make -s
python3 scripts/run_linux.py "$NAME"
if command -v qemu-system-riscv64 >/dev/null && command -v riscv64-linux-gnu-gcc >/dev/null; then
  python3 scripts/run_xv6.py "$NAME"
else
  echo "skipping xv6: sudo apt install qemu-system-misc gcc-riscv64-linux-gnu"
fi
python3 scripts/analyze.py "$NAME"
tar czf "results-$NAME.tgz" "results/$NAME"
echo "Done. Send back results-$NAME.tgz"
