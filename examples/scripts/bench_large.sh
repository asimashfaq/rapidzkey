#!/bin/bash
# ============================================================================
# bench_large.sh — Benchmark zk-setup on a large circuit
# Usage: ./bench_large.sh <r1cs_path> <ptau_path>
# ============================================================================
set -e

R1CS="${1:?Usage: bench_large.sh <r1cs> <ptau>}"
PTAU="${2:?Usage: bench_large.sh <r1cs> <ptau>}"
OUT="/tmp/bench_$(date +%s).zkey"
BIN="$(cd "$(dirname "$0")/../.." && pwd)/target/release/zk-setup"

if [ ! -f "$BIN" ]; then
  echo "Building zk-setup..."
  cd "$(dirname "$0")/../.."
  cargo build --release
fi

echo "============================================"
echo "  zk-setup Benchmark"
echo "============================================"
echo "R1CS: $R1CS"
echo "PTAU: $PTAU"
echo ""

# System info
echo "System: $(uname -m) $(sysctl -n machdep.cpu.brand_string 2>/dev/null || cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1 | cut -d: -f2)"
echo "Cores: $(nproc 2>/dev/null || sysctl -n hw.ncpu)"
echo "RAM: $(sysctl -n hw.memsize 2>/dev/null | awk '{print $1/1073741824, "GB"}' || free -h 2>/dev/null | awk '/Mem:/{print $2}')"
echo ""

echo "Running zk-setup..."
time "$BIN" --r1cs "$R1CS" --ptau "$PTAU" --out "$OUT" 2>&1

echo ""
echo "Output: $OUT ($(du -h "$OUT" | cut -f1))"

# Verify with snarkjs if available
if command -v npx &>/dev/null; then
  echo ""
  echo "Verifying with snarkjs..."
  VK=$(npx snarkjs zkey export verificationkey "$OUT" /tmp/vk_bench.json 2>/dev/null && echo "OK" || echo "FAIL")
  echo "VK export: $VK"
fi

rm -f "$OUT"
