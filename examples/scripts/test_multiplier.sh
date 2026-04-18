#!/bin/bash
# ============================================================================
# test_multiplier.sh — End-to-end test: compile → setup → prove → verify
# ============================================================================
set -e

DIR="$(cd "$(dirname "$0")/../multiplier" && pwd)"
cd "$DIR"

echo "=== 1. Compile circuit ==="
circom multiplier.circom --r1cs --wasm --sym -o . 2>&1 | tail -3

echo ""
echo "=== 2. Download ptau ==="
if [ ! -f pot10.ptau ]; then
  curl -sL https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_10.ptau -o pot10.ptau
fi
echo "pot10.ptau ready ($(du -h pot10.ptau | cut -f1))"

echo ""
echo "=== 3. Generate zkey (zk-setup) ==="
time ../../target/release/zk-setup --r1cs multiplier.r1cs --ptau pot10.ptau --out multiplier_0000.zkey

echo ""
echo "=== 4. Generate reference zkey (snarkjs) ==="
time npx snarkjs groth16 setup multiplier.r1cs pot10.ptau multiplier_snarkjs_0000.zkey

echo ""
echo "=== 5. Byte-level comparison ==="
python3 -c "
import struct
def read_sections(path):
    sections = {}
    with open(path, 'rb') as f:
        f.read(12)
        while True:
            try:
                sid = struct.unpack('<I', f.read(4))[0]
                size = struct.unpack('<Q', f.read(8))[0]
                if size > 1e12: break
                sections[sid] = f.read(size)
            except: break
    return sections
ref_s = read_sections('multiplier_snarkjs_0000.zkey')
rust_s = read_sections('multiplier_0000.zkey')
for sid in sorted(set(list(ref_s.keys()) + list(rust_s.keys()))):
    r, m = ref_s.get(sid, b''), rust_s.get(sid, b'')
    print(f'  Section {sid:2d}: {\"MATCH\" if r == m else \"DIFF\"} ({len(r)} bytes)')
"

echo ""
echo "=== 6. Prove & Verify ==="
node -e "
const s = require('snarkjs');
(async () => {
  const r = await s.groth16.fullProve({a:'3',b:'11'}, 'multiplier_js/multiplier.wasm', 'multiplier_0000.zkey');
  const vk = await s.zKey.exportVerificationKey('multiplier_0000.zkey');
  const ok = await s.groth16.verify(vk, r.publicSignals, r.proof);
  console.log('  Proof valid:', ok);
  console.log('  Signals:', r.publicSignals, '(c=33, a=3)');
})();
"
