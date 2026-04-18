# Examples

## Quick Test (Multiplier Circuit)

```bash
# 1. Install circom
curl -Ls https://github.com/iden3/circom/releases/latest/download/circom-linux-amd64 -o /usr/local/bin/circom
chmod +x /usr/local/bin/circom

# 2. Create a simple circuit
cat > multiplier.circom << 'CIRCOM'
pragma circom 2.0.0;

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}

component main {public [a]} = Multiplier();
CIRCOM

# 3. Compile
circom multiplier.circom --r1cs --wasm --sym -o .

# 4. Download Powers of Tau (small, for testing)
curl -sL https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_10.ptau -o pot10.ptau

# 5. Generate zkey with zk-setup
zk-setup --r1cs multiplier.r1cs --ptau pot10.ptau --out multiplier_0000.zkey

# 6. (Optional) Add phase-2 contribution
npx snarkjs zkey contribute multiplier_0000.zkey multiplier_final.zkey --name="test" -e="random-entropy"

# 7. Verify it works — generate and verify a proof
node -e "
const snarkjs = require('snarkjs');
(async () => {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    { a: '3', b: '11' },
    'multiplier_js/multiplier.wasm',
    'multiplier_0000.zkey'  // or multiplier_final.zkey
  );
  const vk = await snarkjs.zKey.exportVerificationKey('multiplier_0000.zkey');
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  console.log('Proof valid:', ok);         // true
  console.log('Public signals:', publicSignals); // ['33', '3']  (c=33, a=3)
})();
"
```

## Byte-Identical Verification

Compare zk-setup output against snarkjs to confirm correctness:

```bash
# Generate with snarkjs
npx snarkjs groth16 setup multiplier.r1cs pot10.ptau ref_0000.zkey

# Generate with zk-setup  
zk-setup --r1cs multiplier.r1cs --ptau pot10.ptau --out rust_0000.zkey

# Compare section-by-section
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

ref_s = read_sections('ref_0000.zkey')
rust_s = read_sections('rust_0000.zkey')

for sid in sorted(set(list(ref_s.keys()) + list(rust_s.keys()))):
    r, m = ref_s.get(sid, b''), rust_s.get(sid, b'')
    print(f'Section {sid:2d}: {\"MATCH\" if r == m else \"DIFF\"} ({len(r)} bytes)')
"
```

## Large Circuit (WebAuthn P-256 ECDSA)

See [`webauthn/README.md`](webauthn/README.md) for a complete guide on using
`zk-setup` with a ~2M constraint unified WebAuthn compliance circuit,
including benchmarks and on-chain verification results.

```bash
# Download a power-21 ptau (for circuits up to 2M constraints)
curl -L https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau -o pot21.ptau

# Generate zkey (~3 minutes on 8-core machine vs 60+ with snarkjs)
zk-setup --r1cs UnifiedWebAuthnProof.r1cs --ptau pot21.ptau --out UnifiedWebAuthnProof_0000.zkey
```
