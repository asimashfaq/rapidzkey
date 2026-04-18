# WebAuthn P-256 Example

This example demonstrates using `zk-setup` with a large, real-world circuit:
a **unified WebAuthn compliance proof** (~2M constraints) that verifies:

1. **P-256 ECDSA signature** (WebAuthn passkey authentication)
2. **KYC credential** (EdDSA Baby Jubjub signature + expiry check)
3. **Accreditation credential** (EdDSA signature + threshold check)
4. **Sanctions non-membership** (Sparse Merkle Tree proof)
5. **3 nullifiers** (prevents proof replay across compliance periods)

## Why This Matters

The P-256 ECDSA verification alone costs ~500K constraints. With 3 separate
circuits (KYC, Accreditation, Sanctions) each doing P-256, that's 1.5M
constraints total. The unified circuit does P-256 **once** and combines all
3 checks into ~527K constraints.

Running `snarkjs groth16 setup` on this circuit takes **60+ minutes**.
With `zk-setup`, it takes **~3 minutes** on an 8-core machine.

## Prerequisites

```bash
# Circuit compilation requires:
# - circom 2.1.5+ (for P-256 ECDSA templates)
# - circomlib (npm install circomlib)
# - circom-ecdsa-p256 library

# Download a power-21 ptau (for circuits up to 2M constraints)
# This is a 2.3GB file from the Hermez trusted setup ceremony
curl -L https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau -o pot21.ptau
```

## Usage

```bash
# 1. Compile your circuit (produces .r1cs + .wasm)
circom UnifiedWebAuthnProof.circom --r1cs --wasm --sym -o build/

# 2. Generate the phase-1 zkey with zk-setup (~3 min vs 60+ min with snarkjs)
zk-setup --r1cs build/UnifiedWebAuthnProof.r1cs \
         --ptau pot21.ptau \
         --out build/UnifiedWebAuthnProof_0000.zkey

# 3. Apply phase-2 contribution (required for production)
snarkjs zkey beacon \
    build/UnifiedWebAuthnProof_0000.zkey \
    build/UnifiedWebAuthnProof_final.zkey \
    0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10

# 4. Export the Solidity verifier
snarkjs zkey export solidityverifier \
    build/UnifiedWebAuthnProof_final.zkey \
    UnifiedWebAuthnVerifier.sol

# 5. Export the verification key (for off-chain verification)
snarkjs zkey export verificationkey \
    build/UnifiedWebAuthnProof_final.zkey \
    verification_key.json
```

## Proof Generation

The resulting zkey works with both **snarkjs** (browser/Node.js) and
**rapidsnark** (native, ~3x faster):

```bash
# With snarkjs (Node.js)
snarkjs groth16 fullprove input.json \
    build/UnifiedWebAuthnProof_js/UnifiedWebAuthnProof.wasm \
    build/UnifiedWebAuthnProof_final.zkey \
    proof.json public.json

# With rapidsnark (native, recommended for server-side)
# First generate the witness
node build/UnifiedWebAuthnProof_js/generate_witness.js \
    build/UnifiedWebAuthnProof_js/UnifiedWebAuthnProof.wasm \
    input.json witness.wtns

# Then generate the proof
rapidsnark build/UnifiedWebAuthnProof_final.zkey \
    witness.wtns proof.json public.json
```

## Benchmark Results

Tested on Apple M3 Max (16 cores, 48 GB RAM):

```
Circuit: UnifiedWebAuthnProof
  Constraints: 1,989,865
  Variables:   1,975,377
  Public:      9 signals
  Domain:      2,097,152

zk-setup:  2 min 55s  (16 threads, 751% CPU utilization)
snarkjs:   60+ min    (killed after 14 min, still reading ptau)

Output:    1.2 GB zkey
Speedup:   ~20-60x
```

## On-Chain Verification

The zkey produced by `zk-setup` has been verified end-to-end:

1. Proof generated with rapidsnark (~108s)
2. Submitted via ERC-2771 meta-transaction (passkey relay)
3. On-chain Groth16 verification passed (ecpairing precompile)
4. Gas used: 648,920
5. Events: 3 nullifiers consumed, compliance verified, tokens minted

The on-chain verifier uses BN254 precompiles (`ecadd`, `ecmul`, `ecpairing`)
available on Ethereum, Polygon, BSC, and all EVM-compatible chains.
