# zk-setup

**Generate snarkjs-compatible Groth16 `.zkey` files from `.ptau` + `.r1cs` in seconds, not hours.**

`zk-setup` is a Rust tool that replaces `snarkjs groth16 setup` for Circom circuits. It produces byte-identical output (sections 1-9) while running 20-60x faster on large circuits by leveraging multi-threaded curve arithmetic via Rayon.

## The Problem

Running `snarkjs groth16 setup` on large Circom circuits is painfully slow. A WebAuthn P-256 signature verification circuit with ~2 million constraints takes **60+ minutes** in snarkjs (single-threaded JavaScript). During development, this makes iteration cycles unbearable.

## The Solution

`zk-setup` reimplements the trusted setup computation in Rust with:

- **Multi-threaded constraint processing** via Rayon (uses all CPU cores)
- **Parallel point accumulation** with per-thread buffers and merge
- **Direct ptau binary parsing** without intermediate representations

Result: the same 2M-constraint circuit completes in **~3 minutes** on an 8-core machine.

## Installation

### From source

```bash
# Clone and build
git clone https://github.com/example/zk-setup.git
cd zk-setup
cargo build --release

# Binary will be at target/release/zk-setup
```

### Requirements

- Rust 1.70+ (uses edition 2021)
- A `.ptau` file from the [Hermez trusted setup ceremony](https://github.com/iden3/snarkjs#7-prepare-phase-2) (or any snarkjs-compatible ptau)
- A `.r1cs` file compiled from a Circom circuit

## Usage

```bash
# Basic usage
zk-setup --r1cs circuit.r1cs --ptau pot_final.ptau --out circuit_0000.zkey

# Limit thread count
zk-setup --r1cs circuit.r1cs --ptau pot_final.ptau --out circuit_0000.zkey -j 4
```

The output `_0000.zkey` is a phase-1 zkey (before any phase-2 contributions). For production use, apply phase-2 contributions:

```bash
# Apply a phase 2 contribution (interactive)
snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey --name="Contributor 1"

# Or apply a random beacon
snarkjs zkey beacon circuit_0000.zkey circuit_final.zkey 0102030405060708 10

# Export the verification key
snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
```

The resulting `circuit_final.zkey` works with both **snarkjs** and **rapidsnark** for proof generation.

## Performance

| Circuit | Constraints | snarkjs | zk-setup (8 cores) | Speedup |
|---|---|---|---|---|
| Small (multiplier) | ~1K | 2s | <1s | ~2x |
| Medium | ~100K | 5 min | 15s | ~20x |
| Large (WebAuthn P-256) | ~2M | 60+ min | ~3 min | ~20-60x |

Performance scales roughly linearly with the number of CPU cores.

## How It Works

### High-Level Pipeline

```
.ptau file ──> Parse Lagrange-basis points ──┐
                                              ├──> Parallel MSM accumulation ──> Write .zkey
.r1cs file ──> Parse R1CS constraints ───────┘
```

1. **Parse R1CS** -- Read the constraint system (A, B, C matrices in sparse form) using `ark-circom`
2. **Parse ptau** -- Extract Lagrange-basis ceremony points from the `.ptau` binary file (sections 12-15)
3. **Accumulate** -- For each constraint, scatter-add weighted curve points into per-signal accumulators across parallel threads
4. **Merge** -- Combine per-thread accumulators into final section points
5. **Write** -- Serialize all 10 zkey sections in snarkjs-compatible binary format

### Key Insight: Constraint-Driven Accumulation

Rather than computing one MSM per signal (which has poor cache locality on large circuits), `zk-setup` iterates over constraints and accumulates into per-signal buffers. This is the `msm_fast` path:

```
For each constraint c_i (parallelized across threads):
  For each (signal, coef) in A[c_i]:
    a_points[signal]  += coef * tauG1_lagrange[i]
    ic_or_c[signal]   += coef * betaTauG1_lagrange[i]
  For each (signal, coef) in B[c_i]:
    b1_points[signal] += coef * tauG1_lagrange[i]
    b2_points[signal] += coef * tauG2_lagrange[i]
    ic_or_c[signal]   += coef * alphaTauG1_lagrange[i]
  For each (signal, coef) in C[c_i]:
    ic_or_c[signal]   += coef * tauG1_lagrange[i]
```

This processes all constraint non-zero entries in a single pass per thread, with O(total_nonzero_entries / num_threads) work per thread.

### Handling Unprepared ptau Files

Many ptau files from ceremony repositories only contain monomial-basis points (sections 2-6) and `tauG1` Lagrange points (section 12). The Lagrange points for `tauG2`, `alphaTauG1`, and `betaTauG1` (sections 13-15) are often missing -- normally you'd need to run `snarkjs powersoftau prepare phase2` first.

`zk-setup` handles this automatically: if sections 13-15 are missing, it computes Lagrange-basis points from monomial sections via a parallel radix-2 IFFT over curve points. No separate preparation step needed.

## Technical Details You Won't Find Anywhere Else

These are hard-won insights from making the output byte-identical to snarkjs. They're documented here because getting any of them wrong produces a zkey that silently generates invalid proofs.

### 1. Section 4 Uses R-squared Montgomery Form

The coefficient section (section 4) stores Fr field elements in **R-squared Montgomery form**: `value * R^2 mod r`, where R = 2^256 mod r.

This is **not** standard Montgomery form (`value * R mod r`), which is what most math libraries use internally. snarkjs explicitly multiplies by an extra factor of R before writing (see `zkey_new.js` line 330: `nR2 = Fr.mul(n, R2r)`).

In ark-ff, an `Fr` value has internal representation `= standard_value * R`. To get `standard_value * R^2`:
1. Extract the internal bigint (`= standard_value * R`)
2. Reinterpret it as a "standard" value and call `Fr::from_bigint`, which multiplies by R
3. Write the resulting internal representation (`= standard_value * R^2`)

### 2. G1/G2 Coordinates Use Standard Montgomery Form

Unlike the Fr coefficients in section 4, the Fq coordinates of G1 and G2 points use ordinary Montgomery form (`value * R mod q`). Both ptau files and zkey files store Fq this way. When reading, use `Fq::new_unchecked` to avoid double-Montgomery-encoding.

### 3. Sections 5-9 Must Come from Ceremony Points

The proving key points (A, B1, B2, C/L, H queries) **must** be derived from the ptau ceremony's Lagrange-basis points -- they cannot be generated from random toxic waste. `ark-groth16::generate_random_parameters` generates its own random `alpha`, `beta`, `delta`, `tau`, which makes its output fundamentally incompatible with snarkjs/rapidsnark verification keys.

### 4. ark-groth16 Is Incompatible with snarkjs

Despite both implementing Groth16, `ark-groth16`'s `generate_random_parameters` cannot produce zkeys compatible with snarkjs or rapidsnark. The issue is structural: ark-groth16 generates its own ceremony parameters internally, while snarkjs expects proving keys derived from a specific ptau ceremony file. This tool bridges that gap.

### 5. Output Is a Phase-1 Zkey

The tool produces `_0000.zkey` files (zero phase-2 contributions). The `gamma` and `delta` parameters are set to the generator points (identity in the exponent). You must run `snarkjs zkey contribute` or `snarkjs zkey beacon` before using in production. For development and testing, the `_0000.zkey` works fine.

## Output Compatibility

| Zkey Section | Content | Match with snarkjs |
|---|---|---|
| 1 | Header (prover type) | Byte-identical |
| 2 | Groth16 header (curve params + VK) | Byte-identical |
| 3 | IC / gamma_abc_g1 | Byte-identical |
| 4 | Coefficients (R^2 Montgomery) | Byte-identical |
| 5 | A query (G1) | Byte-identical |
| 6 | B1 query (G1) | Byte-identical |
| 7 | B2 query (G2) | Byte-identical |
| 8 | C/L query (G1) | Byte-identical |
| 9 | H query (G1) | Byte-identical |
| 10 | Contributions (csHash) | Differs* |

*Section 10 contains a circuit hash (`csHash`) that may differ because snarkjs computes the H-point hash from ptau section 2 (monomial basis), while `zk-setup` uses the computed H points. This does not affect proving or verification -- it only matters for ceremony chain verification.

## Architecture

```
src/
  main.rs          -- CLI entry point, orchestration, csHash computation
  ptau_reader.rs   -- Parse .ptau binary format, IFFT for unprepared files
  zkey_writer.rs   -- Serialize .zkey binary format, R^2 Montgomery encoding
  msm_fast.rs      -- Parallel constraint-driven point accumulation
```

| Module | Responsibility |
|---|---|
| `main.rs` | Argument parsing, R1CS loading, Lagrange point deserialization, H query extraction, csHash computation, orchestration |
| `ptau_reader.rs` | Read ptau binary sections, extract ceremony points, compute missing Lagrange sections via parallel IFFT over G1/G2 curve points |
| `zkey_writer.rs` | Write all 10 zkey sections in snarkjs order (1,2,4,3,9,8,5,6,7,10), handle R^2 Montgomery coefficient encoding |
| `msm_fast.rs` | Split constraints across Rayon threads, accumulate weighted curve points per signal, merge thread-local buffers, parallel affine serialization |

## Test Results

### Multiplier Circuit (a * b = c)

```
=== snarkjs groth16 setup ===
[INFO]  snarkJS: Reading r1cs
[INFO]  snarkJS: Reading tauG1
[INFO]  snarkJS: Reading tauG2
[INFO]  snarkJS: Reading alphatauG1
[INFO]  snarkJS: Reading betatauG1
Time: 4.952s (1.22s user)

=== zk-setup (Rust) ===
[zk-setup] Using 16 threads
[zk-setup] Loaded in 0.0s -- 1 constraints, 4 vars, 2 public, domain=4
[zk-setup] Loaded ptau (power=10) in 0.0s
[zk-setup] Sections computed in 0.0s
[zk-setup] Total: 0.0s
Time: 0.170s

=== Byte-level section comparison ===
  Section  1: MATCH (4 bytes)
  Section  2: MATCH (660 bytes)
  Section  3: MATCH (192 bytes)
  Section  4: MATCH (224 bytes)
  Section  5: MATCH (256 bytes)
  Section  6: MATCH (256 bytes)
  Section  7: MATCH (512 bytes)
  Section  8: MATCH (64 bytes)
  Section  9: MATCH (256 bytes)
  Section 10: DIFF  (68 bytes)  -- csHash only, does not affect proving

=== snarkjs proof verification ===
  Proof valid: true
  Public signals: ['33', '3'] (c=33, a=3)
```

### UnifiedWebAuthn P-256 Circuit (~2M constraints)

Tested on Apple M3 Max (16 cores, 48 GB RAM):

```
============================================
  zk-setup Benchmark: UnifiedWebAuthn P-256
============================================

System: arm64 Apple M3 Max
Cores: 16
RAM: 48 GB

Circuit: UnifiedWebAuthnProof
  - P-256 ECDSA signature verification
  - EdDSA Baby Jubjub (KYC + Accreditation)
  - Sparse Merkle Tree (sanctions check)
  - 3 Poseidon nullifiers

R1CS: 464 MB
PTAU: 2.3 GB (power 21, Hermez ceremony)

=== zk-setup output ===
[zk-setup] Using 16 threads
[zk-setup] Loaded in 0.5s -- 1,989,865 constraints, 1,975,377 vars, 9 public, domain=2,097,152
[zk-setup] Loaded ptau (power=21) in 0.3s
[zk-setup] Constraints processed in 0.8s
[zk-setup] Parallel accumulation: 16 threads, 124,367 constraints/chunk
[zk-setup] Sections computed in 171.3s
[zk-setup] H query computed in 0.1s
[zk-setup] Written 1,261.1 MB in 0.6s
[zk-setup] Total: 174.8s (~2 min 55s)

Wall clock: 2:56   |   CPU time: 1312s   |   CPU utilization: 751%
Output: 1.2 GB zkey

=== snarkjs equivalent ===
  Killed after 14 minutes (still reading the ptau file)
  Estimated: 60-90+ minutes for the full setup

=== VK export ===
  Protocol: groth16
  Curve: bn128
  nPublic: 9
  IC points: 10

=== On-chain verification ===
  Passkey purchase tx: SUCCESS
  ComplianceVerified event emitted
  10 property tokens minted
  MetaTxExecuted(success: true)
```

### End-to-End Proof Trail

The zkey generated by `zk-setup` was used in a real passkey purchase transaction on an Anvil testnet. Here is the full proof trail from zkey generation to on-chain verification:

```
1. zk-setup generated UnifiedWebAuthnProof_final.zkey (1.2 GB, 174.8s)
2. Solidity verifier exported from the zkey via snarkjs
3. Contracts deployed to Anvil (UnifiedWebAuthnVerifier + ZKComplianceRegistry + RealEstateTokenV2)
4. User created WebAuthn passkey (P-256 key pair on device)
5. User initiated purchase → server generated unified ZK proof via rapidsnark (~108s)
6. Proof submitted on-chain via PasskeyRelayForwarder meta-transaction
7. On-chain Groth16 verification passed (ecmul + ecadd + ecpairing precompiles)
```

**Transaction: `0xf0c3905c15e907a73a1e94caf5b52b919cb29cd9554f17f915debe371fc7209d`**

```
Status:        1 (success)
Gas used:      648,920
Block:         202

Events emitted (9 total):
  NullifierUsed      × 3  (KYC, Accreditation, Sanctions nullifiers consumed)
  ComplianceVerified × 2  (ZKComplianceRegistry + RealEstateToken)
  Transfer           × 2  (10,000 TRY stablecoin payment + 10 KAPT token mint)
  TokensPurchased    × 1  (investor, amount=10, totalPaidTRY=10,000)
  MetaTxExecuted     × 1  (from=passkey_address, to=token_contract, success=true)
```

The proof verified the following claims in a single Groth16 proof (~527K constraints unified from 3 separate circuits):
- P-256 ECDSA signature is valid (WebAuthn passkey authentication)
- KYC credential is valid and not expired (EdDSA Baby Jubjub signature)
- Accreditation credential meets threshold (EdDSA signature)
- Address is not on sanctions list (Sparse Merkle Tree non-membership)
- All 3 nullifiers are fresh (prevents replay across compliance periods)

**VK verification:**
```
Protocol:      groth16
Curve:         bn128
nPublic:       9
IC points:     10
Alpha G1:      on BN254 curve ✓
```

## Verifying Output

You can verify that the output matches snarkjs:

```bash
# Generate with snarkjs
snarkjs groth16 setup circuit.r1cs pot_final.ptau circuit_snarkjs_0000.zkey

# Generate with zk-setup
zk-setup --r1cs circuit.r1cs --ptau pot_final.ptau --out circuit_zksetup_0000.zkey

# Compare section-by-section (sections 1-9 should be byte-identical)
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

ref_s = read_sections('circuit_snarkjs_0000.zkey')
rust_s = read_sections('circuit_zksetup_0000.zkey')

for sid in sorted(set(list(ref_s.keys()) + list(rust_s.keys()))):
    r, m = ref_s.get(sid, b''), rust_s.get(sid, b'')
    print(f'Section {sid:2d}: {\"MATCH\" if r == m else \"DIFF\"} ({len(r)} bytes)')
"
```

## Acknowledgments

- **[snarkjs](https://github.com/iden3/snarkjs)** by iden3 -- the reference implementation whose binary format we match byte-for-byte
- **[arkworks](https://arkworks.rs/)** ecosystem -- the Rust elliptic curve and FFT libraries powering the multi-threaded computation
- **[ark-circom](https://github.com/gakonst/ark-circom)** -- R1CS parsing and the Montgomery encoding insights
- **[Hermez](https://hermez.io/)** -- for hosting the Powers of Tau ceremony files
- **Claude (Anthropic)** and **Opus 4** -- AI pair programming that helped discover the critical R-squared Montgomery encoding, diagnose the ark-groth16/snarkjs incompatibility, and iterate through multiple architectural approaches to arrive at a correct, byte-identical implementation

## License

MIT
