# Debugging Journey: From Invalid Proofs to Byte-Identical Output

> How we discovered the R² Montgomery encoding, proved ark-groth16 is incompatible with snarkjs, and built a working zkey generator through 8 failed attempts.

This document chronicles the sequence of failures, wrong hypotheses, and discoveries that led to [rapidzkey](.). Each attempt produced a plausible theory that turned out to be wrong (or only partially right), requiring deeper investigation. If you're building tools that interact with the snarkjs/circom ecosystem, these lessons may save you weeks of debugging.

---

## Timeline

| Attempt | Hypothesis | Result | Real Issue |
|---------|-----------|--------|------------|
| 1 | Use ark-groth16 random setup | Proofs fail on-chain | Random tau ≠ ceremony tau |
| 2 | `transmute` corrupts IC points | Points actually fine | Random tau (same root cause) |
| 3 | H query has wrong size | Fixed one error | Still wrong tau |
| 4 | CircomReduction vs LibsnarkReduction | No effect | Red herring — tau source matters, not QAP variant |
| 5 | Fr coefs use wrong Montgomery form | Found R² encoding! | Partial fix — coefs correct but points still wrong |
| 6 | Rewrite: derive from ptau directly | Byte-identical on test circuit! | **Correct approach** |
| 7 | Large circuit ptau missing sections | Added IFFT over curve points | Infrastructure fix |
| 8 | Per-signal MSMs too slow | Constraint-driven accumulation | Performance fix |

---

### Attempt 1: ark-groth16 Random Setup

**Approach**: Use `ark_groth16::generate_random_parameters` to create a zkey, then serialize it in snarkjs format.

**Result**: Proofs generated with ark-circom verified in Rust but failed on-chain (Solidity verifier).

**Root cause**: ark-groth16 generates its own random $(\tau, \alpha, \beta, \gamma, \delta)$. The snarkjs prover expects the specific $\tau$ from the ptau ceremony. See [Section 5](#5-why-ark-groth16-is-incompatible).

### Attempt 2: Fixing IC Points

**Symptom**: IC points were reported as "off the BN254 curve."

**Hypothesis**: `std::mem::transmute` was corrupting point data due to `PhantomData` in ark-ec point types.

**Investigation**: `PhantomData<T>` is a zero-sized type (ZST) in Rust, so it doesn't affect memory layout. The real issue was the random $\tau$.

### Attempt 3: H Query Size

**Symptom**: "Scalar size does not match" error during proof generation.

**Root cause**: H query had `domain_size - 1` points instead of `domain_size`. The prover expects exactly `domain_size` points.

**Fix**: Extract `domain_size` odd-indexed points from the doubled-domain Lagrange basis.

### Attempt 4: CircomReduction vs LibsnarkReduction

**Symptom**: Proofs still failed after fixing H query size.

**Hypothesis**: snarkjs uses a different proof element construction ("Circom reduction") than arkworks' default ("Libsnark reduction").

**Investigation**: Switched to CircomReduction. Proofs still failed. This was a red herring -- the real issue remained the random $\tau$.

### Attempt 5: Discovering R^2 Montgomery

**Symptom**: Section 4 byte comparison showed systematic differences from snarkjs output.

**Discovery**: snarkjs stores Fr coefficients as $v \cdot R^2 \mod r$, not $v \cdot R \mod r$.

**Evidence**: The coefficient "1" was stored as `R^2 mod r`, not `R mod r`. Cross-referenced with snarkjs source (`zkey_new.js` line 330) and ark-circom's double-decode pattern.

**Fix**: Implemented the `write_fr_r2` trick (extract Montgomery bigint, re-encode via `from_bigint`).

### Attempt 6: Reimplementation from Scratch

**Approach**: Abandoned ark-groth16 entirely. Read ptau directly, compute MSMs from Lagrange points exactly as snarkjs does.

**Result**: Byte-identical output on test circuit (multiplier with 1 constraint). Proofs verified in snarkjs and on-chain.

### Attempt 7: Large Circuit -- Missing Lagrange Sections

**Symptom**: ptau file for the 2M-constraint circuit lacked sections 13-15 (tauG2, alphaTauG1, betaTauG1 Lagrange points).

**Standard fix**: Run `snarkjs powersoftau prepare phase2` (single-threaded JS, takes hours for power-21 ptau).

**Our fix**: Implemented parallel radix-2 IFFT over G1/G2 projective points. Computes missing Lagrange sections in minutes instead of hours.

### Attempt 8: Performance Optimization

**Symptom**: Per-signal MSM approach was too slow for 2M-variable circuits (each MSM has Pippenger setup overhead).

**Fix**: Switched to constraint-driven scatter-accumulate algorithm (see [Section 7](#7-the-parallel-accumulation-algorithm)). Each thread processes a chunk of constraints, scattering weighted points into per-signal accumulators.

### Final Result

- **3 minutes** for 2M constraints on 8 cores (vs 60+ minutes with snarkjs)
- **Byte-identical** output for sections 1-9
- **On-chain verified**: passkey purchase transaction succeeded with the generated zkey
- Section 10 (csHash) differs due to H-point hashing methodology, but this does not affect proving or verification

### Key Takeaways

1. **Montgomery encoding matters at the bit level.** Getting R vs R^2 wrong produces a zkey that *looks* valid but silently generates invalid proofs.

2. **Random setup is not compatible with ceremony-based verification.** You cannot mix ark-groth16's random $\tau$ with snarkjs's ceremony-derived points.

3. **Section ordering is not numerical.** snarkjs writes sections in order 1,2,4,3,9,8,5,6,7,10. Byte-identical output requires matching this.

4. **The H query size must be exactly `domain_size`.** Not `domain_size - 1`, which some documentation suggests.

5. **Projective coordinates are essential for accumulation.** Affine point addition requires field inversions; accumulating millions of point additions in affine coordinates would be orders of magnitude slower.

6. **IFFT over curve points works.** The Cooley-Tukey butterfly algorithm generalizes cleanly from field elements to elliptic curve points, enabling on-the-fly Lagrange basis computation.

---

*This document describes the implementation in [rapidzkey](.), a Rust tool for generating snarkjs-compatible Groth16 zkey files. For usage instructions, see [README.md](README.md).*
