# rapidzkey: Technical Deep-Dive

A comprehensive guide to the Groth16 trusted setup, the zkey binary format, Montgomery arithmetic pitfalls, and the parallel algorithms that make rapidzkey produce byte-identical output to snarkjs in a fraction of the time.

---

## Table of Contents

1. [Groth16 Theory](#1-groth16-theory)
2. [The Powers of Tau Ceremony](#2-the-powers-of-tau-ceremony)
3. [The zkey Binary Format](#3-the-zkey-binary-format)
4. [Montgomery Form Deep-Dive](#4-montgomery-form-deep-dive)
5. [Why ark-groth16 Is Incompatible](#5-why-ark-groth16-is-incompatible)
6. [How rapidzkey Derives Sections 5-9](#6-how-rapidzkey-derives-sections-5-9)
7. [The Parallel Accumulation Algorithm](#7-the-parallel-accumulation-algorithm)
8. [IFFT Over Curve Points](#8-ifft-over-curve-points)
9. [The H Query (Section 9)](#9-the-h-query-section-9)
10. [Section 10 and the csHash](#10-section-10-and-the-cshash)
11. [Debugging Journey (Lessons Learned)](#11-debugging-journey-lessons-learned)

---

## 1. Groth16 Theory

### Overview

Groth16 is a pairing-based zero-knowledge succinct non-interactive argument of knowledge (zk-SNARK). Published by Jens Groth in 2016, it remains the most widely deployed SNARK in production due to its constant-size proofs (3 group elements) and fast verification (a single pairing equation).

A Groth16 proof demonstrates knowledge of a witness $w$ satisfying a set of arithmetic constraints, without revealing $w$.

### The Setup Parameters

The trusted setup produces structured reference strings (proving key and verification key) parameterized by secret scalars known as "toxic waste":

| Parameter | Role |
|-----------|------|
| $\tau$ | Secret evaluation point for polynomials |
| $\alpha$ | Binds A-polynomial commitments to the setup |
| $\beta$ | Binds B-polynomial commitments and cross-links A/B/C |
| $\gamma$ | Randomizes public-input verification (identity in phase 1) |
| $\delta$ | Randomizes private-witness verification (identity in phase 1) |

In the `_0000.zkey` (phase-1 output), $\gamma = 1$ and $\delta = 1$ (i.e., the generator points are used). Phase-2 contributions randomize $\gamma$ and $\delta$.

### R1CS to QAP

A Rank-1 Constraint System (R1CS) encodes the computation as a set of $m$ constraints, each of the form:

$$\langle a_i, w \rangle \cdot \langle b_i, w \rangle = \langle c_i, w \rangle$$

where $w$ is the full witness vector (public inputs + private signals) and $a_i, b_i, c_i$ are sparse coefficient vectors.

The Quadratic Arithmetic Program (QAP) converts these $m$ constraints into polynomials. For each signal $s$, define polynomials $A_s(x), B_s(x), C_s(x)$ such that:

$$A_s(\omega^i) = a_{i,s}, \quad B_s(\omega^i) = b_{i,s}, \quad C_s(\omega^i) = c_{i,s}$$

where $\omega$ is a primitive $n$-th root of unity ($n$ = domain size, the smallest power of 2 $\geq m + n_{pub} + 1$).

The QAP satisfaction condition is:

$$A(x) \cdot B(x) - C(x) = H(x) \cdot Z(x)$$

where $Z(x) = x^n - 1$ is the vanishing polynomial and $H(x)$ is the quotient.

### Lagrange Basis vs Monomial Basis

The same polynomial can be represented two ways:

- **Monomial basis**: $p(x) = c_0 + c_1 x + c_2 x^2 + \cdots$
- **Lagrange basis**: $p(x) = v_0 L_0(x) + v_1 L_1(x) + \cdots$ where $L_i(\omega^j) = \delta_{ij}$

The Lagrange representation is natural for R1CS: the coefficient of $L_i(x)$ for signal $s$ in matrix $A$ is simply $a_{i,s}$. This is why rapidzkey works directly with Lagrange-basis ptau points -- the R1CS coefficients can be used as MSM scalars without polynomial interpolation.

The conversion between bases is an (I)FFT:
- Lagrange $\to$ Monomial: FFT (evaluation $\to$ coefficients)
- Monomial $\to$ Lagrange: IFFT (coefficients $\to$ evaluations)

### The Verification Equation

A Groth16 proof is a triple $(A, B, C)$ where $A, C \in \mathbb{G}_1$ and $B \in \mathbb{G}_2$. Verification checks:

$$e(A, B) = e(\alpha, \beta) \cdot e(\text{IC}, \gamma) \cdot e(C, \delta)$$

where:
- $e: \mathbb{G}_1 \times \mathbb{G}_2 \to \mathbb{G}_T$ is the bilinear pairing
- $\text{IC} = \sum_{i=0}^{n_{pub}} x_i \cdot \text{IC}_i$ is the public-input commitment
- $\alpha, \beta$ are from the ceremony
- $\gamma, \delta$ are from phase-2 contributions

On BN254, the pairing is computed via the optimal Ate pairing. On-chain (EVM), verification uses the `ecPairing` precompile at address `0x08`.

### Why the Setup Is "Toxic Waste"

If anyone learns $\tau$, they can forge proofs for any statement. Specifically, knowing $\tau$ lets you compute $H(\tau)$ for an arbitrary $H(x)$ and satisfy the pairing equation without knowing a valid witness. The multi-party ceremony ensures $\tau$ is destroyed: as long as at least one participant is honest and deletes their contribution, the combined $\tau$ is unknowable.

---

## 2. The Powers of Tau Ceremony

### What a ptau File Contains

A `.ptau` file is the output of a Powers of Tau ceremony. It contains structured reference string (SRS) elements that are universal (circuit-independent) and can be reused for any circuit up to a certain size.

The core data consists of elliptic curve points encoding powers of the secret $\tau$, combined with $\alpha$ and $\beta$:

| Data | Description | Group |
|------|-------------|-------|
| $\tau^i \cdot G_1$ for $i = 0 \ldots 2^{power}$ | Powers of tau on G1 | $\mathbb{G}_1$ |
| $\tau^i \cdot G_2$ for $i = 0 \ldots 2^{power}$ | Powers of tau on G2 | $\mathbb{G}_2$ |
| $\alpha \cdot \tau^i \cdot G_1$ | Alpha-weighted powers | $\mathbb{G}_1$ |
| $\beta \cdot \tau^i \cdot G_1$ | Beta-weighted powers | $\mathbb{G}_1$ |
| $\beta \cdot G_2$ | Beta on G2 | $\mathbb{G}_2$ |

### Monomial vs Lagrange Sections

The ptau file stores these points in two forms:

```
Monomial basis (sections 2-6):
  Section 2: tauG1[i] = tau^i * G1           (standard polynomial coefficients)
  Section 3: tauG2[i] = tau^i * G2
  Section 4: alphaTauG1[i] = alpha * tau^i * G1
  Section 5: betaTauG1[i] = beta * tau^i * G1
  Section 6: betaTauG2[0] = beta * G2

Lagrange basis (sections 12-15):
  Section 12: tauG1_lagrange[i] = L_i(tau) * G1   (evaluation at roots of unity)
  Section 13: tauG2_lagrange[i] = L_i(tau) * G2
  Section 14: alphaTauG1_lagrange[i] = alpha * L_i(tau) * G1
  Section 15: betaTauG1_lagrange[i] = beta * L_i(tau) * G1
```

Sections 12-15 contain Lagrange points for every power-of-two domain from $2^1$ up to $2^{power}$. The points for domain size $d$ start at byte offset $(d - 1) \times \text{point\_size}$ within the section.

### The Multi-Party Ceremony

Each contributor $k$ samples a random $\tau_k$ and updates the SRS:

$$\tau^i \cdot G_1 \longrightarrow \tau_k^i \cdot (\tau^i \cdot G_1) = (\tau_k \cdot \tau)^i \cdot G_1$$

The final toxic waste is $\tau = \tau_1 \cdot \tau_2 \cdots \tau_n$. As long as one contributor honestly destroys their $\tau_k$, the combined $\tau$ is unknowable. The [Hermez ceremony](https://ceremony.hermez.io/) had 54 contributors for its production ptau files.

### Phase 1 vs Phase 2

| | Phase 1 | Phase 2 |
|---|---------|---------|
| **Scope** | Universal (any circuit up to $2^{power}$) | Circuit-specific |
| **Parameters** | $\tau, \alpha, \beta$ | $\gamma, \delta$ |
| **Output** | `.ptau` file | `_NNNN.zkey` files |
| **Reusable?** | Yes, across all circuits | No, tied to one R1CS |

Our tool generates the **Phase 1 output** (`_0000.zkey`) where $\gamma = 1$ and $\delta = 1$. Phase 2 contributions (via `snarkjs zkey contribute`) multiply the appropriate proving key elements by random $\gamma^{-1}$ and $\delta^{-1}$ factors.

---

## 3. The zkey Binary Format

### File Structure

```
Offset  Size    Field
------  -----   -----
0       4       Magic bytes: "zkey" (0x7a6b6579)
4       4       Version: u32 LE (= 1)
8       4       Number of sections: u32 LE (= 10)
12      ...     Section entries (contiguous)

Each section entry:
+0      4       Section ID: u32 LE
+4      8       Section size: u64 LE
+12     N       Section data: [u8; size]
```

**Critical**: snarkjs writes sections in the order **1, 2, 4, 3, 9, 8, 5, 6, 7, 10** -- NOT numerical order. This ordering must be replicated for byte-identical output.

### Section 1: Header

```
Offset  Size    Field
------  -----   -----
0       4       Prover type: u32 LE (= 1 for Groth16)
```

Total: 4 bytes.

### Section 2: HeaderGroth

Contains the curve parameters and verification key points.

```
Offset  Size    Field
------  -----   -----
0       4       n8q: u32 LE (= 32, bytes per Fq element)
4       32      q: BN254 base field modulus (LE bytes)
                  = 21888242871839275222246405745257275088696311157297823662689037894645226208583
36      4       n8r: u32 LE (= 32, bytes per Fr element)
40      32      r: BN254 scalar field modulus (LE bytes)
                  = 21888242871839275222246405745257275088548364400416034343698204186575808495617
72      4       NVars: u32 LE (total number of signals)
76      4       NPub: u32 LE (public inputs, excluding constant "1" wire)
80      4       DomainSize: u32 LE (next power of 2 >= num_constraints + n_pub + 1)
84      64      alpha1: alpha * G1 (Montgomery Fq, 2x32 bytes: x, y)
148     64      beta1: beta * G1 (Montgomery Fq)
212     128     beta2: beta * G2 (Montgomery Fq, 4x32 bytes: x.c0, x.c1, y.c0, y.c1)
340     128     gamma2: G2 point (= G2 generator for _0000.zkey)
468     64      delta1: G1 point (= G1 generator for _0000.zkey)
532     128     delta2: G2 point (= G2 generator for _0000.zkey)
```

Total: 660 bytes.

### Section 3: IC (gamma_abc_g1)

```
(n_public + 1) * 64 bytes of G1 affine points in Montgomery Fq form.

IC[s] = sum over constraints of:
  A_matrix:   coef * beta * L_i(tau) * G1
  B_matrix:   coef * alpha * L_i(tau) * G1
  C_matrix:   coef * L_i(tau) * G1
  for signals s = 0..n_public
```

These are the public-input verification points used in the pairing equation.

### Section 4: Coefs (R1CS Coefficients)

```
Offset  Size    Field
------  -----   -----
0       4       num_coeffs: u32 LE
4       44*N    Coefficient entries

Each entry (44 bytes):
+0      4       matrix: u32 LE (0 = A, 1 = B; C is implicit)
+4      4       constraint: u32 LE (constraint index)
+8      4       signal: u32 LE (signal index)
+12     32      value: Fr in R^2 Montgomery form (4 LE u64 limbs)
```

**Only A and B matrices are stored.** The C matrix is reconstructed implicitly during witness computation.

After the R1CS constraint coefficients, identity constraints for public signals are appended:

```
For s = 0..n_public:
  matrix = 0 (A)
  constraint = num_constraints + s
  signal = s
  value = 1 (in R^2 Montgomery form)
```

**The R^2 encoding is critical** -- see [Section 4: Montgomery Form Deep-Dive](#4-montgomery-form-deep-dive).

### Section 5: PointsA (a_query)

```
n_vars * 64 bytes of G1 affine points in Montgomery Fq form.

A[s] = sum_i A_coef[i][s] * tauG1_lagrange[i]
```

### Section 6: PointsB1 (b_g1_query)

```
n_vars * 64 bytes of G1 affine points in Montgomery Fq form.

B1[s] = sum_i B_coef[i][s] * tauG1_lagrange[i]
```

### Section 7: PointsB2 (b_g2_query)

```
n_vars * 128 bytes of G2 affine points in Montgomery Fq form.

B2[s] = sum_i B_coef[i][s] * tauG2_lagrange[i]
```

### Section 8: PointsC / L query

```
(n_vars - n_public - 1) * 64 bytes of G1 affine points.

For each private signal s (s > n_public):
L[s] = sum_i (
    A_coef[i][s] * betaTauG1_lagrange[i] +
    B_coef[i][s] * alphaTauG1_lagrange[i] +
    C_coef[i][s] * tauG1_lagrange[i]
)
```

This is the "L query" -- it combines the cross-terms needed for the C proof element.

### Section 9: H query

```
domain_size * 64 bytes of G1 affine points.

H[i] = tauG1_doubled_lagrange[2*i + 1]  for i = 0..domain_size
```

See [Section 9: The H Query](#9-the-h-query-section-9) for the mathematical details.

### Section 10: Contributions

```
Offset  Size    Field
------  -----   -----
0       64      csHash: blake2b-512 circuit hash
64      4       numContributions: u32 LE (= 0 for _0000.zkey)
```

For each contribution (in contributed zkeys), additional data follows with the contributor's delta/gamma randomness and a hash chain.

### Section Size Summary

For a circuit with $V$ variables, $P$ public inputs, domain size $D$:

| Section | Size (bytes) |
|---------|-------------|
| 1 | 4 |
| 2 | 660 |
| 3 | $(P + 1) \times 64$ |
| 4 | $4 + N_{coefs} \times 44$ |
| 5 | $V \times 64$ |
| 6 | $V \times 64$ |
| 7 | $V \times 128$ |
| 8 | $(V - P - 1) \times 64$ |
| 9 | $D \times 64$ |
| 10 | 68 |

For a 2M-constraint circuit ($V \approx 2M$, $D = 2^{21}$), the total is approximately 1.2 GB.

---

## 4. Montgomery Form Deep-Dive

### What Is Montgomery Form?

Montgomery multiplication is a technique for efficient modular arithmetic. Instead of representing a value $v$ directly, it is stored as:

$$\hat{v} = v \cdot R \mod p$$

where $R = 2^{256}$ for 256-bit fields. The key benefit: multiplying two Montgomery-form values $\hat{a} \cdot \hat{b}$ and applying Montgomery reduction yields $(a \cdot b) \cdot R \mod p$ -- modular multiplication without expensive division.

### The R^2 Encoding in Section 4

Section 4 coefficients are stored in **R-squared Montgomery form**:

$$\text{stored} = v \cdot R^2 \mod r$$

This is NOT standard Montgomery ($v \cdot R$). The reason is a snarkjs/rapidsnark convention: the witness computation engine loads these values and applies exactly one Montgomery reduction, yielding $v \cdot R$ (standard Montgomery form) for internal use.

Evidence from the snarkjs source (`zkey_new.js`, line 330):

```javascript
nR2 = Fr.mul(n, R2r);  // Explicitly multiplies coefficient by R^2
```

Evidence from ark-circom's `deserialize_field_fr`:

```rust
// Double new_unchecked/into_bigint to undo the R^2 encoding
let mont = Fr::new_unchecked(BigInteger256::new(limbs));
let standard = Fr::from_bigint(mont.into_bigint()).unwrap();
```

Empirical verification: the coefficient `1` is stored as:

$$1 \cdot R^2 \mod r = \texttt{0x0216d0b17f4e44a58c49833d53bb808553fe3ab1e35c59e31bb8e645ae216da7}$$

which equals `944936681149208446651664254269745548490766851729442924617792859073125903783` in decimal.

### How rapidzkey Encodes R^2

In ark-ff, an `Fr` value's internal representation is already `standard_value * R` (standard Montgomery). To get `standard_value * R^2`:

```rust
fn write_fr_r2(buf: &mut Vec<u8>, val: &Fr) {
    // val.0.0 = standard_value * R as raw BigInteger limbs
    let vr = BigInteger256::new(val.0.0);

    // Fr::from_bigint treats vr as a "standard" value and multiplies by R:
    // internal = vr * R = (standard_value * R) * R = standard_value * R^2
    let doubled = Fr::from_bigint(vr).unwrap();

    // Write the internal limbs (which are standard_value * R^2 in Montgomery)
    for limb in doubled.0.0.iter() {
        buf.write_u64::<LittleEndian>(*limb).unwrap();
    }
}
```

### G1/G2 Coordinates: Standard Montgomery

Unlike Fr coefficients, the Fq coordinates of curve points use standard Montgomery form ($v \cdot R \mod q$). Both ptau files and zkey files store Fq this way. When reading raw bytes:

```rust
// CORRECT: new_unchecked loads raw Montgomery limbs without re-encoding
let x = Fq::new_unchecked(BigInteger256::new(limbs));

// WRONG: from_bigint would multiply by R again, double-encoding
let x = Fq::from_bigint(BigInteger256::new(limbs));  // DON'T DO THIS
```

### Summary Table

| Data | Encoding | Where |
|------|----------|-------|
| Section 4 Fr coefficients | $v \cdot R^2 \mod r$ | zkey only |
| Fq coordinates (G1/G2 points) | $v \cdot R \mod q$ | ptau and zkey |
| ark-ff `Fr` internal representation | $v \cdot R \mod r$ | in-memory only |
| "Standard" (non-Montgomery) | $v$ | csHash hashing, display |

---

## 5. Why ark-groth16 Is Incompatible

### The Problem

`ark-groth16::generate_random_parameters` samples fresh random values for $(\tau, \alpha, \beta, \gamma, \delta)$ internally. These are self-consistent -- ark-groth16 can prove and verify with them. But the resulting zkey is fundamentally incompatible with snarkjs/rapidsnark.

### Why It Breaks

The critical issue is the **tau source**. snarkjs's prover computes the proof using:

1. The QAP polynomials $A(x), B(x), C(x)$ derived from Section 4 coefficients
2. The H query points from Section 9, which encode $\tau$ from the ptau ceremony
3. The quotient polynomial $H(\tau) = (A(\tau) \cdot B(\tau) - C(\tau)) / Z(\tau)$

If the proving key's A/B/C/L points were generated with a *different* $\tau$ (as ark-groth16 does), the QAP evaluation at $\tau$ is inconsistent with the H points, and the pairing equation fails.

```
                        ┌─────────────────────────┐
  ark-groth16:          │ random tau_ark           │──> A, B, C points
                        └─────────────────────────┘
                                  ↕  MISMATCH
                        ┌─────────────────────────┐
  snarkjs prover:       │ ptau ceremony tau_ptau   │──> H points, witness computation
                        └─────────────────────────┘
```

### The Red Herrings

During debugging, two differences appeared suspicious but turned out to be irrelevant:

1. **`CircomReduction` vs `LibsnarkReduction`**: These affect how the proof elements are computed (different linear combinations of the same polynomials), but both are valid Groth16 variants. The choice doesn't matter as long as the verifier matches.

2. **`PhantomData` transmute bug**: An early theory was that `PhantomData<T>` in ark-ec point types caused layout issues during transmute. Since `PhantomData` is a ZST (zero-sized type), this was not the real issue.

### Empirical Confirmation

We verified the incompatibility by:

1. Generating a zkey with ark-groth16 random setup
2. Proving with ark-circom (which uses ark-groth16's prover internally)
3. Verifying with ark-circom's verifier: **PASS** (internally consistent)
4. Verifying with snarkjs: **FAIL** (tau mismatch)

The fix: derive all proving key points directly from the ptau ceremony's Lagrange-basis points, exactly as snarkjs does.

---

## 6. How rapidzkey Derives Sections 5-9

### The Principle

Instead of random setup, we compute each proving key point as a multi-scalar multiplication (MSM) of ptau Lagrange-basis points weighted by R1CS coefficients.

For section 5 (A query), each signal $s$:

$$A[s] = \sum_{j} A\_\text{matrix}[j][s] \cdot \tau G1\_\text{lagrange}[j]$$

This is exactly what snarkjs's `zkey_new.js` does in `processConstraints()` and `composeAndWritePoints()`.

### Section-by-Section Derivation

```
Section 5 (A query): For each signal s:
  A[s] = sum_j  A_coef[j][s] * tauG1_lagrange[j]

Section 6 (B1 query): For each signal s:
  B1[s] = sum_j  B_coef[j][s] * tauG1_lagrange[j]

Section 7 (B2 query): For each signal s:
  B2[s] = sum_j  B_coef[j][s] * tauG2_lagrange[j]

Section 3 (IC): For each public signal s (0..n_public):
  IC[s] = sum_j (
      A_coef[j][s] * betaTauG1_lagrange[j] +
      B_coef[j][s] * alphaTauG1_lagrange[j] +
      C_coef[j][s] * tauG1_lagrange[j]
  )

Section 8 (L query): For each private signal s (> n_public):
  L[s] = sum_j (
      A_coef[j][s] * betaTauG1_lagrange[j] +
      B_coef[j][s] * alphaTauG1_lagrange[j] +
      C_coef[j][s] * tauG1_lagrange[j]
  )
```

### Identity Constraints

Public signals $s = 0 \ldots n_{pub}$ have additional identity constraints appended after the R1CS constraints. For each such signal $s$:

- In the A matrix at constraint index $m + s$ (where $m$ = number of R1CS constraints): coefficient = 1
- This adds `tauG1_lagrange[m + s]` to `A[s]` and `betaTauG1_lagrange[m + s]` to `IC[s]`

### Determinism

The result is entirely deterministic given (ptau, r1cs). There is no randomness in the `_0000.zkey`. Phase-2 contributions (`snarkjs zkey contribute`) introduce the $\gamma$ and $\delta$ randomness later.

---

## 7. The Parallel Accumulation Algorithm

### The Naive Approach

The straightforward implementation computes one MSM per signal:

```
for s in 0..n_vars:
    bases  = [tauG1_lagrange[j] for all constraints j where A[j][s] != 0]
    scalars = [A_coef[j][s]      for all constraints j where A[j][s] != 0]
    A[s] = MSM(bases, scalars)
```

This has $O(n\_vars)$ MSM invocations. Each MSM uses Pippenger's algorithm internally, which has setup overhead (bucket allocation, scalar decomposition). For a 2M-variable circuit, this means 2 million MSM calls -- each individually fast but cumulatively slow, with poor cache locality as we jump around the ptau point arrays.

### The Fast Approach: Constraint-Driven Scatter-Accumulate

Instead of iterating over signals, iterate over constraints:

```
┌────────────────────────────────────────────────────────┐
│ Constraints split into chunks (one per thread)         │
│                                                        │
│ Thread 0: constraints[0..chunk_size]                   │
│ Thread 1: constraints[chunk_size..2*chunk_size]        │
│ Thread 2: constraints[2*chunk_size..3*chunk_size]      │
│ ...                                                    │
│                                                        │
│ Each thread has per-signal accumulator buffers:         │
│   a[0..n_vars]   : G1Projective (section 5)            │
│   b1[0..n_vars]  : G1Projective (section 6)            │
│   b2[0..n_vars]  : G2Projective (section 7)            │
│   ic[0..n_pub+1] : G1Projective (section 3)            │
│   c[0..n_priv]   : G1Projective (section 8)            │
└────────────────────────────────────────────────────────┘
```

Each thread processes its constraint chunk:

```
for constraint c_i in my_chunk:
    for (signal, coef) in A[c_i]:
        a[signal]  += coef * tauG1_lagrange[i]      // scalar mul + point add
        ic_or_c[signal] += coef * betaTauG1_lagrange[i]
    for (signal, coef) in B[c_i]:
        b1[signal] += coef * tauG1_lagrange[i]
        b2[signal] += coef * tauG2_lagrange[i]
        ic_or_c[signal] += coef * alphaTauG1_lagrange[i]
    for (signal, coef) in C[c_i]:
        ic_or_c[signal] += coef * tauG1_lagrange[i]
```

After all threads finish, merge via point addition and convert to affine:

```
final = ThreadAccum::new()
for each thread_result:
    final.merge(thread_result)   // element-wise point addition
final.to_affine()                // batch inversion for projective -> affine
```

### Why Projective Coordinates?

During accumulation, we use projective coordinates $(X : Y : Z)$ instead of affine $(x, y)$:

- **Point addition in projective**: ~12 field multiplications, no inversions
- **Point addition in affine**: requires a field inversion ($\sim 200 \times$ more expensive)
- **Conversion to affine**: one inversion per point, done once at the end

### Memory Analysis

Each thread allocates:

| Buffer | Points | Size per point | Size |
|--------|--------|----------------|------|
| a | n_vars | 96 bytes (G1Projective: 3 Fq) | $V \times 96$ |
| b1 | n_vars | 96 bytes | $V \times 96$ |
| b2 | n_vars | 192 bytes (G2Projective: 3 Fq2) | $V \times 192$ |
| ic | n_pub+1 | 96 bytes | negligible |
| c | n_vars - n_pub - 1 | 96 bytes | $V \times 96$ |

Total per thread: $\approx V \times 480$ bytes. For $V = 2M$ signals and 16 threads:

$$16 \times 2{,}000{,}000 \times 480 \approx 15 \text{ GB}$$

This is the primary memory bottleneck. On the tested M3 Max (48 GB RAM), this fits comfortably.

### Time Complexity

$$T = O\left(\frac{\text{total\_nonzero\_entries}}{n\_\text{threads}}\right)$$

Each non-zero R1CS entry requires one scalar multiplication (~4000 ns for G1, ~12000 ns for G2) and one point addition (~100 ns). For a 2M-constraint circuit with average 3 non-zeros per constraint per matrix, and 16 threads:

$$\approx \frac{2M \times 3 \times 3 \times 4000\text{ns}}{16} \approx 135\text{s}$$

Measured: ~171s (including G2 operations and overhead), consistent with expectation.

---

## 8. IFFT Over Curve Points

### The Problem

Many ptau files from ceremony repositories contain only:
- Section 12: tauG1 Lagrange points (always present)
- Sections 2-6: Monomial-basis points

Sections 13 (tauG2 Lagrange), 14 (alphaTauG1 Lagrange), and 15 (betaTauG1 Lagrange) are often missing. The standard fix is:

```bash
snarkjs powersoftau prepare phase2 pot_raw.ptau pot_prepared.ptau
```

But this is single-threaded JavaScript and takes hours for large ceremonies (power 21+).

### Our Fix: Parallel IFFT Over Curve Points

We compute the Lagrange-basis points from monomial points via radix-2 IFFT, operating directly on elliptic curve points instead of field elements.

The key insight: an IFFT is a sequence of "butterfly" operations, each consisting of:
1. **Multiply by twiddle factor**: scalar multiplication of a curve point by an Fr element
2. **Add/subtract**: curve point addition and subtraction

These operations are well-defined on elliptic curve groups, so the standard Cooley-Tukey FFT algorithm applies.

### The Algorithm

```
Input:  P[0..n-1] = monomial-basis points (tau^i * G)
Output: P[0..n-1] = Lagrange-basis points (L_i(tau) * G)

1. Bit-reverse permutation:
   for i in 0..n:
       j = bit_reverse(i, log2(n))
       if i < j: swap(P[i], P[j])

2. Butterfly stages (log2(n) levels):
   step = 2
   while step <= n:
       half = step / 2
       w_step = omega_inv^(n/step)     // twiddle factor step

       // Precompute twiddles for this level
       twiddles[k] = omega_inv^(k * n/step)  for k = 0..half

       // Process butterflies (parallelized when num_groups >= 4)
       for each group of `step` consecutive elements:
           for i in 0..half:
               u = P[base + i]
               v = twiddles[i] * P[base + i + half]    // SCALAR MULT
               P[base + i]        = u + v               // POINT ADD
               P[base + i + half] = u - v               // POINT SUB
       step *= 2

3. Scale by 1/n:
   n_inv = Fr::from(n).inverse()
   for all i: P[i] = n_inv * P[i]                      // SCALAR MULT
```

### Parallelization

At each butterfly level, independent groups of elements are processed in parallel using Rayon's `par_chunks_mut`. Parallelism kicks in when there are $\geq 4$ groups (early levels with large steps have few groups; later levels have many).

```
Level 1 (step=2):     n/2 groups, highly parallel
Level 2 (step=4):     n/4 groups, parallel
...
Level log2(n) (step=n): 1 group, sequential
```

The final scaling by $1/n$ is embarrassingly parallel.

### Roots of Unity

The twiddle factors use $\omega^{-1}$ (inverse of the domain generator) from `ark_poly::Radix2EvaluationDomain<Fr>`. For BN254, the scalar field $r$ has $2$-adicity of 28, so the largest supported domain is $2^{28}$.

### Performance

For domain size $2^{21}$ (2M points):
- G1 IFFT: ~30 seconds (21 levels, each with up to 1M scalar multiplications)
- G2 IFFT: ~90 seconds (G2 scalar multiplication is ~3x slower due to Fq2 arithmetic)

This is significantly faster than snarkjs's single-threaded JavaScript implementation (hours), though still the main cost when dealing with unprepared ptau files.

---

## 9. The H Query (Section 9)

### Mathematical Background

The H query encodes the quotient polynomial evaluation. In the Groth16 proof, the prover must demonstrate that:

$$A(\tau) \cdot B(\tau) - C(\tau) = H(\tau) \cdot Z(\tau)$$

where $Z(x) = x^n - 1$ is the vanishing polynomial over the domain of $n$-th roots of unity.

The quotient polynomial $H(x)$ has degree $\leq n - 1$ (since $\deg(A \cdot B) \leq 2(n-1)$ and $\deg(Z) = n$). But $A(x) \cdot B(x)$ has degree $2(n-1)$, so we need evaluations on a domain of size $2n$.

### The Doubled Domain and Coset Evaluations

snarkjs computes H points using the **coset** of the doubled domain. The doubled domain has $2n$ roots of unity $\{\omega_{2n}^i\}_{i=0}^{2n-1}$. The "odd" roots $\omega_{2n}^{2i+1}$ form a coset of the original domain -- they are exactly the points where $Z(x) \neq 0$, which is necessary for dividing by $Z(x)$.

### How snarkjs Extracts H Points

From the ptau file, section 12 contains tauG1 Lagrange points for the doubled domain ($2n$ points). snarkjs extracts the odd-indexed points:

```
H[i] = tauG1_doubled_lagrange[2*i + 1]    for i = 0..domain_size
```

In rapidzkey, this is a direct byte copy:

```rust
for i in 0..domain_size {
    let src_idx = i * 2 + 1;
    let offset = src_idx * G1_SIZE;
    points_h_bytes.extend_from_slice(
        &ptau.tau_g1_lagrange_doubled[offset..offset + G1_SIZE]
    );
}
```

### Why Odd Indices?

The even-indexed Lagrange points of the doubled domain correspond to the original domain's roots $\omega_n^i$, where $Z(\omega_n^i) = 0$. Division by $Z(x)$ at these points is undefined.

The odd-indexed points correspond to $\omega_{2n}^{2i+1} = \omega_{2n} \cdot \omega_n^i$, which is a **coset shift** by $\omega_{2n}$. At these points:

$$Z(\omega_{2n}^{2i+1}) = (\omega_{2n}^{2i+1})^n - 1 = \omega_{2n}^{n(2i+1)} - 1 = \omega_{2n}^n \cdot \omega_{2n}^{2ni} - 1 = (-1) \cdot 1 - 1 = -2$$

So $Z$ is non-zero (and constant!) on the coset, enabling clean division.

### Domain Size vs Domain Size - 1

A subtle point: Section 9 contains `domain_size` points (not `domain_size - 1`). An earlier bug in rapidzkey used `domain_size - 1` points, which caused "Scalar size does not match" errors during proof generation. The fix was to pad with one extra point -- or more precisely, to extract exactly `domain_size` odd-indexed points from the $2n$-point Lagrange basis.

---

## 10. Section 10 and the csHash

### What csHash Is

The `csHash` is a blake2b-512 hash of all circuit-specific data in the zkey. It serves as a fingerprint that links all phase-2 contributions to the same circuit, ensuring that contributors can't mix contributions from different circuits.

### What Gets Hashed

The hash includes, in order:

```
1. VK points in "uncompressed" form (standard Fq, big-endian):
   - alpha_g1
   - beta_g1
   - beta_g2
   - gamma_g2 (= G2 generator for _0000)
   - delta_g1 (= G1 generator for _0000)
   - delta_g2 (= G2 generator for _0000)

2. IC section: u32BE(n_public + 1) + IC points uncompressed

3. H section: u32BE(domain_size - 1) + H points (special computation)
   NOTE: snarkjs hashes H from ptau section 2 (monomial), not from section 9.
   Specifically: H_hash[i] = tauG1_monomial[domain_size + i] - tauG1_monomial[i]

4. C section: u32BE(n_vars - n_public - 1) + L points uncompressed

5. A section: u32BE(n_vars) + A points uncompressed

6. B1 section: u32BE(n_vars) + B1 points uncompressed

7. B2 section: u32BE(n_vars) + B2 points uncompressed
```

"Uncompressed" means standard (non-Montgomery) Fq coordinates in big-endian byte order. snarkjs calls this "LEM to Uncompressed" conversion.

### Why Our csHash Differs

snarkjs computes the H-point portion of the hash from ptau section 2 (monomial tauG1 points), using the formula:

$$H\_\text{hash}[i] = \tau^{n+i} \cdot G_1 - \tau^i \cdot G_1 = (\tau^n - 1) \cdot \tau^i \cdot G_1$$

rapidzkey hashes the actual H points from section 9 instead. This produces a different csHash, but **does not affect proving or verification** -- it only affects ceremony chain integrity checks. A tool like `snarkjs zkey verify` would report a csHash mismatch, but the proofs generated from the zkey are valid and verify on-chain.

### Contribution Hash Chain

In a contributed zkey (`_0001.zkey`, `_0002.zkey`, etc.), section 10 contains:

```
csHash (64 bytes)
numContributions: u32 LE
For each contribution:
  deltaG1_after: 64 bytes (new delta * G1)
  deltaG2_after: 128 bytes (new delta * G2)
  contributionHash: 64 bytes (blake2b of contribution)
```

The hash chain ensures that each contributor built on the previous one's output.

---

## 11. Debugging Journey

The path from first attempt to working implementation involved 8 failed hypotheses and progressive discoveries. The full chronological account — including wrong turns, red herrings, and the eventual fixes — is documented separately:

**[DEBUGGING.md](DEBUGGING.md)** — *From Invalid Proofs to Byte-Identical Output*

Key takeaways:

1. **Montgomery encoding matters at the bit level.** Getting R vs R² wrong produces a zkey that *looks* valid but silently generates invalid proofs.
2. **Random setup is incompatible with ceremony-based verification.** You cannot mix ark-groth16's random τ with snarkjs's ceremony-derived points.
3. **Section ordering is not numerical.** snarkjs writes sections as 1,2,4,3,9,8,5,6,7,10.
4. **The H query size must be exactly `domain_size`.** Not `domain_size - 1`.
5. **Projective coordinates are essential for accumulation.** Affine addition requires inversions — millions of them would be orders of magnitude slower.
6. **IFFT over curve points works.** The Cooley-Tukey butterfly generalizes cleanly from field elements to elliptic curve points.

---

*This document describes the implementation in [rapidzkey](.). For usage instructions, see [README.md](README.md). For the debugging narrative, see [DEBUGGING.md](DEBUGGING.md).*
