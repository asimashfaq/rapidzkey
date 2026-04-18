// ============================================================================
// zkey_writer.rs — Write snarkjs-compatible .zkey files from ptau + R1CS data
// ============================================================================
// Produces _0000.zkey files (before phase 2 contributions) that are
// byte-identical to snarkjs's `groth16 setup` output.
//
// Format: "zkey" magic + version(1) + sections:
//   1: Header (prover type = 1 for Groth16)
//   2: HeaderGroth (curve params + verification key points)
//   3: IC (gamma_abc_g1 points)
//   4: Coefs (R1CS coefficients in R^2 Montgomery form)
//   5: PointsA (a_query)
//   6: PointsB1 (b_g1_query)
//   7: PointsB2 (b_g2_query)
//   8: PointsC (l_query)
//   9: PointsH (h_query)
//  10: Contributions (csHash + 0 contributions)
// ============================================================================

use ark_bn254::{Fq, Fr};
use ark_circom::circom::Constraints;
use ark_ff::{BigInteger256, PrimeField};
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::{self, Write};

/// BN254 base field modulus q (Fq) in little-endian u64 limbs.
/// q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
const Q: [u64; 4] = [
    0x3C208C16D87CFD47,
    0x97816a916871ca8d,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// BN254 scalar field modulus r (Fr) in little-endian u64 limbs.
/// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const R: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// BN254 G1 generator in Montgomery Fq form (x, y).
/// G1 generator: (1, 2) in standard form.
/// In Montgomery Fq: Fq::one() and Fq::from(2u64).
fn g1_generator_bytes() -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    write_fq_montgomery(&mut buf, &Fq::from(1u64));
    write_fq_montgomery(&mut buf, &Fq::from(2u64));
    buf
}

/// BN254 G2 generator in Montgomery Fq form (x.c0, x.c1, y.c0, y.c1).
fn g2_generator_bytes() -> Vec<u8> {
    use ark_bn254::G2Affine;
    use ark_ec::AffineRepr;

    let g2 = G2Affine::generator();
    let x = g2.x().unwrap();
    let y = g2.y().unwrap();
    let mut buf = Vec::with_capacity(128);
    write_fq_montgomery(&mut buf, &x.c0);
    write_fq_montgomery(&mut buf, &x.c1);
    write_fq_montgomery(&mut buf, &y.c0);
    write_fq_montgomery(&mut buf, &y.c1);
    buf
}

/// Write a complete `_0000.zkey` file (phase-1, zero contributions) from ptau-derived data.
///
/// The sections are written in the same order as snarkjs: 1, 2, 4, 3, 9, 8, 5, 6, 7, 10.
/// This ordering is important for byte-identical output -- snarkjs writes sections in this
/// specific non-sequential order, and tools that compare zkey files expect it.
///
/// # File format
/// ```text
/// "zkey" (4 bytes magic)
/// version: u32 LE (= 1)
/// num_sections: u32 LE (= 10)
/// For each section:
///   section_id: u32 LE
///   section_size: u64 LE
///   section_data: [u8; section_size]
/// ```
pub fn write_zkey<W: Write>(
    writer: &mut W,
    n_vars: usize,
    n_public: usize,
    domain_size: u32,
    // VK points from ptau (raw Montgomery bytes)
    alpha_g1: &[u8], // 64 bytes
    beta_g1: &[u8],  // 64 bytes
    beta_g2: &[u8],  // 128 bytes
    // Pre-computed section data (raw bytes)
    ic_bytes: &[u8],        // Section 3
    coefs_bytes: &[u8],     // Section 4
    points_a_bytes: &[u8],  // Section 5
    points_b1_bytes: &[u8], // Section 6
    points_b2_bytes: &[u8], // Section 7
    points_c_bytes: &[u8],  // Section 8
    points_h_bytes: &[u8],  // Section 9
    cs_hash: &[u8],         // 64-byte circuit hash for contributions section
) -> io::Result<()> {
    let g1_gen = g1_generator_bytes();
    let g2_gen = g2_generator_bytes();

    // Build sections
    let section_1 = build_header_section();
    let section_2 = build_header_groth_section(
        n_vars,
        n_public,
        domain_size,
        alpha_g1,
        beta_g1,
        beta_g2,
        &g2_gen,
        &g1_gen,
        &g2_gen,
    );
    let section_10 = build_contributions_section(cs_hash);

    // Write in snarkjs order: 1, 2, 4, 3, 9, 8, 5, 6, 7, 10
    let sections: Vec<(u32, &[u8])> = vec![
        (1, &section_1),
        (2, &section_2),
        (4, coefs_bytes),
        (3, ic_bytes),
        (9, points_h_bytes),
        (8, points_c_bytes),
        (5, points_a_bytes),
        (6, points_b1_bytes),
        (7, points_b2_bytes),
        (10, &section_10),
    ];

    // Write magic "zkey"
    writer.write_all(b"zkey")?;
    // Version
    writer.write_u32::<LittleEndian>(1)?;
    // Number of sections
    writer.write_u32::<LittleEndian>(sections.len() as u32)?;

    // Write each section
    for (id, data) in &sections {
        writer.write_u32::<LittleEndian>(*id)?;
        writer.write_u64::<LittleEndian>(data.len() as u64)?;
        writer.write_all(data)?;
    }

    Ok(())
}

/// Build section 1: prover type header.
///
/// Contains a single u32 identifying the proof system. Value 1 = Groth16.
fn build_header_section() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.write_u32::<LittleEndian>(1).unwrap();
    buf
}

/// Build section 2: Groth16 header with curve parameters and verification key points.
///
/// # Layout
/// ```text
/// n8q: u32 (= 32, bytes per Fq element)
/// q: 32 bytes (base field modulus)
/// n8r: u32 (= 32, bytes per Fr element)
/// r: 32 bytes (scalar field modulus)
/// NVars: u32 (total number of signals)
/// NPub: u32 (number of public inputs, excluding constant "1" wire)
/// DomainSize: u32 (next power of 2 >= num_constraints + n_public + 1)
/// alpha1: 64 bytes (alpha * G1, from ptau ceremony)
/// beta1: 64 bytes (beta * G1, from ptau ceremony)
/// beta2: 128 bytes (beta * G2, from ptau ceremony)
/// gamma2: 128 bytes (G2 generator for _0000 zkey)
/// delta1: 64 bytes (G1 generator for _0000 zkey)
/// delta2: 128 bytes (G2 generator for _0000 zkey)
/// ```
fn build_header_groth_section(
    n_vars: usize,
    n_public: usize,
    domain_size: u32,
    alpha_g1: &[u8], // 64 bytes from ptau
    beta_g1: &[u8],  // 64 bytes from ptau
    beta_g2: &[u8],  // 128 bytes from ptau
    gamma_g2: &[u8], // 128 bytes (G2 generator for _0000 zkey)
    delta_g1: &[u8], // 64 bytes (G1 generator for _0000 zkey)
    delta_g2: &[u8], // 128 bytes (G2 generator for _0000 zkey)
) -> Vec<u8> {
    let mut buf = Vec::new();

    // n8q (bytes per Fq element = 32)
    buf.write_u32::<LittleEndian>(32).unwrap();
    // q (field modulus)
    write_bigint256(&mut buf, &BigInteger256::new(Q));
    // n8r (bytes per Fr element = 32)
    buf.write_u32::<LittleEndian>(32).unwrap();
    // r (scalar field modulus)
    write_bigint256(&mut buf, &BigInteger256::new(R));
    // NVars
    buf.write_u32::<LittleEndian>(n_vars as u32).unwrap();
    // NPub
    buf.write_u32::<LittleEndian>(n_public as u32).unwrap();
    // DomainSize
    buf.write_u32::<LittleEndian>(domain_size).unwrap();
    // VK points
    buf.extend_from_slice(alpha_g1); // alpha1
    buf.extend_from_slice(beta_g1); // beta1
    buf.extend_from_slice(beta_g2); // beta2
    buf.extend_from_slice(gamma_g2); // gamma2
    buf.extend_from_slice(delta_g1); // delta1
    buf.extend_from_slice(delta_g2); // delta2

    buf
}

/// Build section 10: contributions.
///
/// For a `_0000.zkey` (phase 1), this contains only the 64-byte circuit hash
/// (`csHash`, a blake2b-512 digest) followed by a zero contribution count.
/// Phase-2 contributions are appended by `snarkjs zkey contribute`.
fn build_contributions_section(cs_hash: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(cs_hash);
    buf.write_u32::<LittleEndian>(0).unwrap();
    buf
}

/// Build Section 4 (Coefs) -- R1CS coefficients for snarkjs/rapidsnark witness computation.
///
/// # Format
/// ```text
/// num_coeffs: u32 LE
/// For each coefficient:
///   matrix: u32 LE    (0 = A, 1 = B)
///   constraint: u32 LE
///   signal: u32 LE
///   value: 32 bytes   (Fr in R^2 Montgomery form)
/// ```
///
/// Only matrices A and B are stored. Matrix C is implicit from the QAP construction.
///
/// Identity constraints for public signals (0..=n_public) are appended after the R1CS
/// constraints. These encode the identity `1 * signal_s = signal_s` in the A matrix at
/// constraint indices `num_constraints + s`.
///
/// # CRITICAL: R^2 Montgomery encoding
///
/// Coefficient values are stored in **R-squared Montgomery form**: `value * R^2 mod r`,
/// NOT standard Montgomery form (`value * R mod r`). This is a snarkjs convention
/// (see `zkey_new.js` line 330). Getting this wrong produces a zkey that compiles
/// but generates invalid proofs.
pub fn build_coefs_section(constraints: &[Constraints<Fr>], n_public: usize) -> Vec<u8> {
    // Count total coefficients
    let mut total_coeffs = 0u32;
    for c in constraints {
        total_coeffs += c.0.len() as u32; // A
        total_coeffs += c.1.len() as u32; // B
    }
    // Identity constraints for signals 0..n_public (including constant "1" wire)
    total_coeffs += (n_public + 1) as u32;

    let mut buf = Vec::with_capacity(4 + total_coeffs as usize * 44);
    buf.write_u32::<LittleEndian>(total_coeffs).unwrap();

    let n_constraints = constraints.len();
    for (ci, c) in constraints.iter().enumerate() {
        let constraint_idx = ci as u32;
        // A coefficients (matrix = 0)
        for (signal, val) in &c.0 {
            buf.write_u32::<LittleEndian>(0).unwrap();
            buf.write_u32::<LittleEndian>(constraint_idx).unwrap();
            buf.write_u32::<LittleEndian>(*signal as u32).unwrap();
            write_fr_r2(&mut buf, val);
        }
        // B coefficients (matrix = 1)
        for (signal, val) in &c.1 {
            buf.write_u32::<LittleEndian>(1).unwrap();
            buf.write_u32::<LittleEndian>(constraint_idx).unwrap();
            buf.write_u32::<LittleEndian>(*signal as u32).unwrap();
            write_fr_r2(&mut buf, val);
        }
    }

    // Identity constraints for public signals AFTER R1CS constraints
    for s in 0..=n_public {
        buf.write_u32::<LittleEndian>(0).unwrap(); // matrix A
        buf.write_u32::<LittleEndian>((n_constraints + s) as u32)
            .unwrap(); // constraint index
        buf.write_u32::<LittleEndian>(s as u32).unwrap(); // signal index
        write_fr_r2(&mut buf, &Fr::from(1u64)); // value = 1
    }

    buf
}

/// Write an Fr element as 32 little-endian bytes in R^2 Montgomery form.
///
/// # Why R^2 Montgomery?
///
/// snarkjs stores coefficients as `value * R^2 mod r` (see `zkey_new.js` line 330:
/// `nR2 = Fr.mul(n, R2r)`). This is because rapidsnark's witness computation
/// loads these values and expects one Montgomery reduction to arrive at standard
/// Montgomery form (`value * R`).
///
/// # How it works with ark-ff
///
/// In ark-ff, an `Fr` value's internal representation is `standard_value * R` (standard
/// Montgomery form). We need to output `standard_value * R^2`.
///
/// The trick:
/// 1. Extract the internal bigint: `val.0.0` = `standard_value * R` as a plain integer
/// 2. Call `Fr::from_bigint(that_integer)` which treats it as a standard value and
///    multiplies by R internally, giving `(standard_value * R) * R = standard_value * R^2`
/// 3. Write the resulting internal limbs
///
/// This avoids expensive modular exponentiation or explicit R^2 multiplication.
fn write_fr_r2(buf: &mut Vec<u8>, val: &Fr) {
    let vr = BigInteger256::new(val.0 .0); // = std_value * R as BigInteger
    let doubled = Fr::from_bigint(vr).unwrap(); // internal = vr * R = std_value * R^2
    let limbs = &doubled.0 .0;
    for limb in limbs.iter() {
        buf.write_u64::<LittleEndian>(*limb).unwrap();
    }
}

/// Write an Fq element in Montgomery form (raw internal representation).
/// snarkjs and ptau both store Fq elements in Montgomery form.
fn write_fq_montgomery(buf: &mut Vec<u8>, val: &Fq) {
    let limbs = &val.0 .0;
    for limb in limbs.iter() {
        buf.write_u64::<LittleEndian>(*limb).unwrap();
    }
}

/// Write a BigInteger256 as 32 bytes little-endian
fn write_bigint256(buf: &mut Vec<u8>, val: &BigInteger256) {
    for limb in val.0.iter() {
        buf.write_u64::<LittleEndian>(*limb).unwrap();
    }
}
