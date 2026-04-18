// ============================================================================
// ptau_reader.rs — Parse snarkjs Powers of Tau (.ptau) binary files
// ============================================================================
//
// Reads the ptau binary format to extract Lagrange-basis points needed for
// Groth16 zkey generation without random toxic waste.
//
// Key sections read:
//   1: Header (power, ceremony contributions)
//   2: tauG1 monomial basis (fallback source for section 12)
//   3: tauG2 monomial basis (fallback source for section 13)
//   4: alphaTauG1 monomial (alpha*G1 at offset 0, fallback source for section 14)
//   5: betaTauG1 monomial (beta*G1 at offset 0, fallback source for section 15)
//   6: betaTauG2 monomial (beta*G2 at offset 0)
//  12: tauG1 Lagrange basis
//  13: tauG2 Lagrange basis
//  14: alphaTauG1 Lagrange basis
//  15: betaTauG1 Lagrange basis
//
// When sections 13-15 are missing (common with ptau files that haven't been
// processed by `snarkjs powersoftau prepare phase2`), the Lagrange-basis
// points are computed from monomial sections (2-5) via radix-2 IFFT over
// curve points, parallelised with Rayon.
// ============================================================================

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger256, Field, One, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use byteorder::{LittleEndian, ReadBytesExt};
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};

const G1_SIZE: usize = 64;
const G2_SIZE: usize = 128;

struct Section {
    position: u64,
    size: u64,
}

/// Parsed ptau ceremony data needed for Groth16 zkey generation.
///
/// All point data is stored as raw bytes in Montgomery Fq encoding, exactly as
/// they appear in the ptau file. This avoids unnecessary deserialization/reserialization
/// for sections that are copied directly into the zkey (e.g., VK points, H query).
pub struct PtauData {
    pub power: u32,

    // Header VK points (raw Montgomery bytes, ready to write to zkey)
    pub alpha_g1: Vec<u8>,  // 64 bytes — alpha*G1 from section 4
    pub beta_g1: Vec<u8>,   // 64 bytes — beta*G1 from section 5
    pub beta_g2: Vec<u8>,   // 128 bytes — beta*G2 from section 6

    // Lagrange-basis points for the circuit's domain size
    // tauG1[i] = tau^i * G1 in Lagrange basis (section 12)
    pub tau_g1_lagrange: Vec<u8>,       // domain_size * 64 bytes
    // tauG2[i] = tau^i * G2 in Lagrange basis (section 13)
    pub tau_g2_lagrange: Vec<u8>,       // domain_size * 128 bytes
    // alphaTauG1[i] = alpha * tau^i * G1 in Lagrange basis (section 14)
    pub alpha_tau_g1_lagrange: Vec<u8>, // domain_size * 64 bytes
    // betaTauG1[i] = beta * tau^i * G1 in Lagrange basis (section 15)
    pub beta_tau_g1_lagrange: Vec<u8>,  // domain_size * 64 bytes

    // For H query: 2*domain_size tauG1 Lagrange points from the doubled domain (section 12)
    pub tau_g1_lagrange_doubled: Vec<u8>, // 2*domain_size * 64 bytes
}

// ============================================================================
// Montgomery byte encoding helpers (same as main.rs)
// ============================================================================

/// Read an Fq element from 32 LE bytes in Montgomery form.
fn read_fq_montgomery(bytes: &[u8]) -> Fq {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    Fq::new_unchecked(BigInteger256::new(limbs))
}

/// Read a G1 point from raw Montgomery Fq bytes (64 bytes).
fn read_g1_from_bytes(bytes: &[u8]) -> G1Affine {
    let x = read_fq_montgomery(&bytes[0..32]);
    let y = read_fq_montgomery(&bytes[32..64]);
    if x.is_zero() && y.is_zero() {
        G1Affine::identity()
    } else {
        G1Affine::new_unchecked(x, y)
    }
}

/// Read a G2 point from raw Montgomery Fq bytes (128 bytes).
fn read_g2_from_bytes(bytes: &[u8]) -> G2Affine {
    let x_c0 = read_fq_montgomery(&bytes[0..32]);
    let x_c1 = read_fq_montgomery(&bytes[32..64]);
    let y_c0 = read_fq_montgomery(&bytes[64..96]);
    let y_c1 = read_fq_montgomery(&bytes[96..128]);
    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);
    if x.is_zero() && y.is_zero() {
        G2Affine::identity()
    } else {
        G2Affine::new_unchecked(x, y)
    }
}

/// Write a G1Affine point as 64 raw Montgomery bytes.
fn write_g1_bytes(point: &G1Affine) -> Vec<u8> {
    let mut buf = Vec::with_capacity(G1_SIZE);
    if point.is_zero() {
        buf.extend_from_slice(&[0u8; G1_SIZE]);
    } else {
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        write_fq_montgomery_to(&mut buf, &x);
        write_fq_montgomery_to(&mut buf, &y);
    }
    buf
}

/// Write a G2Affine point as 128 raw Montgomery bytes.
fn write_g2_bytes(point: &G2Affine) -> Vec<u8> {
    let mut buf = Vec::with_capacity(G2_SIZE);
    if point.is_zero() {
        buf.extend_from_slice(&[0u8; G2_SIZE]);
    } else {
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        write_fq_montgomery_to(&mut buf, &x.c0);
        write_fq_montgomery_to(&mut buf, &x.c1);
        write_fq_montgomery_to(&mut buf, &y.c0);
        write_fq_montgomery_to(&mut buf, &y.c1);
    }
    buf
}

fn write_fq_montgomery_to(buf: &mut Vec<u8>, val: &Fq) {
    use byteorder::WriteBytesExt;
    for limb in val.0 .0.iter() {
        buf.write_u64::<LittleEndian>(*limb).unwrap();
    }
}

// ============================================================================
// NTT (Number Theoretic Transform) over BN254 curve points
// ============================================================================
//
// These implement radix-2 inverse FFT (IFFT) over G1/G2 projective points.
// The "multiply by twiddle factor" step uses scalar multiplication of a curve
// point by an Fr element, and "add/subtract" are curve point operations.
//
// This converts monomial-basis points (tau^i * G) into Lagrange-basis points.
// ============================================================================

/// Bit-reverse an index within a domain of size 2^log_n.
///
/// Required for the Cooley-Tukey FFT butterfly pattern. For example, with log_n=3:
/// `bit_reverse(1, 3) = 4`, `bit_reverse(3, 3) = 6`.
fn bit_reverse(mut x: usize, log_n: usize) -> usize {
    let mut result = 0usize;
    for _ in 0..log_n {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}

/// In-place radix-2 IFFT over G1 projective points.
///
/// Transforms `n` monomial-basis points `[tau^0 * G1, tau^1 * G1, ..., tau^(n-1) * G1]`
/// into Lagrange-basis points `[L_0(tau) * G1, L_1(tau) * G1, ..., L_(n-1)(tau) * G1]`,
/// where `L_i` are the Lagrange basis polynomials for the domain of n-th roots of unity.
///
/// The "twiddle factors" are powers of `omega_inv` (the inverse of the domain generator),
/// and the final result is scaled by `1/n`. This is the standard inverse DFT, but
/// operating on elliptic curve points instead of field elements: "addition" is curve
/// point addition and "multiplication by twiddle" is scalar multiplication.
///
/// Butterfly operations at each level are parallelized via Rayon when there are
/// enough independent groups (>= 4).
fn ifft_g1(points: &mut [G1Projective]) {
    let n = points.len();
    assert!(n.is_power_of_two(), "domain size must be a power of two");
    let log_n = n.trailing_zeros() as usize;

    // Bit-reverse permutation
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            points.swap(i, j);
        }
    }

    // Get omega_inv from ark-poly domain
    let domain = Radix2EvaluationDomain::<Fr>::new(n).unwrap();
    let omega_inv = domain.group_gen_inv();

    // Butterfly stages
    let mut step = 2;
    while step <= n {
        let half = step / 2;
        let w_step = omega_inv.pow(&[(n / step) as u64]);

        // Precompute twiddle factors for this level
        let twiddles: Vec<Fr> = {
            let mut tw = Vec::with_capacity(half);
            let mut w = Fr::one();
            for _ in 0..half {
                tw.push(w);
                w *= w_step;
            }
            tw
        };

        // Parallelise over independent butterfly groups
        let num_groups = n / step;
        if num_groups >= 4 {
            // Enough groups to benefit from parallelism
            points
                .par_chunks_mut(step)
                .for_each(|chunk| {
                    for i in 0..half {
                        let u = chunk[i];
                        let v = chunk[i + half] * twiddles[i];
                        chunk[i] = u + v;
                        chunk[i + half] = u - v;
                    }
                });
        } else {
            for j in 0..num_groups {
                let base = j * step;
                for i in 0..half {
                    let u = points[base + i];
                    let v = points[base + i + half] * twiddles[i];
                    points[base + i] = u + v;
                    points[base + i + half] = u - v;
                }
            }
        }

        step *= 2;
    }

    // Scale by 1/n
    let n_inv = Fr::from(n as u64).inverse().unwrap();
    points.par_iter_mut().for_each(|p| {
        *p = *p * n_inv;
    });
}

/// In-place radix-2 IFFT over G2 projective points.
///
/// Identical algorithm to `ifft_g1` but operating on G2 points (128 bytes each,
/// over the Fq2 extension field). G2 scalar multiplication is ~3x slower than G1,
/// so this is the bottleneck when computing missing Lagrange sections.
fn ifft_g2(points: &mut [G2Projective]) {
    let n = points.len();
    assert!(n.is_power_of_two(), "domain size must be a power of two");
    let log_n = n.trailing_zeros() as usize;

    // Bit-reverse permutation
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            points.swap(i, j);
        }
    }

    // Get omega_inv from ark-poly domain
    let domain = Radix2EvaluationDomain::<Fr>::new(n).unwrap();
    let omega_inv = domain.group_gen_inv();

    // Butterfly stages
    let mut step = 2;
    while step <= n {
        let half = step / 2;
        let w_step = omega_inv.pow(&[(n / step) as u64]);

        // Precompute twiddle factors for this level
        let twiddles: Vec<Fr> = {
            let mut tw = Vec::with_capacity(half);
            let mut w = Fr::one();
            for _ in 0..half {
                tw.push(w);
                w *= w_step;
            }
            tw
        };

        // Parallelise over independent butterfly groups
        let num_groups = n / step;
        if num_groups >= 4 {
            points
                .par_chunks_mut(step)
                .for_each(|chunk| {
                    for i in 0..half {
                        let u = chunk[i];
                        let v = chunk[i + half] * twiddles[i];
                        chunk[i] = u + v;
                        chunk[i + half] = u - v;
                    }
                });
        } else {
            for j in 0..num_groups {
                let base = j * step;
                for i in 0..half {
                    let u = points[base + i];
                    let v = points[base + i + half] * twiddles[i];
                    points[base + i] = u + v;
                    points[base + i + half] = u - v;
                }
            }
        }

        step *= 2;
    }

    // Scale by 1/n
    let n_inv = Fr::from(n as u64).inverse().unwrap();
    points.par_iter_mut().for_each(|p| {
        *p = *p * n_inv;
    });
}

/// Read `count` G1 points from raw bytes and return as projective points.
fn parse_g1_points(bytes: &[u8], count: usize) -> Vec<G1Projective> {
    (0..count)
        .map(|i| read_g1_from_bytes(&bytes[i * G1_SIZE..]).into_group())
        .collect()
}

/// Read `count` G2 points from raw bytes and return as projective points.
fn parse_g2_points(bytes: &[u8], count: usize) -> Vec<G2Projective> {
    (0..count)
        .map(|i| read_g2_from_bytes(&bytes[i * G2_SIZE..]).into_group())
        .collect()
}

/// Serialize G1 projective points back to raw Montgomery bytes.
fn serialize_g1_points(points: &[G1Projective]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(points.len() * G1_SIZE);
    for p in points {
        buf.extend_from_slice(&write_g1_bytes(&p.into_affine()));
    }
    buf
}

/// Serialize G2 projective points back to raw Montgomery bytes.
fn serialize_g2_points(points: &[G2Projective]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(points.len() * G2_SIZE);
    for p in points {
        buf.extend_from_slice(&write_g2_bytes(&p.into_affine()));
    }
    buf
}

/// Compute Lagrange-basis G1 points from monomial-basis G1 points via IFFT.
///
/// Used when ptau sections 14 or 15 are missing (file not "prepared" for phase 2).
/// Parses raw bytes to projective points, runs the IFFT, then serializes back.
fn compute_lagrange_g1(monomial_bytes: &[u8], domain_size: usize) -> Vec<u8> {
    let mut points = parse_g1_points(monomial_bytes, domain_size);
    ifft_g1(&mut points);
    serialize_g1_points(&points)
}

/// Compute Lagrange-basis G2 points from monomial-basis G2 points via IFFT.
///
/// Used when ptau section 13 is missing. G2 IFFT is significantly slower than G1
/// due to Fq2 arithmetic (each scalar-mul involves operations over the quadratic extension).
fn compute_lagrange_g2(monomial_bytes: &[u8], domain_size: usize) -> Vec<u8> {
    let mut points = parse_g2_points(monomial_bytes, domain_size);
    ifft_g2(&mut points);
    serialize_g2_points(&points)
}

// ============================================================================
// Main ptau reader
// ============================================================================

/// Read a ptau file and extract all data needed for Groth16 zkey generation.
///
/// Parses the snarkjs `.ptau` binary format and extracts:
/// - VK points: alpha*G1, beta*G1, beta*G2 (from sections 4, 5, 6)
/// - Lagrange-basis points for the circuit's domain size (from sections 12-15)
/// - Doubled-domain tauG1 Lagrange points for the H query (from section 12)
///
/// # Automatic Lagrange computation
///
/// If sections 13, 14, or 15 are missing (common with ptau files that haven't been
/// processed by `snarkjs powersoftau prepare phase2`), this function computes the
/// Lagrange-basis points from monomial sections (2-5) via parallel radix-2 IFFT
/// over curve points. This makes `zk-setup` work with raw ceremony output files
/// without a separate preparation step.
///
/// # Section 12 layout
///
/// Section 12 contains tauG1 Lagrange points for every power-of-two domain from
/// 2^1 up to 2^power. The points for domain size `d` start at byte offset
/// `(d - 1) * 64` within the section.
///
/// # Errors
///
/// Returns an error if:
/// - The file is not a valid ptau file (wrong magic bytes)
/// - Required sections are missing (1, 4, 5, 6, 12)
/// - The circuit's domain size exceeds the ptau ceremony's power
pub fn read_ptau<R: Read + Seek>(reader: &mut R, domain_size: usize) -> io::Result<PtauData> {
    // Read magic
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != b"ptau" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid ptau magic"));
    }

    let _version = reader.read_u32::<LittleEndian>()?;
    let num_sections = reader.read_u32::<LittleEndian>()?;

    // Build section index (robust against truncated/corrupt ptau files)
    let mut sections = HashMap::<u32, Section>::new();
    for _ in 0..num_sections {
        let section_id = match reader.read_u32::<LittleEndian>() {
            Ok(id) => id,
            Err(_) => break, // EOF or corrupt — stop parsing sections
        };
        let section_size = match reader.read_u64::<LittleEndian>() {
            Ok(s) => s,
            Err(_) => break,
        };
        let position = reader.stream_position()?;
        // Skip obviously corrupt sections (size > 100 GB)
        if section_size > 100_000_000_000 {
            break;
        }
        sections.insert(section_id, Section { position, size: section_size });
        if reader.seek(SeekFrom::Current(section_size as i64)).is_err() {
            break;
        }
    }

    // Read header (section 1)
    let sec1 = sections.get(&1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Missing ptau section 1 (header)")
    })?;
    reader.seek(SeekFrom::Start(sec1.position))?;
    let n8q = reader.read_u32::<LittleEndian>()?;
    let mut _q = vec![0u8; n8q as usize];
    reader.read_exact(&mut _q)?;
    let power = reader.read_u32::<LittleEndian>()?;
    let _ceremony_power = reader.read_u32::<LittleEndian>()?;

    let cir_power = (domain_size as f64).log2().ceil() as u32;
    if cir_power > power {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Circuit domain {} (power {}) exceeds ptau power {}", domain_size, cir_power, power),
        ));
    }

    // Read alpha*G1 from section 4, offset 0 (first G1 point)
    let sec4 = sections.get(&4).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Missing ptau section 4")
    })?;
    reader.seek(SeekFrom::Start(sec4.position))?;
    let mut alpha_g1 = vec![0u8; G1_SIZE];
    reader.read_exact(&mut alpha_g1)?;

    // Read beta*G1 from section 5, offset 0
    let sec5 = sections.get(&5).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Missing ptau section 5")
    })?;
    reader.seek(SeekFrom::Start(sec5.position))?;
    let mut beta_g1 = vec![0u8; G1_SIZE];
    reader.read_exact(&mut beta_g1)?;

    // Read beta*G2 from section 6, offset 0
    let sec6 = sections.get(&6).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Missing ptau section 6")
    })?;
    reader.seek(SeekFrom::Start(sec6.position))?;
    let mut beta_g2 = vec![0u8; G2_SIZE];
    reader.read_exact(&mut beta_g2)?;

    // Section 12: tauG1 Lagrange basis
    // Layout: lagrange points for domains 2^1, 2^2, ..., 2^power
    // Domain of size 2^k starts at offset (2^k - 1) * G1_SIZE within section 12
    let sec12 = sections.get(&12).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Missing ptau section 12 (tauG1 Lagrange)")
    })?;

    // Read domain_size points for the circuit's domain
    let lagrange_offset = (domain_size - 1) as u64 * G1_SIZE as u64;
    reader.seek(SeekFrom::Start(sec12.position + lagrange_offset))?;
    let mut tau_g1_lagrange = vec![0u8; domain_size * G1_SIZE];
    reader.read_exact(&mut tau_g1_lagrange)?;

    // Read 2*domain_size points for H query (doubled domain)
    let doubled_domain = domain_size * 2;
    let doubled_offset = (doubled_domain - 1) as u64 * G1_SIZE as u64;
    reader.seek(SeekFrom::Start(sec12.position + doubled_offset))?;
    let mut tau_g1_lagrange_doubled = vec![0u8; doubled_domain * G1_SIZE];
    reader.read_exact(&mut tau_g1_lagrange_doubled)?;

    // ========================================================================
    // Sections 13, 14, 15: read if present, otherwise compute via IFFT
    // ========================================================================

    let has_section_13 = sections.get(&13).map_or(false, |s| s.size > 0);
    let has_section_14 = sections.get(&14).map_or(false, |s| s.size > 0);
    let has_section_15 = sections.get(&15).map_or(false, |s| s.size > 0);

    let need_ntt = !has_section_13 || !has_section_14 || !has_section_15;

    if need_ntt {
        eprintln!(
            "[zk-setup] Lagrange sections missing (13={}, 14={}, 15={}), computing via IFFT...",
            if has_section_13 { "present" } else { "MISSING" },
            if has_section_14 { "present" } else { "MISSING" },
            if has_section_15 { "present" } else { "MISSING" },
        );
    }

    // Section 13: tauG2 Lagrange basis
    let tau_g2_lagrange = if has_section_13 {
        let sec13 = sections.get(&13).unwrap();
        let lagrange_offset_g2 = (domain_size - 1) as u64 * G2_SIZE as u64;
        reader.seek(SeekFrom::Start(sec13.position + lagrange_offset_g2))?;
        let mut buf = vec![0u8; domain_size * G2_SIZE];
        reader.read_exact(&mut buf)?;
        buf
    } else {
        eprintln!("[zk-setup] Computing tauG2 Lagrange (section 13) from monomial section 3...");
        let sec3 = sections.get(&3).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Missing ptau section 3 (tauG2 monomial), needed to compute section 13")
        })?;
        reader.seek(SeekFrom::Start(sec3.position))?;
        let mut monomial_bytes = vec![0u8; domain_size * G2_SIZE];
        reader.read_exact(&mut monomial_bytes)?;
        let result = compute_lagrange_g2(&monomial_bytes, domain_size);
        eprintln!("[zk-setup] Section 13 computed ({} G2 points)", domain_size);
        result
    };

    // Section 14: alphaTauG1 Lagrange basis
    let alpha_tau_g1_lagrange = if has_section_14 {
        let sec14 = sections.get(&14).unwrap();
        let lagrange_offset = (domain_size - 1) as u64 * G1_SIZE as u64;
        reader.seek(SeekFrom::Start(sec14.position + lagrange_offset))?;
        let mut buf = vec![0u8; domain_size * G1_SIZE];
        reader.read_exact(&mut buf)?;
        buf
    } else {
        eprintln!("[zk-setup] Computing alphaTauG1 Lagrange (section 14) from monomial section 4...");
        let sec4_full = sections.get(&4).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Missing ptau section 4 (alphaTauG1 monomial), needed to compute section 14")
        })?;
        reader.seek(SeekFrom::Start(sec4_full.position))?;
        let mut monomial_bytes = vec![0u8; domain_size * G1_SIZE];
        reader.read_exact(&mut monomial_bytes)?;
        let result = compute_lagrange_g1(&monomial_bytes, domain_size);
        eprintln!("[zk-setup] Section 14 computed ({} G1 points)", domain_size);
        result
    };

    // Section 15: betaTauG1 Lagrange basis
    let beta_tau_g1_lagrange = if has_section_15 {
        let sec15 = sections.get(&15).unwrap();
        let lagrange_offset = (domain_size - 1) as u64 * G1_SIZE as u64;
        reader.seek(SeekFrom::Start(sec15.position + lagrange_offset))?;
        let mut buf = vec![0u8; domain_size * G1_SIZE];
        reader.read_exact(&mut buf)?;
        buf
    } else {
        eprintln!("[zk-setup] Computing betaTauG1 Lagrange (section 15) from monomial section 5...");
        let sec5_full = sections.get(&5).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Missing ptau section 5 (betaTauG1 monomial), needed to compute section 15")
        })?;
        reader.seek(SeekFrom::Start(sec5_full.position))?;
        let mut monomial_bytes = vec![0u8; domain_size * G1_SIZE];
        reader.read_exact(&mut monomial_bytes)?;
        let result = compute_lagrange_g1(&monomial_bytes, domain_size);
        eprintln!("[zk-setup] Section 15 computed ({} G1 points)", domain_size);
        result
    };

    Ok(PtauData {
        power,
        alpha_g1,
        beta_g1,
        beta_g2,
        tau_g1_lagrange,
        tau_g2_lagrange,
        alpha_tau_g1_lagrange,
        beta_tau_g1_lagrange,
        tau_g1_lagrange_doubled,
    })
}
