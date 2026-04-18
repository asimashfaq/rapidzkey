// ============================================================================
// msm_fast.rs — Parallel constraint-driven point accumulation
// ============================================================================
//
// Splits constraints into chunks processed in parallel by Rayon. Each thread
// accumulates into its own per-signal buffers, then results are merged.
// O(total_nonzero_entries / num_threads) wall-clock time.
// ============================================================================

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use rayon::prelude::*;

const G1_SIZE: usize = 64;
const G2_SIZE: usize = 128;

/// Computed proving key section data, ready to write into the zkey file.
///
/// All byte vectors contain curve points serialized in Montgomery Fq form
/// (64 bytes per G1 point, 128 bytes per G2 point).
pub struct SectionPoints {
    /// Section 3: IC / gamma_abc_g1 points. (n_public + 1) G1 points.
    pub ic_bytes: Vec<u8>,
    /// Section 5: A query. n_vars G1 points.
    pub points_a_bytes: Vec<u8>,
    /// Section 6: B1 query. n_vars G1 points.
    pub points_b1_bytes: Vec<u8>,
    /// Section 7: B2 query. n_vars G2 points.
    pub points_b2_bytes: Vec<u8>,
    /// Section 8: C/L query. (n_vars - n_public - 1) G1 points.
    pub points_c_bytes: Vec<u8>,
}

/// Per-thread accumulation buffers for all zkey sections.
///
/// Each thread maintains its own set of projective-coordinate accumulators,
/// one per signal per section. After all constraints in the thread's chunk
/// are processed, these are merged across threads via point addition.
///
/// Using projective coordinates avoids expensive inversions during accumulation;
/// conversion to affine only happens once during final serialization.
struct ThreadAccum {
    a: Vec<G1Projective>,
    b1: Vec<G1Projective>,
    b2: Vec<G2Projective>,
    ic: Vec<G1Projective>,
    c: Vec<G1Projective>,
}

impl ThreadAccum {
    fn new(n_vars: usize, n_public: usize) -> Self {
        Self {
            a: vec![G1Projective::zero(); n_vars],
            b1: vec![G1Projective::zero(); n_vars],
            b2: vec![G2Projective::zero(); n_vars],
            ic: vec![G1Projective::zero(); n_public + 1],
            c: vec![G1Projective::zero(); n_vars - n_public - 1],
        }
    }

    /// Merge another thread's results into self.
    fn merge(&mut self, other: &ThreadAccum) {
        for i in 0..self.a.len() {
            self.a[i] += other.a[i];
        }
        for i in 0..self.b1.len() {
            self.b1[i] += other.b1[i];
        }
        for i in 0..self.b2.len() {
            self.b2[i] += other.b2[i];
        }
        for i in 0..self.ic.len() {
            self.ic[i] += other.ic[i];
        }
        for i in 0..self.c.len() {
            self.c[i] += other.c[i];
        }
    }
}

/// Compute all proving key sections (3, 5, 6, 7, 8) via parallel constraint-driven accumulation.
///
/// This is the core computation of the tool. Instead of computing one multi-scalar
/// multiplication (MSM) per signal (which has O(n_vars) overhead and poor locality),
/// this iterates over constraints and scatters weighted curve points into per-signal
/// accumulators.
///
/// # Algorithm
///
/// 1. Split constraints into `num_threads` chunks
/// 2. Each thread processes its chunk, accumulating `coef * base_point[constraint_index]`
///    into the appropriate signal's buffer for each non-zero R1CS entry
/// 3. Merge all thread-local accumulators via point addition
/// 4. Add identity constraints for public signals
/// 5. Convert from projective to affine and serialize
///
/// # Arguments
///
/// - `constraints` -- R1CS constraint triples (A, B, C), each a sparse vector of (signal, coefficient)
/// - `n_vars` -- Total number of signals in the circuit
/// - `n_public` -- Number of public inputs (excluding the constant "1" wire at index 0)
/// - `num_constraints` -- Number of R1CS constraints
/// - `tau_g1` -- Lagrange-basis tau*G1 points from ptau ceremony (domain_size points)
/// - `tau_g2` -- Lagrange-basis tau*G2 points from ptau ceremony (domain_size points)
/// - `alpha_tau_g1` -- Lagrange-basis alpha*tau*G1 points (domain_size points)
/// - `beta_tau_g1` -- Lagrange-basis beta*tau*G1 points (domain_size points)
pub fn compute_all_sections_fast(
    constraints: &[(Vec<(usize, Fr)>, Vec<(usize, Fr)>, Vec<(usize, Fr)>)],
    n_vars: usize,
    n_public: usize,
    num_constraints: usize,
    tau_g1: &[G1Affine],
    tau_g2: &[G2Affine],
    alpha_tau_g1: &[G1Affine],
    beta_tau_g1: &[G1Affine],
) -> SectionPoints {
    let n_threads = rayon::current_num_threads();
    let chunk_size = num_constraints.div_ceil(n_threads);

    eprintln!(
        "[zk-setup]   Parallel accumulation: {} threads, {} constraints/chunk",
        n_threads, chunk_size
    );

    // Process constraint chunks in parallel
    let thread_results: Vec<ThreadAccum> = constraints
        .par_chunks(chunk_size)
        .enumerate()
        .map(|(chunk_idx, chunk)| {
            let base_ci = chunk_idx * chunk_size;
            let mut acc = ThreadAccum::new(n_vars, n_public);

            for (local_ci, (a_terms, b_terms, c_terms)) in chunk.iter().enumerate() {
                let ci = base_ci + local_ci;

                let tau_g1_ci = tau_g1[ci];
                let tau_g2_ci = tau_g2[ci];
                let alpha_ci = alpha_tau_g1[ci];
                let beta_ci = beta_tau_g1[ci];

                // A matrix
                for (signal, coef) in a_terms {
                    let s = *signal;
                    let cb = coef.into_bigint();
                    acc.a[s] += tau_g1_ci.mul_bigint(cb);
                    if s <= n_public {
                        acc.ic[s] += beta_ci.mul_bigint(cb);
                    } else {
                        acc.c[s - n_public - 1] += beta_ci.mul_bigint(cb);
                    }
                }

                // B matrix
                for (signal, coef) in b_terms {
                    let s = *signal;
                    let cb = coef.into_bigint();
                    acc.b1[s] += tau_g1_ci.mul_bigint(cb);
                    acc.b2[s] += tau_g2_ci.mul_bigint(cb);
                    if s <= n_public {
                        acc.ic[s] += alpha_ci.mul_bigint(cb);
                    } else {
                        acc.c[s - n_public - 1] += alpha_ci.mul_bigint(cb);
                    }
                }

                // C matrix
                for (signal, coef) in c_terms {
                    let s = *signal;
                    let cb = coef.into_bigint();
                    if s <= n_public {
                        acc.ic[s] += tau_g1_ci.mul_bigint(cb);
                    } else {
                        acc.c[s - n_public - 1] += tau_g1_ci.mul_bigint(cb);
                    }
                }
            }

            if chunk_idx == 0 || (chunk_idx + 1) % 4 == 0 {
                eprintln!(
                    "[zk-setup]   chunk {}/{} done",
                    chunk_idx + 1,
                    num_constraints.div_ceil(chunk_size)
                );
            }

            acc
        })
        .collect();

    eprintln!(
        "[zk-setup]   Merging {} thread results...",
        thread_results.len()
    );

    // Merge all thread results
    let mut final_acc = ThreadAccum::new(n_vars, n_public);
    for t in &thread_results {
        final_acc.merge(t);
    }

    // Identity constraints for public signals
    for s in 0..=n_public {
        let ci = num_constraints + s;
        final_acc.a[s] += G1Projective::from(tau_g1[ci]);
        final_acc.ic[s] += G1Projective::from(beta_tau_g1[ci]);
    }

    eprintln!("[zk-setup]   Serializing points...");

    // Serialize in parallel
    let ic_bytes = serialize_g1_par(&final_acc.ic);
    let points_a_bytes = serialize_g1_par(&final_acc.a);
    let points_b1_bytes = serialize_g1_par(&final_acc.b1);
    let points_b2_bytes = serialize_g2_par(&final_acc.b2);
    let points_c_bytes = serialize_g1_par(&final_acc.c);

    SectionPoints {
        ic_bytes,
        points_a_bytes,
        points_b1_bytes,
        points_b2_bytes,
        points_c_bytes,
    }
}

/// Convert projective G1 points to affine (in parallel) and serialize to Montgomery bytes.
fn serialize_g1_par(points: &[G1Projective]) -> Vec<u8> {
    let affine: Vec<G1Affine> = points.par_iter().map(|p| p.into_affine()).collect();
    let mut buf = Vec::with_capacity(affine.len() * G1_SIZE);
    for p in &affine {
        write_g1_to(&mut buf, p);
    }
    buf
}

/// Convert projective G2 points to affine (in parallel) and serialize to Montgomery bytes.
fn serialize_g2_par(points: &[G2Projective]) -> Vec<u8> {
    let affine: Vec<G2Affine> = points.par_iter().map(|p| p.into_affine()).collect();
    let mut buf = Vec::with_capacity(affine.len() * G2_SIZE);
    for p in &affine {
        write_g2_to(&mut buf, p);
    }
    buf
}

/// Write a G1 affine point as 64 raw Montgomery bytes (x, y as 4 LE u64 limbs each).
fn write_g1_to(buf: &mut Vec<u8>, point: &G1Affine) {
    use byteorder::{LittleEndian, WriteBytesExt};
    if point.is_zero() {
        buf.extend_from_slice(&[0u8; G1_SIZE]);
    } else {
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        for limb in x.0 .0.iter() {
            buf.write_u64::<LittleEndian>(*limb).unwrap();
        }
        for limb in y.0 .0.iter() {
            buf.write_u64::<LittleEndian>(*limb).unwrap();
        }
    }
}

/// Write a G2 affine point as 128 raw Montgomery bytes (x.c0, x.c1, y.c0, y.c1).
fn write_g2_to(buf: &mut Vec<u8>, point: &G2Affine) {
    use byteorder::{LittleEndian, WriteBytesExt};
    if point.is_zero() {
        buf.extend_from_slice(&[0u8; G2_SIZE]);
    } else {
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        for limb in x.c0.0 .0.iter() {
            buf.write_u64::<LittleEndian>(*limb).unwrap();
        }
        for limb in x.c1.0 .0.iter() {
            buf.write_u64::<LittleEndian>(*limb).unwrap();
        }
        for limb in y.c0.0 .0.iter() {
            buf.write_u64::<LittleEndian>(*limb).unwrap();
        }
        for limb in y.c1.0 .0.iter() {
            buf.write_u64::<LittleEndian>(*limb).unwrap();
        }
    }
}
