//! Dual scalar multiplication implementations for different curve types.
//!
//! This module provides the `DualScalarMultiplication` trait and implementations
//! for both GLV-optimized curves and non-GLV curves.

use alloc::vec;
use alloc::vec::Vec;

#[cfg(feature = "benchmark")]
use std::time::Instant;

use ark_ec::scalar_mul::glv::GLVConfig;
use ark_ec::short_weierstrass::Projective;
use ark_ec::CurveGroup;
use ark_ff::{AdditiveGroup, PrimeField, Zero};

/// Marker trait for curves that don't have GLV endomorphism optimization.
/// Implement this for curves that should use the vanilla Strauss-Shamir algorithm.
pub trait NonGLVCurve: CurveGroup {}

/// Marker trait for BLS curve configs with GLV endomorphism optimization.
/// We need this marker trait because Rust lacks negative trait bounds
/// and won't let us have overlapping blanket impls. GLVConfig already exists
/// but Rust's coherence rules force us to explicitly mark each curve anyway. 😠
pub trait BLSGLVConfig: GLVConfig {}

impl BLSGLVConfig for ark_bls12_381::g1::Config {}
impl BLSGLVConfig for ark_bls12_377::g1::Config {}


/// Trait for dual scalar multiplication (computing a*P + b*Q efficiently).
/// This is used in Chaum-Pedersen signature verification.
pub trait DualScalarMultiplication: CurveGroup {
    fn dual_scalar_mul(
        first_scalar: &Self::ScalarField,
        second_scalar: &Self::ScalarField,
        first_base: &Self,
        second_base: &Self,
        pre_computed_table: Option<&[Self]>,
    ) -> Self;
}

/// Blanket implementation for curves without GLV optimization.
/// Uses vanilla Strauss-Shamir two-point multiplication.
impl<G: NonGLVCurve> DualScalarMultiplication for G {
    fn dual_scalar_mul(
        first_scalar: &Self::ScalarField,
        second_scalar: &Self::ScalarField,
        first_base: &Self,
        second_base: &Self,
        pre_computed_table: Option<&[Self]>,
    ) -> Self {
        #[cfg(feature = "benchmark")]
        let total_start = Instant::now();

        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        let mut res = Self::zero();

        let first_scalar_as_big_int = first_scalar.into_bigint();
        let second_scalar_as_big_int = second_scalar.into_bigint();

        let n1 = first_scalar_as_big_int.as_ref().len() * 64;
        let n2 = second_scalar_as_big_int.as_ref().len() * 64;

        let mut n = if n1 > n2 { n1 } else { n2 };
        #[cfg(feature = "benchmark")]
        println!("[Shamir] scalar_to_bigint: {:?}", start.elapsed());

        // Skip the leading zero bits
        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        while n > 0 {
            n -= 1;
            let part = n / 64;
            let bit = n - (64 * part);
            if n1 > n {
                if first_scalar_as_big_int.as_ref()[part] & (1 << bit) > 0 {
                    break;
                }
            }
            if n2 > n {
                if second_scalar_as_big_int.as_ref()[part] & (1 << bit) > 0 {
                    break;
                }
            }
        }
        #[cfg(feature = "benchmark")]
        println!("[Shamir] skip_leading_zeros: {:?}", start.elapsed());

        if n == 0 {
            return res;
        }

        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        let first_base_plus_second_base = match pre_computed_table {
            Some(table) => match table.len() {
                1 => table[0],
                _ => *first_base + *second_base,
            },
            None => *first_base + *second_base,
        };
        #[cfg(feature = "benchmark")]
        println!("[Shamir] precompute_sum: {:?}", start.elapsed());

        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        n += 1; // n is unsigned so we can't go negative
        while n > 0 {
            n -= 1;
            let part = n / 64;
            let bit = n - (64 * part);
            let first_scalar_bit = if n1 > n {
                first_scalar_as_big_int.as_ref()[part] & (1 << bit) > 0
            } else {
                false
            };
            let second_scalar_bit: bool = if n2 > n {
                second_scalar_as_big_int.as_ref()[part] & (1 << bit) > 0
            } else {
                false
            };

            res.double_in_place();
            if (first_scalar_bit, second_scalar_bit) == (false, false) {
                continue;
            } else {
                res += match (first_scalar_bit, second_scalar_bit) {
                    (true, true) => first_base_plus_second_base,
                    (true, false) => *first_base,
                    (false, true) => *second_base,
                    _ => Self::zero(),
                }
            }
        }
        #[cfg(feature = "benchmark")]
        println!(
            "[Shamir] main_loop ({} bits): {:?}",
            n1.max(n2),
            start.elapsed()
        );

        #[cfg(feature = "benchmark")]
        println!("[Shamir] TOTAL: {:?}", total_start.elapsed());

        res
    }
}

/// Struct for precomputed subset sums for Strauss-Shamir multi-scalar multiplication.
/// The table contains all 2^n subset sums for n points.
/// Not serialized - always recomputed from public keys on deserialization.
#[derive(Debug, Clone)]
pub struct StrausPrecomputedTable<P: CurveGroup> {
    pub table: Vec<P>,
}

impl<C: BLSGLVConfig> StrausPrecomputedTable<Projective<C>> {
    /// Creates a new StrausPrecomputedTable with 256 entries covering all sign combinations.
    /// Each point is GLV-decomposed into two points, giving 4 points total.
    /// With 4 sign choices, we have 16 sign combinations × 16 subset sums = 256 entries.
    ///
    /// Table layout: entries [sign_idx * 16 .. sign_idx * 16 + 16] contain the
    /// subset sum table for sign combination `sign_idx`.
    pub fn new(generator: Projective<C>, public_key: Projective<C>) -> Self {
        // GLV decompose generator: G -> (G, φ(G))
        let gen_affine = generator.into_affine();
        let g_glv: Projective<C> = C::endomorphism_affine(&gen_affine).into();

        // GLV decompose public key: PK -> (PK, φ(PK))
        let pk_affine = public_key.into_affine();
        let pk_glv: Projective<C> = C::endomorphism_affine(&pk_affine).into();

        let points = [generator, g_glv, public_key, pk_glv];

        // Build tables for all 16 sign combinations
        let mut table = Vec::with_capacity(256);
        for sign_idx in 0..16u8 {
            let signed_points = [
                if sign_idx & 1 == 0 {
                    points[0]
                } else {
                    -points[0]
                },
                if sign_idx & 2 == 0 {
                    points[1]
                } else {
                    -points[1]
                },
                if sign_idx & 4 == 0 {
                    points[2]
                } else {
                    -points[2]
                },
                if sign_idx & 8 == 0 {
                    points[3]
                } else {
                    -points[3]
                },
            ];
            let subset_table = Self::precompute_sums(&signed_points);
            table.extend(subset_table.table);
        }

        Self { table }
    }

    /// Precomputes sums of all subsets of the list of `points` for Strauss-Shamir.
    /// For n points, this creates a table of 2^n elements indexed by n-bit patterns.
    pub fn precompute_sums(points: &[Projective<C>]) -> Self {
        let mut table = vec![Projective::<C>::zero()];
        for p in points {
            let new_rows: Vec<Projective<C>> = table.iter().map(|&prev| prev + *p).collect();
            table.extend(new_rows);
        }
        Self { table }
    }
}

/// Computes the sign index from scalar decomposition signs.
/// sign=true means positive (bit=0), sign=false means negative (bit=1).
#[inline]
pub fn glv_sign_index(sgn_s1_1: bool, sgn_s1_2: bool, sgn_s2_1: bool, sgn_s2_2: bool) -> usize {
    let bit0 = if sgn_s1_1 { 0 } else { 1 };
    let bit1 = if sgn_s1_2 { 0 } else { 2 };
    let bit2 = if sgn_s2_1 { 0 } else { 4 };
    let bit3 = if sgn_s2_2 { 0 } else { 8 };
    bit0 | bit1 | bit2 | bit3
}

/// GLV-optimized implementation of DualScalarMultiplication for curves with GLV endomorphism.
/// This uses GLV decomposition to split scalars and perform 4-scalar multiplication
/// with a precomputed table for better performance.
impl<C: BLSGLVConfig> DualScalarMultiplication for Projective<C> {
    fn dual_scalar_mul(
        first_scalar: &Self::ScalarField,
        second_scalar: &Self::ScalarField,
        first_base: &Self,
        second_base: &Self,
        pre_computed_table: Option<&[Self]>,
    ) -> Self {
        #[cfg(feature = "benchmark")]
        let total_start = Instant::now();

        // GLV decompose both scalars
        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        let ((sgn_s1_1, s1_1), (sgn_s1_2, s1_2)) = C::scalar_decomposition(*first_scalar);
        let ((sgn_s2_1, s2_1), (sgn_s2_2, s2_2)) = C::scalar_decomposition(*second_scalar);
        #[cfg(feature = "benchmark")]
        println!("[GLV] scalar_decomposition: {:?}", start.elapsed());

        // Build or use precomputed table for 4 points
        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        let owned_table;
        let table: &[Self] = match pre_computed_table {
            Some(t) if t.len() == 256 => {
                // Use precomputed 256-element table: select correct 16-element slice by sign index
                #[cfg(feature = "benchmark")]
                println!("[GLV] using precomputed 256-element table");
                let sign_idx = glv_sign_index(sgn_s1_1, sgn_s1_2, sgn_s2_1, sgn_s2_2);
                &t[sign_idx * 16..(sign_idx + 1) * 16]
            }
            _ => {
                // Compute 16-element table at runtime with correct signs
                #[cfg(feature = "benchmark")]
                println!("[GLV] computing 16-element table at runtime");
                let first_affine = first_base.into_affine();
                let second_affine = second_base.into_affine();

                let mut p1_1 = *first_base;
                let mut p1_2: Self = C::endomorphism_affine(&first_affine).into();
                let mut p2_1 = *second_base;
                let mut p2_2: Self = C::endomorphism_affine(&second_affine).into();

                if !sgn_s1_1 {
                    p1_1 = -p1_1;
                }
                if !sgn_s1_2 {
                    p1_2 = -p1_2;
                }
                if !sgn_s2_1 {
                    p2_1 = -p2_1;
                }
                if !sgn_s2_2 {
                    p2_2 = -p2_2;
                }

                let points = [p1_1, p1_2, p2_1, p2_2];
                owned_table = StrausPrecomputedTable::precompute_sums(&points).table;
                &owned_table
            }
        };
        #[cfg(feature = "benchmark")]
        println!("[GLV] table_setup: {:?}", start.elapsed());

        // Convert scalars to big integers for bit access
        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        let s1_1_bits = s1_1.into_bigint();
        let s1_2_bits = s1_2.into_bigint();
        let s2_1_bits = s2_1.into_bigint();
        let s2_2_bits = s2_2.into_bigint();

        // Get bit lengths
        let n1 = s1_1_bits.as_ref().len() * 64;
        let n2 = s1_2_bits.as_ref().len() * 64;
        let n3 = s2_1_bits.as_ref().len() * 64;
        let n4 = s2_2_bits.as_ref().len() * 64;
        #[cfg(feature = "benchmark")]
        println!("[GLV] scalar_to_bigint: {:?}", start.elapsed());

        let mut n = core::cmp::max(core::cmp::max(n1, n2), core::cmp::max(n3, n4));

        // Skip the leading zero bits
        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        while n > 0 {
            n -= 1;
            let part = n / 64;
            let bit = n - (64 * part);
            if (n1 > n && s1_1_bits.as_ref()[part] & (1 << bit) > 0)
                || (n2 > n && s1_2_bits.as_ref()[part] & (1 << bit) > 0)
                || (n3 > n && s2_1_bits.as_ref()[part] & (1 << bit) > 0)
                || (n4 > n && s2_2_bits.as_ref()[part] & (1 << bit) > 0)
            {
                break;
            }
        }
        #[cfg(feature = "benchmark")]
        println!("[GLV] skip_leading_zeros: {:?}", start.elapsed());

        if n == 0 {
            return Self::zero();
        }

        let mut res = Self::zero();

        // Straus-Shamir with 4 scalars using precomputed table
        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        #[cfg(feature = "benchmark")]
        let loop_bits = n;
        n += 1; // n is unsigned so we can't go negative
        while n > 0 {
            n -= 1;
            let part = n / 64;
            let bit = n - (64 * part);

            // Build 4-bit index from current bits of all 4 scalars
            let bit0 = if n1 > n && s1_1_bits.as_ref()[part] & (1 << bit) > 0 {
                1
            } else {
                0
            };
            let bit1 = if n2 > n && s1_2_bits.as_ref()[part] & (1 << bit) > 0 {
                2
            } else {
                0
            };
            let bit2 = if n3 > n && s2_1_bits.as_ref()[part] & (1 << bit) > 0 {
                4
            } else {
                0
            };
            let bit3 = if n4 > n && s2_2_bits.as_ref()[part] & (1 << bit) > 0 {
                8
            } else {
                0
            };
            let idx = bit0 | bit1 | bit2 | bit3;

            res.double_in_place();
            if idx != 0 {
                res += table[idx];
            }
        }
        #[cfg(feature = "benchmark")]
        println!(
            "[GLV] main_loop ({} bits): {:?}",
            loop_bits,
            start.elapsed()
        );

        #[cfg(feature = "benchmark")]
        println!("[GLV] TOTAL: {:?}", total_start.elapsed());

        res
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ark_ec::short_weierstrass::Projective;
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    impl NonGLVCurve for ark_sw_by_bls12_381::SWProjective {}

    // --- glv_sign_index tests ---

    #[test]
    fn test_glv_sign_index_all_positive() {
        assert_eq!(glv_sign_index(true, true, true, true), 0);
    }

    #[test]
    fn test_glv_sign_index_all_negative() {
        assert_eq!(glv_sign_index(false, false, false, false), 15);
    }

    #[test]
    fn test_glv_sign_index_individual_bits() {
        // Only first scalar component negative
        assert_eq!(glv_sign_index(false, true, true, true), 1);
        // Only second scalar component negative
        assert_eq!(glv_sign_index(true, false, true, true), 2);
        // Only third scalar component negative
        assert_eq!(glv_sign_index(true, true, false, true), 4);
        // Only fourth scalar component negative
        assert_eq!(glv_sign_index(true, true, true, false), 8);
    }

    #[test]
    fn test_glv_sign_index_mixed() {
        // First and third negative
        assert_eq!(glv_sign_index(false, true, false, true), 5);
        // Second and fourth negative
        assert_eq!(glv_sign_index(true, false, true, false), 10);
    }

    // --- StrausPrecomputedTable tests ---

    #[test]
    fn test_precompute_sums_table_size() {
        type G1 = Projective<ark_bls12_381::g1::Config>;
        let g = G1::generator();
        let points = [g, g + g];
        let table = StrausPrecomputedTable::precompute_sums(&points);
        // 2 points => 2^2 = 4 entries
        assert_eq!(table.table.len(), 4);
    }

    #[test]
    fn test_precompute_sums_identity_at_zero() {
        type G1 = Projective<ark_bls12_381::g1::Config>;
        let g = G1::generator();
        let points = [g, g + g, g + g + g];
        let table = StrausPrecomputedTable::precompute_sums(&points);
        // 3 points => 2^3 = 8 entries
        assert_eq!(table.table.len(), 8);
        // Index 0 should be identity
        assert!(table.table[0].is_zero());
    }

    #[test]
    fn test_precompute_sums_single_point() {
        type G1 = Projective<ark_bls12_381::g1::Config>;
        let g = G1::generator();
        let table = StrausPrecomputedTable::precompute_sums(&[g]);
        // 1 point => 2^1 = 2 entries: [0, g]
        assert_eq!(table.table.len(), 2);
        assert!(table.table[0].is_zero());
        assert_eq!(table.table[1], g);
    }

    #[test]
    fn test_precompute_sums_subset_correctness() {
        type G1 = Projective<ark_bls12_381::g1::Config>;
        let rng = &mut thread_rng();
        let p = G1::rand(rng);
        let q = G1::rand(rng);
        let table = StrausPrecomputedTable::precompute_sums(&[p, q]);
        // table[0] = 0, table[1] = p, table[2] = q, table[3] = p+q
        assert!(table.table[0].is_zero());
        assert_eq!(table.table[1], p);
        assert_eq!(table.table[2], q);
        assert_eq!(table.table[3], p + q);
    }

    #[test]
    fn test_straus_precomputed_table_new_has_256_entries() {
        type G1 = Projective<ark_bls12_381::g1::Config>;
        let rng = &mut thread_rng();
        let g = G1::generator();
        let pk = G1::rand(rng);
        let table = StrausPrecomputedTable::new(g, pk);
        assert_eq!(table.table.len(), 256);
    }

    #[test]
    fn test_straus_precomputed_table_new_first_slice_has_identity() {
        type G1 = Projective<ark_bls12_381::g1::Config>;
        let rng = &mut thread_rng();
        let g = G1::generator();
        let pk = G1::rand(rng);
        let table = StrausPrecomputedTable::new(g, pk);
        // First 16-element slice (sign_idx=0, all positive) should have identity at index 0
        assert!(table.table[0].is_zero());
    }

    // --- NonGLVCurve dual_scalar_mul tests ---

    #[test]
    #[cfg(feature = "experimental")]
    fn test_non_glv_dual_scalar_mul_zero_scalars() {
        type SW = ark_sw_by_bls12_381::SWProjective;
        let rng = &mut thread_rng();
        let p = SW::rand(rng);
        let q = SW::rand(rng);
        let zero = <SW as PrimeGroup>::ScalarField::from(0u64);

        let result = SW::dual_scalar_mul(&zero, &zero, &p, &q, None);
        assert!(result.is_zero());
    }

    #[test]
    #[cfg(feature = "experimental")]
    fn test_non_glv_dual_scalar_mul_single_scalar() {
        type SW = ark_sw_by_bls12_381::SWProjective;
        let rng = &mut thread_rng();
        let p = SW::rand(rng);
        let q = SW::rand(rng);
        let a = <SW as PrimeGroup>::ScalarField::rand(rng);
        let zero = <SW as PrimeGroup>::ScalarField::from(0u64);

        // a*P + 0*Q == a*P
        let result = SW::dual_scalar_mul(&a, &zero, &p, &q, None);
        assert_eq!(result, p * a);

        // 0*P + a*Q == a*Q
        let result = SW::dual_scalar_mul(&zero, &a, &p, &q, None);
        assert_eq!(result, q * a);
    }

    #[test]
    #[cfg(feature = "experimental")]
    fn test_non_glv_dual_scalar_mul_correctness() {
        type SW = ark_sw_by_bls12_381::SWProjective;
        let rng = &mut thread_rng();
        let p = SW::rand(rng);
        let q = SW::rand(rng);
        let a = <SW as PrimeGroup>::ScalarField::rand(rng);
        let b = <SW as PrimeGroup>::ScalarField::rand(rng);

        let result = SW::dual_scalar_mul(&a, &b, &p, &q, None);
        let expected = p * a + q * b;
        assert_eq!(result, expected);
    }

    #[test]
    #[cfg(feature = "experimental")]
    fn test_non_glv_dual_scalar_mul_with_precomputed_table() {
        type SW = ark_sw_by_bls12_381::SWProjective;
        let rng = &mut thread_rng();
        let p = SW::rand(rng);
        let q = SW::rand(rng);
        let a = <SW as PrimeGroup>::ScalarField::rand(rng);
        let b = <SW as PrimeGroup>::ScalarField::rand(rng);

        // With a 1-element table (P+Q precomputed)
        let p_plus_q = p + q;
        let result = SW::dual_scalar_mul(&a, &b, &p, &q, Some(&[p_plus_q]));
        let expected = p * a + q * b;
        assert_eq!(result, expected);
    }

    // --- GLV curve dual_scalar_mul tests ---

    #[test]
    fn test_glv_dual_scalar_mul_correctness_no_table() {
        type G1 = Projective<ark_bls12_381::g1::Config>;
        let rng = &mut thread_rng();
        let p = G1::rand(rng);
        let q = G1::rand(rng);
        let a = <G1 as PrimeGroup>::ScalarField::rand(rng);
        let b = <G1 as PrimeGroup>::ScalarField::rand(rng);

        let result = G1::dual_scalar_mul(&a, &b, &p, &q, None);
        let expected = p * a + q * b;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_glv_dual_scalar_mul_with_precomputed_256_table() {
        type G1 = Projective<ark_bls12_381::g1::Config>;
        let rng = &mut thread_rng();
        let p = G1::generator();
        let q = G1::rand(rng);
        let a = <G1 as PrimeGroup>::ScalarField::rand(rng);
        let b = <G1 as PrimeGroup>::ScalarField::rand(rng);

        let table = StrausPrecomputedTable::new(p, q);
        assert_eq!(table.table.len(), 256);

        let result = G1::dual_scalar_mul(&a, &b, &p, &q, Some(&table.table));
        let expected = p * a + q * b;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_glv_dual_scalar_mul_precomputed_matches_runtime() {
        type G1 = Projective<ark_bls12_381::g1::Config>;
        let rng = &mut thread_rng();
        let p = G1::generator();
        let q = G1::rand(rng);
        let a = <G1 as PrimeGroup>::ScalarField::rand(rng);
        let b = <G1 as PrimeGroup>::ScalarField::rand(rng);

        let table = StrausPrecomputedTable::new(p, q);

        let result_with_table = G1::dual_scalar_mul(&a, &b, &p, &q, Some(&table.table));
        let result_without_table = G1::dual_scalar_mul(&a, &b, &p, &q, None);
        assert_eq!(result_with_table, result_without_table);
    }

    #[test]
    fn test_glv_dual_scalar_mul_zero_scalars() {
        type G1 = Projective<ark_bls12_381::g1::Config>;
        let rng = &mut thread_rng();
        let p = G1::rand(rng);
        let q = G1::rand(rng);
        let zero = <G1 as PrimeGroup>::ScalarField::from(0u64);

        let result = G1::dual_scalar_mul(&zero, &zero, &p, &q, None);
        assert!(result.is_zero());
    }

    #[test]
    fn test_glv_dual_scalar_mul_bls12_377() {
        type G1 = Projective<ark_bls12_377::g1::Config>;
        let rng = &mut thread_rng();
        let p = G1::rand(rng);
        let q = G1::rand(rng);
        let a = <G1 as PrimeGroup>::ScalarField::rand(rng);
        let b = <G1 as PrimeGroup>::ScalarField::rand(rng);

        let result = G1::dual_scalar_mul(&a, &b, &p, &q, None);
        let expected = p * a + q * b;
        assert_eq!(result, expected);
    }
}
