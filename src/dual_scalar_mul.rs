//! Dual scalar multiplication implementations for different curve types.
//!
//! This module provides the `DualScalarMultiplication` trait and implementations
//! for both GLV-optimized curves and non-GLV curves.

use alloc::vec;
use alloc::vec::Vec;

use ark_ec::scalar_mul::glv::GLVConfig;
use ark_ec::short_weierstrass::Projective;
use ark_ec::CurveGroup;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, Zero};

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
        let mut res = Self::zero();

        let first_scalar_as_big_int = first_scalar.into_bigint();
        let second_scalar_as_big_int = second_scalar.into_bigint();

        let n1 = first_scalar_as_big_int.as_ref().len() * 64;
        let n2 = second_scalar_as_big_int.as_ref().len() * 64;

        let mut n = if n1 > n2 { n1 } else { n2 };

        // Skip the leading zero bits
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

        if n == 0 {
            return res;
        }

        let first_base_plus_second_base = match pre_computed_table {
            Some(table) => match table.len() {
                1 => table[0],
                _ => *first_base + *second_base,
            },
            None => *first_base + *second_base,
        };

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
    /// Creates a new StrausPrecomputedTable by precomputing the table
    /// for the GLV-decomposed generator and public key points.
    /// Each point is decomposed into two GLV points, giving 4 points total.
    /// The table has 2^4 = 16 entries for all subset sums.
    pub fn new(generator: Projective<C>, public_key: Projective<C>) -> Self {
        // GLV decompose generator: G -> (G, φ(G))
        let gen_affine = generator.into_affine();
        let gen_glv: Projective<C> = C::endomorphism_affine(&gen_affine).into();

        // GLV decompose public key: PK -> (PK, φ(PK))
        let pk_affine = public_key.into_affine();
        let pk_glv: Projective<C> = C::endomorphism_affine(&pk_affine).into();

        // Build table for 4 points: [G, φ(G), PK, φ(PK)]
        Self::precompute_sums(&[generator, gen_glv, public_key, pk_glv])
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
        // GLV decompose both scalars
        let ((sgn_s1_1, s1_1), (sgn_s1_2, s1_2)) = C::scalar_decomposition(*first_scalar);
        let ((sgn_s2_1, s2_1), (sgn_s2_2, s2_2)) = C::scalar_decomposition(*second_scalar);

        // GLV decompose both base points
        let first_affine = first_base.into_affine();
        let second_affine = second_base.into_affine();

        let mut p1_1 = *first_base;
        let mut p1_2: Self = C::endomorphism_affine(&first_affine).into();
        let mut p2_1 = *second_base;
        let mut p2_2: Self = C::endomorphism_affine(&second_affine).into();

        // Apply signs from scalar decomposition
        if !sgn_s1_1 { p1_1 = -p1_1; }
        if !sgn_s1_2 { p1_2 = -p1_2; }
        if !sgn_s2_1 { p2_1 = -p2_1; }
        if !sgn_s2_2 { p2_2 = -p2_2; }

        // Build or use precomputed table for 4 points (16 entries for GLV)
        // Only allocate if the provided table is missing or wrong size
        let owned_table;
        let table: &[Self] = match pre_computed_table {
            Some(t) if t.len() == 16 => t,
            _ => {
                let points = [p1_1, p1_2, p2_1, p2_2];
                owned_table = StrausPrecomputedTable::precompute_sums(&points).table;
                &owned_table
            }
        };

        // Convert scalars to big integers for bit access
        let s1_1_bits = s1_1.into_bigint();
        let s1_2_bits = s1_2.into_bigint();
        let s2_1_bits = s2_1.into_bigint();
        let s2_2_bits = s2_2.into_bigint();

        // Find max bit length
        let max_bits = core::cmp::max(
            core::cmp::max(s1_1_bits.num_bits(), s1_2_bits.num_bits()),
            core::cmp::max(s2_1_bits.num_bits(), s2_2_bits.num_bits()),
        ) as usize;

        if max_bits == 0 {
            return Self::zero();
        }

        let mut res = Self::zero();

        // Straus-Shamir with 4 scalars using precomputed table
        for i in (0..max_bits).rev() {
            res.double_in_place();

            // Build 4-bit index from current bits of all 4 scalars
            let bit0 = if s1_1_bits.get_bit(i) { 1 } else { 0 };
            let bit1 = if s1_2_bits.get_bit(i) { 2 } else { 0 };
            let bit2 = if s2_1_bits.get_bit(i) { 4 } else { 0 };
            let bit3 = if s2_2_bits.get_bit(i) { 8 } else { 0 };
            let idx = bit0 | bit1 | bit2 | bit3;

            if idx != 0 {
                res += table[idx];
            }
        }

        res
    }
}

