use ark_algebra_bench_templates::*;
use ark_sw_by_bls12_381::{SWProjective as G, fq::Fq, fr::Fr};

bench!(
    Name = "SWByBls12_381",
    Group = G,
    ScalarField = Fr,
    PrimeBaseField = Fq,
);
