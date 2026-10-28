use ark_algebra_bench_templates::*;
use ark_ed_by_bls12_381::{EdwardsProjective as G, fq::Fq, fr::Fr};

bench!(
    Name = "EdByBls12_381",
    Group = G,
    ScalarField = Fr,
    PrimeBaseField = Fq,
);
