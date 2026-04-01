use ark_algebra_bench_templates::*;
use ark_ed_by_bls12_381::{fq::Fq, fr::Fr, EdwardsProjective as G};

bench!(
    Name = "EdByBls12_381",
    Group = G,
    ScalarField = Fr,
    PrimeBaseField = Fq,
);
