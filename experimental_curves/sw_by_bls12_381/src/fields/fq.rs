use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use ark_std::convert::TryInto;
//sage: q = 52435875175126190479447740508185965837256304113503012511244875124696220556829F
//sage: Fq = GF(q)
//sage: two = Fq(2)
//sage: two.multiplicative_order()
//52435875175126190479447740508185965837256304113503012511244875124696220556828
//sage: factor(two.multiplicative_order())
//2^2 * 3 * 11 * 2304037 * 2695806557 * 63955281582005849408086532907918123933177856853934647284631
#[derive(MontConfig)]
#[modulus = "52435875175126190479447740508185965837256304113503012511244875124696220556829"]
#[generator = "2"]
#[small_subgroup_base = "2"]
#[small_subgroup_power = "2"]
pub struct FqConfig;
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;
