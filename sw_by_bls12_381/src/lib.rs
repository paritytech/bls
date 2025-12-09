#![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    warnings,
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms
)]
#![forbid(unsafe_code)]

//! This library implements a prime order weirestrass curve whose scalar field is the
//! scalar field of the curve BLS12-381.
//!
mod curves;
mod fields;

pub use curves::*;
pub use fields::*;
