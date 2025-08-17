//! # Inner Product Argument (IPA)
//!
//! This crate implements the inner product argument, which is the core component
//! of Bulletproofs. The IPA allows proving knowledge of vectors `a` and `b` such that:
//!
//! ```text
//! P = g^a * h^b * u^<a,b>
//! ```
//!
//! ## Mathematical Background
//!
//! The inner product argument uses a recursive folding approach:
//!
//! 1. **Base Case**: For vectors of length 1, the proof is just the values `a` and `b`.
//!
//! 2. **Recursive Case**: For vectors of length `n > 1`:
//!    - Split vectors: `a = (a_L, a_R)`, `b = (b_L, b_R)`
//!    - Compute cross terms:
//!      - `L = g_R^{a_L} * h_L^{b_R} * u^{<a_L, b_R>}`
//!      - `R = g_L^{a_R} * h_R^{b_L} * u^{<a_R, b_L>}`
//!    - Get challenge `x` from Fiat-Shamir
//!    - Fold vectors:
//!      - `a' = a_L * x + a_R * x^{-1}`
//!      - `b' = b_L * x^{-1} + b_R * x`
//!    - Fold generators:
//!      - `g' = g_L^{x^{-1}} * g_R^x`
//!      - `h' = h_L^x * h_R^{x^{-1}}`
//!    - Recurse with folded values
//!
//! The proof consists of all the L and R values from each folding round.

pub mod proof;
pub mod prover;
pub mod verifier;

pub use proof::*;
pub use prover::*;
pub use verifier::*;