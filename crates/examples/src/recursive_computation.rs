//! Example: Recursive Computation using Nova
//! 
//! This example demonstrates recursive computation with Nova's folding scheme.

use nova_core::*;
use ark_std::{vec, One};

fn main() {
    println!("Nova Recursive Computation Example");
    
    // Create a simple computation: f(x) = x^2 + 1
    let mut x = NovaField::from(2u64);
    
    println!("Starting with x = {}", x);
    
    // Apply the function recursively
    for i in 0..5 {
        let new_x = x * x + NovaField::one();
        println!("f^{}(x) = {}", i + 1, new_x);
        x = new_x;
    }
    
    println!("Recursive computation example completed!");
}