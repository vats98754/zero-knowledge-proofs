//! Example: Fibonacci sequence using Nova incremental computation
//! 
//! This example shows how to compute Fibonacci numbers incrementally with Nova.

use nova_core::*;

fn main() {
    println!("Nova Fibonacci Example");
    
    let mut a = NovaField::from(0u64);
    let mut b = NovaField::from(1u64);
    
    println!("F(0) = {}", a);
    println!("F(1) = {}", b);
    
    // Compute first 10 Fibonacci numbers
    for i in 2..=10 {
        let c = a + b;
        println!("F({}) = {}", i, c);
        a = b;
        b = c;
    }
    
    println!("Fibonacci example completed!");
}