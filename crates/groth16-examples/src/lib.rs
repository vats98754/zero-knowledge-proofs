//! Example circuits and usage demonstrations for Groth16.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use groth16_field::{F, FieldLike};
use groth16_r1cs::{R1CS, LinearCombination};
use groth16_qap::QAP;
use groth16_setup::CRS;
use ark_poly::EvaluationDomain;
use anyhow::Result;

/// Example: Simple multiplication circuit (x * y = z)
pub fn multiplication_circuit() -> Result<()> {
    println!("=== Multiplication Circuit Example ===");
    
    // Create R1CS for: x * y = z
    let mut r1cs = R1CS::<F>::new(0);
    let x = r1cs.allocate_variable(); // variable 1
    let y = r1cs.allocate_variable(); // variable 2  
    let z = r1cs.allocate_variable(); // variable 3
    
    r1cs.enforce_multiplication(
        LinearCombination::from_variable(x),
        LinearCombination::from_variable(y),
        LinearCombination::from_variable(z)
    );
    
    println!("Circuit has {} variables and {} constraints", 
             r1cs.num_variables, r1cs.num_constraints());
    
    // Convert to QAP
    let qap = QAP::from_r1cs(&r1cs)?;
    println!("QAP has degree {}", qap.degree());
    
    // Generate CRS
    let mut rng = rand::thread_rng();
    let crs = CRS::generate_random(&qap, 1, &mut rng)?;
    println!("Generated CRS with {} public inputs", crs.vk.num_public);
    
    // Test with witness: 3 * 4 = 12 (with x=3 public)
    let assignment = vec![
        <F as FieldLike>::one(), // constant = 1
        F::from(3u64),           // x = 3 (public)
        F::from(4u64),           // y = 4 (private)
        F::from(12u64),          // z = 12 (private)
    ];
    
    // Validate QAP at domain point
    let omega = qap.domain.group_gen();
    let eval = qap.evaluate_at(omega, &assignment)?;
    
    if qap.verify_evaluation(&eval) {
        println!("✓ Witness satisfies QAP constraints");
    } else {
        println!("✗ Witness does not satisfy QAP constraints");
    }
    
    println!("Multiplication circuit example completed successfully!");
    Ok(())
}

/// Example: Quadratic circuit (x^2 + y^2 = z)
pub fn quadratic_circuit() -> Result<()> {
    println!("\n=== Quadratic Circuit Example ===");
    
    let mut r1cs = R1CS::<F>::new(0);
    
    // Variables
    let x = r1cs.allocate_variable();      // input x
    let y = r1cs.allocate_variable();      // input y
    let x_squared = r1cs.allocate_variable(); // x^2
    let y_squared = r1cs.allocate_variable(); // y^2
    let z = r1cs.allocate_variable();      // output z = x^2 + y^2
    
    // Constraints
    // 1. x * x = x_squared
    r1cs.enforce_multiplication(
        LinearCombination::from_variable(x),
        LinearCombination::from_variable(x),
        LinearCombination::from_variable(x_squared)
    );
    
    // 2. y * y = y_squared
    r1cs.enforce_multiplication(
        LinearCombination::from_variable(y),
        LinearCombination::from_variable(y),
        LinearCombination::from_variable(y_squared)
    );
    
    // 3. x_squared + y_squared = z  
    // We need to enforce: x_squared + y_squared - z = 0
    // This means: 0 = x_squared + y_squared - z
    // But we need it in the form A * B = C
    // So we use: (x_squared + y_squared - z) * 1 = 0
    // Which requires: x_squared + y_squared - z = 0
    
    // Use enforce_equal instead: x_squared + y_squared = z
    r1cs.enforce_equal(
        {
            let mut lc = LinearCombination::from_variable(x_squared);
            lc.add_lc(&LinearCombination::from_variable(y_squared));
            lc
        },
        LinearCombination::from_variable(z)
    );
    
    println!("Quadratic circuit has {} variables and {} constraints", 
             r1cs.num_variables, r1cs.num_constraints());
    
    // Convert to QAP
    let qap = QAP::from_r1cs(&r1cs)?;
    println!("QAP has degree {}", qap.degree());
    
    // Test with witness: 3^2 + 4^2 = 25 (inputs 3, 4 public)
    let assignment = vec![
        <F as FieldLike>::one(), // constant = 1
        F::from(3u64),           // x = 3 (public)
        F::from(4u64),           // y = 4 (public)  
        F::from(9u64),           // x_squared = 9
        F::from(16u64),          // y_squared = 16
        F::from(25u64),          // z = 25
    ];
    
    // Validate constraint satisfaction
    if r1cs.is_satisfied(&assignment)? {
        println!("✓ Witness satisfies all R1CS constraints");
    } else {
        println!("✗ Witness does not satisfy R1CS constraints");
    }
    
    println!("Quadratic circuit example completed successfully!");
    Ok(())
}

/// Example: Boolean circuit (AND gate)
pub fn boolean_circuit() -> Result<()> {
    println!("\n=== Boolean Circuit Example ===");
    
    let mut r1cs = R1CS::<F>::new(0);
    
    // Boolean variables (0 or 1)
    let a = r1cs.allocate_variable();
    let b = r1cs.allocate_variable(); 
    let c = r1cs.allocate_variable(); // c = a AND b
    
    // Boolean constraints: each variable must be 0 or 1
    // We implement this as: a * a = a, b * b = b, c * c = c
    r1cs.enforce_multiplication(
        LinearCombination::from_variable(a),
        LinearCombination::from_variable(a),
        LinearCombination::from_variable(a)
    );
    r1cs.enforce_multiplication(
        LinearCombination::from_variable(b),
        LinearCombination::from_variable(b),
        LinearCombination::from_variable(b)
    );
    r1cs.enforce_multiplication(
        LinearCombination::from_variable(c),
        LinearCombination::from_variable(c),
        LinearCombination::from_variable(c)
    );
    
    // AND constraint: a * b = c
    r1cs.enforce_multiplication(
        LinearCombination::from_variable(a),
        LinearCombination::from_variable(b),
        LinearCombination::from_variable(c)
    );
    
    println!("Boolean circuit has {} variables and {} constraints", 
             r1cs.num_variables, r1cs.num_constraints());
    
    // Test cases
    let test_cases = vec![
        (0u64, 0u64, 0u64), // 0 AND 0 = 0
        (0u64, 1u64, 0u64), // 0 AND 1 = 0
        (1u64, 0u64, 0u64), // 1 AND 0 = 0
        (1u64, 1u64, 1u64), // 1 AND 1 = 1
    ];
    
    for (a_val, b_val, c_val) in test_cases {
        let assignment = vec![
            <F as FieldLike>::one(),
            F::from(a_val),
            F::from(b_val),
            F::from(c_val),
        ];
        
        let satisfied = r1cs.is_satisfied(&assignment)?;
        println!("Test {} AND {} = {}: {}", 
                 a_val, b_val, c_val, 
                 if satisfied { "✓" } else { "✗" });
    }
    
    println!("Boolean circuit example completed successfully!");
    Ok(())
}

/// Run all examples
pub fn run_all_examples() -> Result<()> {
    println!("Running Groth16 example circuits...\n");
    
    multiplication_circuit()?;
    quadratic_circuit()?;
    boolean_circuit()?;
    
    println!("\n🎉 All examples completed successfully!");
    Ok(())
}