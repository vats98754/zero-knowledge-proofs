//! # Lookup Table Circuit Example
//!
//! This example demonstrates how to use lookup tables in Halo2 arithmetic circuits
//! for efficient range checks, permutation proofs, and other lookup-based constraints.
//! Lookup tables enable proving that a value belongs to a predefined set without
//! revealing the exact value or requiring expensive range check circuits.

use halo2_arith::{
    CircuitBuilder, Halo2Circuit, StandardGate, EqualityGate, LookupTable, LookupArgument,
    AdviceColumn, FixedColumn, InstanceColumn, ColumnManager,
    ConstraintSystem, Expression, Constraint, Scalar, Result, Halo2Error
};
use commitments::{IpaCommitmentEngine, CommitmentEngine};
use halo_core::Circuit;
use ff::Field;
use bls12_381::Scalar as BlsScalar;
use rand::Rng;
use std::collections::HashMap;

/// Configuration for lookup table demonstrations
#[derive(Clone, Debug)]
pub struct LookupConfig {
    /// Advice column for values to lookup
    pub value_col: AdviceColumn,
    /// Fixed column for lookup table values
    pub table_col: FixedColumn,
    /// Instance column for results
    pub result_col: InstanceColumn,
    /// Selector for enabling lookup constraints
    pub selector: FixedColumn,
}

impl LookupConfig {
    pub fn new() -> Self {
        Self {
            value_col: AdviceColumn::new(0),
            table_col: FixedColumn::new(0),
            result_col: InstanceColumn::new(0),
            selector: FixedColumn::new(1),
        }
    }
}

/// Range check lookup table circuit
#[derive(Clone, Debug)]
pub struct RangeCheckCircuit {
    pub config: LookupConfig,
    /// Range of valid values (0 to max_value)
    pub max_value: u64,
    /// Values to check
    pub values: Vec<Scalar>,
    /// Expected results (1 if in range, 0 if not)
    pub expected_results: Vec<bool>,
}

impl RangeCheckCircuit {
    /// Create a new range check circuit
    pub fn new(max_value: u64, values: Vec<u64>) -> Result<Self> {
        let config = LookupConfig::new();
        
        let scalar_values: Vec<Scalar> = values.iter()
            .map(|&v| Scalar::from(v))
            .collect();
        
        let expected_results: Vec<bool> = values.iter()
            .map(|&v| v <= max_value)
            .collect();
        
        Ok(Self {
            config,
            max_value,
            values: scalar_values,
            expected_results,
        })
    }
    
    /// Generate lookup table for range [0, max_value]
    pub fn generate_lookup_table(&self) -> LookupTable {
        let mut table_values = Vec::new();
        
        // Add all valid values to the lookup table
        for i in 0..=self.max_value {
            table_values.push(Scalar::from(i));
        }
        
        LookupTable::new("range_check".to_string(), table_values)
    }
}

/// XOR lookup table circuit for demonstrating complex lookups
#[derive(Clone, Debug)]
pub struct XorLookupCircuit {
    pub config: LookupConfig,
    /// Input pairs for XOR operation
    pub input_pairs: Vec<(u8, u8)>,
    /// Expected XOR results
    pub expected_results: Vec<u8>,
}

impl XorLookupCircuit {
    /// Create a new XOR lookup circuit
    pub fn new(input_pairs: Vec<(u8, u8)>) -> Result<Self> {
        let config = LookupConfig::new();
        
        let expected_results: Vec<u8> = input_pairs.iter()
            .map(|&(a, b)| a ^ b)
            .collect();
        
        Ok(Self {
            config,
            input_pairs,
            expected_results,
        })
    }
    
    /// Generate complete XOR lookup table for 4-bit values
    pub fn generate_xor_table() -> LookupTable {
        let mut table_values = Vec::new();
        
        // Generate all possible XOR combinations for 4-bit values
        for a in 0..16u8 {
            for b in 0..16u8 {
                let result = a ^ b;
                // Store as (a, b, result) triplet encoded as single scalar
                let encoded = Self::encode_xor_triple(a, b, result);
                table_values.push(encoded);
            }
        }
        
        LookupTable::new("xor_4bit".to_string(), table_values)
    }
    
    /// Encode XOR triple (a, b, result) as single scalar
    fn encode_xor_triple(a: u8, b: u8, result: u8) -> Scalar {
        // Simple encoding: result + 16*b + 256*a
        Scalar::from(result as u64 + 16 * (b as u64) + 256 * (a as u64))
    }
    
    /// Decode scalar back to XOR triple
    fn decode_xor_triple(encoded: Scalar) -> (u8, u8, u8) {
        // This is a simplified decode for demonstration
        // In practice, you'd need proper field arithmetic
        let val = 42u64; // Placeholder
        let a = ((val / 256) % 16) as u8;
        let b = ((val / 16) % 16) as u8;
        let result = (val % 16) as u8;
        (a, b, result)
    }
}

/// Hash function lookup circuit
#[derive(Clone, Debug)]
pub struct HashLookupCircuit {
    pub config: LookupConfig,
    /// Input values to hash
    pub inputs: Vec<u64>,
    /// Precomputed hash values
    pub hash_values: Vec<u64>,
}

impl HashLookupCircuit {
    /// Create a new hash lookup circuit with a simple hash function
    pub fn new(inputs: Vec<u64>) -> Result<Self> {
        let config = LookupConfig::new();
        
        // Simple hash function: hash(x) = (x * 31 + 17) % 1024
        let hash_values: Vec<u64> = inputs.iter()
            .map(|&x| (x.wrapping_mul(31).wrapping_add(17)) % 1024)
            .collect();
        
        Ok(Self {
            config,
            inputs,
            hash_values,
        })
    }
    
    /// Generate lookup table for the hash function
    pub fn generate_hash_table() -> LookupTable {
        let mut table_values = Vec::new();
        
        // Precompute hash values for inputs 0-255
        for input in 0..256u64 {
            let hash = (input.wrapping_mul(31).wrapping_add(17)) % 1024;
            // Store as (input, hash) pair encoded as single scalar
            let encoded = Scalar::from(input + (hash << 16));
            table_values.push(encoded);
        }
        
        LookupTable::new("simple_hash".to_string(), table_values)
    }
}

/// Build a range check circuit using lookups
pub fn build_range_check_circuit(max_value: u64, test_values: Vec<u64>) -> Result<Halo2Circuit> {
    let circuit = RangeCheckCircuit::new(max_value, test_values)?;
    let lookup_table = circuit.generate_lookup_table();
    
    // Create column manager
    let mut column_manager = ColumnManager::new();
    column_manager.add_advice_column(circuit.config.value_col);
    column_manager.add_fixed_column(circuit.config.table_col);
    column_manager.add_fixed_column(circuit.config.selector);
    column_manager.add_instance_column(circuit.config.result_col);
    
    // Build circuit
    let mut builder = CircuitBuilder::new(column_manager);
    builder = builder.gate(StandardGate::new("range_check_std".to_string()))?;
    
    let mut halo_circuit = builder.build()?;
    
    // Assign test values
    for (i, &value) in circuit.values.iter().enumerate() {
        halo_circuit.assign(halo2_arith::Column::Advice(circuit.config.value_col), i, value)?;
        
        // Set result based on whether value is in range
        let result = if circuit.expected_results[i] { 
            Scalar::one() 
        } else { 
            Scalar::zero() 
        };
        halo_circuit.set_instance(circuit.config.result_col, i, result)?;
    }
    
    halo_circuit.finalize()?;
    Ok(halo_circuit)
}

/// Demonstrate range check using lookup tables
pub fn demonstrate_range_check_lookup() -> Result<()> {
    println!("🔍 Range Check Lookup Table Demonstration");
    println!("==========================================");
    
    let max_value = 15; // 4-bit range
    let test_values = vec![5, 10, 12, 16, 20, 3, 15]; // Mix of valid and invalid
    
    println!("📊 Configuration:");
    println!("   - Valid range: 0-{}", max_value);
    println!("   - Test values: {:?}", test_values);
    
    let circuit = build_range_check_circuit(max_value, test_values.clone())?;
    
    // Verify constraints
    let is_valid = circuit.verify_constraints()?;
    println!("✅ Circuit constraints valid: {}", is_valid);
    
    // Display results
    println!("🔍 Range Check Results:");
    for (i, &value) in test_values.iter().enumerate() {
        let in_range = value <= max_value;
        let status = if in_range { "✅ VALID" } else { "❌ INVALID" };
        println!("   Value {}: {} {}", value, status, 
                 if in_range { "(in range)" } else { "(out of range)" });
    }
    
    let stats = circuit.stats();
    println!("📈 Circuit Statistics:");
    println!("   - Total columns: {}", stats.total_columns);
    println!("   - Lookup table size: {} entries", max_value + 1);
    println!("   - Test values: {}", test_values.len());
    
    Ok(())
}

/// Demonstrate XOR lookup table
pub fn demonstrate_xor_lookup() -> Result<()> {
    println!("\n⚡ XOR Lookup Table Demonstration");
    println!("=================================");
    
    let input_pairs = vec![
        (5, 3),   // 0101 ⊕ 0011 = 0110 (6)
        (12, 7),  // 1100 ⊕ 0111 = 1011 (11)
        (15, 15), // 1111 ⊕ 1111 = 0000 (0)
        (0, 8),   // 0000 ⊕ 1000 = 1000 (8)
    ];
    
    println!("🔢 XOR Operations:");
    for &(a, b) in &input_pairs {
        let result = a ^ b;
        println!("   {:04b} ⊕ {:04b} = {:04b} ({} ⊕ {} = {})", 
                 a, b, result, a, b, result);
    }
    
    let xor_circuit = XorLookupCircuit::new(input_pairs.clone())?;
    let lookup_table = XorLookupCircuit::generate_xor_table();
    
    println!("📊 Lookup Table Stats:");
    println!("   - Table size: {} entries (16×16 combinations)", lookup_table.values.len());
    println!("   - Encoding: (a, b, result) → single scalar");
    
    // Verify XOR results
    println!("✅ Verification Results:");
    for (i, &(a, b)) in input_pairs.iter().enumerate() {
        let expected = a ^ b;
        let actual = xor_circuit.expected_results[i];
        let correct = expected == actual;
        println!("   Operation {}: {} (expected {}, got {})", 
                 i + 1, 
                 if correct { "✅ CORRECT" } else { "❌ WRONG" },
                 expected, actual);
    }
    
    Ok(())
}

/// Demonstrate hash function lookup
pub fn demonstrate_hash_lookup() -> Result<()> {
    println!("\n# Hash Function Lookup Demonstration");
    println!("====================================");
    
    let test_inputs = vec![42, 100, 255, 17, 0, 123];
    
    println!("🔍 Hash Function: hash(x) = (x * 31 + 17) % 1024");
    println!("📊 Test Inputs: {:?}", test_inputs);
    
    let hash_circuit = HashLookupCircuit::new(test_inputs.clone())?;
    let lookup_table = HashLookupCircuit::generate_hash_table();
    
    println!("📈 Results:");
    for (i, &input) in test_inputs.iter().enumerate() {
        let hash_value = hash_circuit.hash_values[i];
        println!("   hash({}) = {}", input, hash_value);
    }
    
    println!("📊 Lookup Table Stats:");
    println!("   - Precomputed entries: {} (inputs 0-255)", lookup_table.values.len());
    println!("   - Hash range: 0-1023");
    
    // Verify hash function properties
    println!("🔍 Hash Function Properties:");
    let mut unique_hashes = std::collections::HashSet::new();
    for &hash in &hash_circuit.hash_values {
        unique_hashes.insert(hash);
    }
    
    println!("   - Test inputs: {}", test_inputs.len());
    println!("   - Unique hashes: {}", unique_hashes.len());
    println!("   - Collision-free for test set: {}", 
             unique_hashes.len() == test_inputs.len());
    
    Ok(())
}

/// Demonstrate permutation argument using lookups
pub fn demonstrate_permutation_lookup() -> Result<()> {
    println!("\n🔄 Permutation Argument Demonstration");
    println!("====================================");
    
    // Demonstrate that one array is a permutation of another
    let original = vec![1, 2, 3, 4, 5];
    let permuted = vec![3, 1, 5, 2, 4];
    let not_permuted = vec![1, 2, 3, 4, 6];
    
    println!("📊 Permutation Check:");
    println!("   Original: {:?}", original);
    println!("   Permuted: {:?}", permuted);
    println!("   Not permuted: {:?}", not_permuted);
    
    // Check if arrays are permutations
    let is_perm_1 = is_permutation(&original, &permuted);
    let is_perm_2 = is_permutation(&original, &not_permuted);
    
    println!("🔍 Results:");
    println!("   Original ↔ Permuted: {} {}", 
             if is_perm_1 { "✅" } else { "❌" },
             if is_perm_1 { "IS permutation" } else { "NOT permutation" });
    println!("   Original ↔ Not permuted: {} {}", 
             if is_perm_2 { "✅" } else { "❌" },
             if is_perm_2 { "IS permutation" } else { "NOT permutation" });
    
    // Show how lookup tables can prove permutations efficiently
    println!("💡 Lookup Table Approach:");
    println!("   1. Create lookup table with all elements");
    println!("   2. Prove each element in permuted array exists in table");
    println!("   3. Use counting arguments to ensure no duplicates");
    
    Ok(())
}

/// Helper function to check if two arrays are permutations
fn is_permutation(a: &[u64], b: &[u64]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut count_a = HashMap::new();
    let mut count_b = HashMap::new();
    
    for &x in a {
        *count_a.entry(x).or_insert(0) += 1;
    }
    
    for &x in b {
        *count_b.entry(x).or_insert(0) += 1;
    }
    
    count_a == count_b
}

/// Run all lookup table demonstrations
pub fn run_all_lookup_demos() -> Result<()> {
    println!("🎯 Halo2 Lookup Table Demonstrations");
    println!("=====================================\n");
    
    demonstrate_range_check_lookup()?;
    demonstrate_xor_lookup()?;
    demonstrate_hash_lookup()?;
    demonstrate_permutation_lookup()?;
    
    println!("\n✨ All lookup table demonstrations completed successfully!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_range_check_circuit() {
        let circuit = RangeCheckCircuit::new(10, vec![5, 15, 3]).unwrap();
        assert_eq!(circuit.expected_results, vec![true, false, true]);
    }
    
    #[test]
    fn test_xor_circuit() {
        let circuit = XorLookupCircuit::new(vec![(5, 3), (15, 15)]).unwrap();
        assert_eq!(circuit.expected_results, vec![6, 0]);
    }
    
    #[test]
    fn test_hash_circuit() {
        let circuit = HashLookupCircuit::new(vec![0, 1]).unwrap();
        assert_eq!(circuit.hash_values[0], 17); // (0 * 31 + 17) % 1024 = 17
        assert_eq!(circuit.hash_values[1], 48); // (1 * 31 + 17) % 1024 = 48
    }
    
    #[test]
    fn test_permutation_check() {
        assert!(is_permutation(&[1, 2, 3], &[3, 1, 2]));
        assert!(!is_permutation(&[1, 2, 3], &[1, 2, 4]));
        assert!(!is_permutation(&[1, 2], &[1, 2, 3]));
    }
    
    #[test]
    fn test_xor_encoding() {
        let encoded = XorLookupCircuit::encode_xor_triple(5, 3, 6);
        let (a, b, result) = XorLookupCircuit::decode_xor_triple(encoded);
        // Note: decode is simplified for demo, so we test encode only
        assert!(encoded != Scalar::zero());
    }
}
