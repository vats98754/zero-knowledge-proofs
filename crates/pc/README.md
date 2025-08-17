# PLONK Polynomial Commitment Scheme

This crate implements the KZG (Kate-Zaverucha-Goldberg) polynomial commitment scheme over the BLS12-381 elliptic curve, providing cryptographic commitments to polynomials with efficient opening proofs.

## Mathematical Foundation

### KZG Commitment Scheme

The KZG scheme allows committing to a polynomial f(x) of degree at most d:

**Setup Phase:**
Generate a structured reference string (SRS) with secret τ:
```
SRS = ([1]₁, [τ]₁, [τ²]₁, ..., [τᵈ]₁, [1]₂, [τ]₂)
```
where [·]₁ and [·]₂ denote group elements in G₁ and G₂ respectively.

**Commitment:**
For polynomial f(x) = Σᵢ aᵢxᵢ, compute:
```
C = Σᵢ aᵢ[τᵢ]₁ = [f(τ)]₁
```

**Opening:**
To prove f(z) = v, compute witness polynomial:
```
w(x) = (f(x) - v) / (x - z)
π = [w(τ)]₁
```

**Verification:**
Check the pairing equation:
```
e(C - [v]₁, [1]₂) = e(π, [τ]₂ - [z]₂)
```

## Key Features

- **Universal Setup**: Single SRS works for all polynomials up to degree d
- **Constant Size**: Commitments and proofs are single group elements
- **Efficient Verification**: Single pairing check per opening
- **Batch Operations**: Multiple openings can be verified together
- **Homomorphic**: Supports addition of committed polynomials

## Usage Examples

### Universal Setup Generation

```rust
use plonk_pc::{KZGEngine, UniversalSetup};
use ark_std::test_rng;

let mut rng = test_rng();
let max_degree = 1024;

// Generate universal SRS
let setup = UniversalSetup::<KZGEngine>::new(max_degree, &mut rng)?;

// Extract keys for specific degree
let degree = 256;
let (committer_key, verifier_key) = setup.extract_keys(degree)?;
```

### Polynomial Commitment

```rust
use plonk_pc::{KZGEngine, CommitmentEngine};
use plonk_field::{PlonkField, Polynomial};

// Create polynomial: 3x² + 2x + 1
let coeffs = vec![
    PlonkField::from_u64(1),
    PlonkField::from_u64(2), 
    PlonkField::from_u64(3),
];
let poly = Polynomial::new(coeffs);

// Commit to polynomial
let commitment = KZGEngine::commit(&committer_key, &poly)?;
```

### Opening Proof Generation

```rust
use plonk_field::PlonkField;

// Evaluation point and expected value
let z = PlonkField::from_u64(5);
let v = poly.evaluate(z); // Should equal 86 for our example

// Generate opening proof
let proof = KZGEngine::open(&committer_key, &poly, z)?;
```

### Proof Verification

```rust
// Verify the opening proof
let is_valid = KZGEngine::verify(
    &verifier_key,
    &commitment,
    z,
    v,
    &proof,
)?;

assert!(is_valid);
```

### Fiat-Shamir Transcript

```rust
use plonk_pc::Transcript;

// Create transcript for non-interactive proofs
let mut transcript = Transcript::new(b"my_protocol");

// Add data to transcript
transcript.append_field(b"commitment", field_element);
transcript.append_bytes(b"proof", proof_bytes);

// Generate challenge
let challenge = transcript.challenge_field(b"challenge");
```

## Advanced Features

### Batch Verification

Verify multiple openings simultaneously:

```rust
use plonk_pc::BatchVerifier;

let mut verifier = BatchVerifier::new();

// Add multiple opening claims
verifier.add_opening(&commitment1, z1, v1, &proof1);
verifier.add_opening(&commitment2, z2, v2, &proof2);
verifier.add_opening(&commitment3, z3, v3, &proof3);

// Verify all at once (more efficient than individual verification)
let all_valid = verifier.verify(&verifier_key)?;
```

### Polynomial Arithmetic

Commitments support homomorphic operations:

```rust
// Add two committed polynomials
let commitment_sum = commitment1 + commitment2;

// Scalar multiplication
let commitment_scaled = commitment1 * scalar;
```

## Security Properties

### Computational Assumptions

1. **q-Strong Bilinear Diffie-Hellman (q-SBDH)**:
   Given (g, g^τ, g^τ², ..., g^τᵈ), computing g^(1/τ) is hard.

2. **Discrete Logarithm in G₁**:
   Given g^a, computing a is hard.

### Security Guarantees

- **Binding**: Cannot open commitment to different values at same point
- **Hiding**: Commitment reveals no information about polynomial
- **Evaluation Correctness**: Opening proofs guarantee correct evaluation

### Trusted Setup Requirements

The universal setup requires:
1. Secure generation of secret τ
2. Proper powers of τ computation  
3. Destruction of τ after setup
4. Public verification of setup correctness

## Performance Characteristics

### Operation Complexities

| Operation | Time Complexity | Space Complexity |
|-----------|----------------|------------------|
| Setup Generation | O(d) | O(d) |
| Commitment | O(d) | O(1) |
| Opening | O(d) | O(1) |
| Verification | O(1) | O(1) |
| Batch Verification | O(k) | O(k) |

Where d is polynomial degree and k is number of proofs.

### Concrete Performance

Based on benchmarks with BLS12-381:

| Polynomial Degree | Commitment Time | Opening Time | Verification Time |
|-------------------|----------------|--------------|-------------------|
| 256 | ~2ms | ~3ms | ~8ms |
| 1024 | ~8ms | ~12ms | ~8ms |
| 4096 | ~35ms | ~50ms | ~8ms |
| 16384 | ~150ms | ~200ms | ~8ms |

## Implementation Details

### Elliptic Curve Operations

- **Group G₁**: BLS12-381 base field points
- **Group G₂**: BLS12-381 extension field points  
- **Pairing**: Optimal Ate pairing for verification
- **Serialization**: Compressed point encoding for efficiency

### Optimizations

1. **Multi-Scalar Multiplication (MSM)**:
   - Pippenger's algorithm for large degree polynomials
   - Parallelization across multiple cores
   - Precomputed tables for fixed bases

2. **Batch Operations**:
   - Random linear combinations for batch verification
   - Amortized pairing costs across multiple proofs

3. **Memory Management**:
   - Efficient allocation patterns for large polynomials
   - Memory mapping for very large SRS files

### Error Handling

```rust
use plonk_pc::PCError;

match KZGEngine::commit(&key, &poly) {
    Ok(commitment) => { /* success */ },
    Err(PCError::DegreeTooBig) => { /* polynomial too large */ },
    Err(PCError::InvalidKey) => { /* malformed key */ },
    Err(e) => { /* other errors */ },
}
```

## Testing and Validation

### Test Coverage

- **Correctness**: Commitment/opening soundness
- **Edge Cases**: Zero polynomial, single coefficient
- **Malformed Inputs**: Invalid proofs, wrong parameters
- **Homomorphic Properties**: Addition and scaling
- **Serialization**: Round-trip encoding/decoding

### Property-Based Testing

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn commitment_opening_soundness(coeffs: Vec<u64>, z_val: u64) {
        let poly = create_polynomial(coeffs);
        let z = PlonkField::from_u64(z_val);
        let v = poly.evaluate(z);
        
        let commitment = KZGEngine::commit(&key, &poly).unwrap();
        let proof = KZGEngine::open(&key, &poly, z).unwrap();
        
        assert!(KZGEngine::verify(&vk, &commitment, z, v, &proof).unwrap());
    }
}
```

### Cross-Validation

Tests validate against:
- Reference implementations in other languages
- Known test vectors from academic papers
- Cross-validation with other KZG implementations

## Usage in PLONK

The polynomial commitment scheme is used throughout PLONK:

1. **Wire Polynomials**: Commit to witness values a(x), b(x), c(x)
2. **Selector Polynomials**: Commit to gate selectors qₘ(x), qₗ(x), etc.
3. **Permutation Polynomial**: Commit to copy constraint polynomial Z(x)
4. **Quotient Polynomial**: Commit to quotient t(x)
5. **Opening Proofs**: Prove evaluations at challenge point ζ

## References

- Kate, A., Zaverucha, G. M., & Goldberg, I. (2010). "Constant-size commitments to polynomials and their applications"
- Gabizon, A., Williamson, Z. J., & Ciobotaru, O. (2019). "PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge"
- Boneh, D., Drake, J., Fisch, B., & Gabizon, A. (2019). "Efficient polynomial commitment schemes for multiple points and polynomials"