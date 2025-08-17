# PLONK Zero-Knowledge Proof System - Technical Specification

## Overview

This document provides a comprehensive technical specification for our production-grade Rust implementation of PLONK (Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge). PLONK is a universal zero-knowledge SNARK that enables efficient proving and verification of arbitrary arithmetic circuits.

## Mathematical Foundations

### 1. Field Arithmetic

PLONK operates over a prime field **F_p** where p is the order of the BLS12-381 scalar field:
```
p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

All arithmetic operations are performed modulo p, providing the cryptographic security foundation.

### 2. Polynomial Commitment Scheme

We use the KZG (Kate-Zaverucha-Goldberg) polynomial commitment scheme over the BLS12-381 elliptic curve group G₁.

**Setup**: For maximum degree n, generate SRS (Structured Reference String):
```
SRS = (G, G^τ, G^τ², ..., G^τⁿ, H, H^τ)
```
where G ∈ G₁, H ∈ G₂, and τ is a secret trapdoor.

**Commitment**: For polynomial f(x) = Σᵢ aᵢxᵢ:
```
C = Σᵢ aᵢ[τⁱ]₁ = [f(τ)]₁
```

**Opening**: To prove f(z) = v, compute witness polynomial w(x):
```
w(x) = (f(x) - v) / (x - z)
π = [w(τ)]₁
```

**Verification**: Check pairing equation:
```
e(C - [v]₁, H) = e(π, [τ]₂ - [z]₂)
```

### 3. PLONK Arithmetization

#### Circuit Representation

PLONK represents arithmetic circuits using a wire model with m=3 wires per row:
- **a_i**: Left input wire
- **b_i**: Right input wire  
- **c_i**: Output wire

#### Gate Constraints

Each gate i is defined by selector polynomials:
```
q_M[i] · a[i] · b[i] + q_L[i] · a[i] + q_R[i] · b[i] + q_O[i] · c[i] + q_C[i] = 0
```

Where:
- **q_M**: Multiplication selector
- **q_L, q_R**: Left/right addition selectors
- **q_O**: Output selector
- **q_C**: Constant selector

#### Permutation Argument

The permutation argument enforces copy constraints using a grand product:
```
Z(x) = ∏ᵢ (aᵢ + β·σ(i) + γ) / (aᵢ + β·i + γ)
```

Where:
- **σ**: Permutation mapping
- **β, γ**: Random challenges
- **Z(x)**: Permutation polynomial

### 4. PLONK Protocol

#### Prover Algorithm

1. **Round 1**: Commit to wire polynomials
   ```
   [a(x)]₁, [b(x)]₁, [c(x)]₁
   ```

2. **Round 2**: Compute permutation polynomial Z(x)
   ```
   Z(ωⁱ⁺¹) = Z(ωⁱ) · (a(ωⁱ) + β·σ(ωⁱ) + γ) / (a(ωⁱ) + β·ωⁱ + γ)
   ```
   Commit to [Z(x)]₁

3. **Round 3**: Compute quotient polynomial t(x)
   ```
   t(x) = (gate_constraint(x) + α·permutation_constraint(x)) / Z_H(x)
   ```
   Commit to [t(x)]₁

4. **Round 4**: Provide evaluations at random point ζ
   ```
   a(ζ), b(ζ), c(ζ), Z(ζ), Z(ζω), qᵢ(ζ)
   ```

5. **Round 5**: Compute opening proofs for all evaluations

#### Verifier Algorithm

1. **Verify gate constraints**:
   ```
   gate_eval = q_M(ζ)·a(ζ)·b(ζ) + q_L(ζ)·a(ζ) + q_R(ζ)·b(ζ) + q_O(ζ)·c(ζ) + q_C(ζ)
   ```

2. **Verify permutation constraints**:
   ```
   perm_eval = Z(ζω)·L₁(ζ) - Z(ζ)·(a(ζ) + β·ζ + γ)
   ```

3. **Verify quotient evaluation**:
   ```
   t(ζ)·Z_H(ζ) = gate_eval + α·perm_eval
   ```

4. **Verify all KZG opening proofs**

## Security Analysis

### Cryptographic Assumptions

1. **Discrete Logarithm Assumption**: Computing x from g^x is hard in G₁
2. **q-Strong Bilinear Diffie-Hellman**: Computing g^(1/τ) from SRS is hard
3. **Generic Group Model**: Adversary can only perform group operations

### Security Properties

1. **Completeness**: Honest prover with valid witness always convinces verifier
2. **Soundness**: Malicious prover cannot convince verifier without valid witness
3. **Zero-Knowledge**: Proof reveals no information about secret witness
4. **Succinct**: Proof size is O(1), verification time is O(1)

### Attack Vectors and Mitigations

1. **Trusted Setup Corruption**:
   - **Risk**: If τ is known, prover can forge proofs
   - **Mitigation**: Use ceremony with multiple participants, destroy τ

2. **Polynomial Commitment Attacks**:
   - **Risk**: Opening proofs at incorrect points
   - **Mitigation**: Fiat-Shamir transformation with strong hash function

3. **Permutation Argument Attacks**:
   - **Risk**: Malformed permutation polynomials
   - **Mitigation**: Verify grand product property and boundary conditions

## Implementation Details

### Field Implementation
- Uses Arkworks BLS12-381 scalar field
- Montgomery form for efficient modular arithmetic
- Assembly optimizations for performance-critical operations

### Polynomial Operations
- FFT/IFFT for O(n log n) polynomial multiplication
- Barycentric evaluation for efficient point evaluation
- Batch inversion for multiple field inversions

### Elliptic Curve Operations
- Projective coordinates for efficient group operations
- Batch verification for multiple pairing checks
- Precomputed tables for fixed-base scalar multiplication

### Optimizations
- **Parallelization**: Multi-threaded polynomial operations using Rayon
- **Memory Management**: Efficient allocation patterns for large polynomials
- **Caching**: Precomputed powers and roots of unity

## Performance Characteristics

### Asymptotic Complexity
- **Proving Time**: O(n log n) where n is circuit size
- **Verification Time**: O(1) - constant regardless of circuit size
- **Proof Size**: O(1) - approximately 768 bytes
- **Setup Size**: O(n) - linear in maximum circuit size

### Concrete Performance (estimated)
- **Small Circuit** (1K gates): ~100ms proving, <10ms verification
- **Medium Circuit** (100K gates): ~10s proving, <10ms verification  
- **Large Circuit** (1M gates): ~100s proving, <10ms verification

## Cryptographic Parameters

### BLS12-381 Curve Parameters
```rust
// Prime field modulus
p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

// Curve equation: y² = x³ + 4
// Generator points
G1 = (0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb, 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1)
```

### Security Levels
- **Classical Security**: ~126 bits (from BLS12-381 discrete log)
- **Quantum Security**: ~84 bits (Grover's algorithm)
- **Recommended**: Use post-quantum alternatives for long-term security

## References

1. Gabizon, A., Williamson, Z. J., & Ciobotaru, O. (2019). "PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge"
2. Kate, A., Zaverucha, G. M., & Goldberg, I. (2010). "Constant-size commitments to polynomials and their applications"
3. Bowe, S., Grigg, J., & Hopwood, D. (2017). "Recursive Proof Composition without a Trusted Setup"
4. Boneh, D., Drake, J., Fisch, B., & Gabizon, A. (2019). "Halo Infinite: Recursive zk-SNARKs from any Additive Polynomial Commitment Scheme"