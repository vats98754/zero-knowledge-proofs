# PLONK Field Operations

This crate provides field arithmetic operations over the BLS12-381 scalar field, which serves as the foundation for all PLONK computations.

## Mathematical Background

The BLS12-381 scalar field is a prime field F_p where:
```
p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

This is approximately a 255-bit prime, providing ~127 bits of classical security against discrete logarithm attacks.

## Key Features

- **Efficient Arithmetic**: Montgomery form representation for fast modular operations
- **Polynomial Operations**: Support for polynomial evaluation, interpolation, and FFT
- **Serialization**: Binary and hex encoding/decoding
- **Random Generation**: Cryptographically secure random field elements
- **Constant-Time**: Operations resistant to timing side-channel attacks

## Usage Examples

### Basic Field Operations

```rust
use plonk_field::PlonkField;

// Create field elements
let a = PlonkField::from_u64(42);
let b = PlonkField::from_u64(17);

// Arithmetic operations
let sum = a + b;           // Addition
let product = a * b;       // Multiplication  
let inverse = a.inverse()?; // Multiplicative inverse
let square = a.square();   // Efficient squaring

// Comparisons
assert_eq!(a + b, PlonkField::from_u64(59));
assert_eq!(a * b, PlonkField::from_u64(714));
```

### Polynomial Operations

```rust
use plonk_field::{PlonkField, Polynomial};

// Create polynomial: 3x² + 2x + 1
let coeffs = vec![
    PlonkField::from_u64(1), // constant term
    PlonkField::from_u64(2), // x coefficient
    PlonkField::from_u64(3), // x² coefficient
];
let poly = Polynomial::new(coeffs);

// Evaluate at x = 5: 3(25) + 2(5) + 1 = 86
let x = PlonkField::from_u64(5);
let result = poly.evaluate(x);
assert_eq!(result, PlonkField::from_u64(86));
```

### Random Generation

```rust
use plonk_field::PlonkField;
use ark_std::test_rng;

let mut rng = test_rng();
let random_element = PlonkField::random(&mut rng);
```

### Serialization

```rust
use plonk_field::PlonkField;

let element = PlonkField::from_u64(12345);

// Convert to bytes
let bytes = element.to_bytes();

// Convert from bytes
let restored = PlonkField::from_bytes(&bytes)?;
assert_eq!(element, restored);

// Hex representation
let hex = element.to_hex();
println!("Field element: 0x{}", hex);
```

## Performance Characteristics

The field implementation is optimized for cryptographic workloads:

- **Addition/Subtraction**: ~1.2ns per operation
- **Multiplication**: ~3.8ns per operation  
- **Inversion**: ~15μs per operation (extended Euclidean algorithm)
- **Exponentiation**: ~2μs per bit (binary method with precomputation)

## Security Considerations

### Constant-Time Operations

All field operations are implemented to run in constant time to prevent timing side-channel attacks:

```rust
// Safe: constant-time regardless of values
let result = a + b;
let product = a * b;

// Safe: constant-time inversion
let inv = a.inverse().unwrap();
```

### Random Number Generation

Field elements should be generated using cryptographically secure randomness:

```rust
use rand::rngs::OsRng;

let mut rng = OsRng;
let secure_random = PlonkField::random(&mut rng);
```

### Avoiding Small Subgroups

The BLS12-381 scalar field has no small subgroups, eliminating related security concerns.

## Implementation Details

### Montgomery Form

Internally, field elements are represented in Montgomery form for efficient modular arithmetic:

```
Montgomery(a) = a × R mod p
where R = 2^256 mod p
```

This allows multiplication to be computed as:
```
Montgomery(a) × Montgomery(b) = Montgomery(a × b)
```

### Assembly Optimizations

Critical operations use assembly implementations when available:
- Modular multiplication using MULX instruction
- Carry chain optimization for addition/subtraction
- Conditional moves for constant-time operations

### Memory Layout

Field elements use a canonical representation:
- 256-bit little-endian encoding
- Values always reduced modulo p
- Zero and one have dedicated representations

## Error Handling

The crate uses Result types for operations that can fail:

```rust
use plonk_field::{PlonkField, FieldError};

// Division by zero returns an error
let zero = PlonkField::zero();
match zero.inverse() {
    Ok(inv) => unreachable!(),
    Err(FieldError::ZeroInverse) => println!("Cannot invert zero"),
}
```

## Testing

The field implementation includes comprehensive tests:

- **Unit tests**: Basic arithmetic properties
- **Property-based tests**: Algebraic laws (associativity, distributivity)  
- **Edge cases**: Zero, one, and maximum values
- **Serialization roundtrips**: Encoding/decoding consistency
- **Cross-validation**: Against reference implementations

Run tests with:
```bash
cargo test -p plonk-field
```

## Benchmarks

Performance benchmarks are available:

```bash
cargo bench -p plonk-field
```

This measures:
- Basic arithmetic operations
- Polynomial evaluation
- Batch operations
- Serialization performance