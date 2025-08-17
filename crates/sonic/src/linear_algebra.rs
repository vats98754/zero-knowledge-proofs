//! Linear algebra operations optimized for zero-knowledge proofs
//!
//! This module provides high-performance linear algebra operations
//! specifically optimized for polynomial commitment schemes and SNARKs.

use crate::{Result, SonicError};
use zkp_field::{Scalar, polynomial::DensePolynomial};
use ark_ff::{Zero, One};
use rayon::prelude::*;
use std::ops::{Add, Mul};

/// High-performance linear algebra operations
pub struct LinearAlgebra;

/// Sparse matrix representation optimized for cryptographic operations
#[derive(Debug, Clone)]
pub struct SparseMatrix {
    /// Matrix entries as (row, col, value) triplets
    pub entries: Vec<(usize, usize, Scalar)>,
    /// Number of rows
    pub num_rows: usize,
    /// Number of columns
    pub num_cols: usize,
}

/// Dense matrix for operations requiring full matrix representation
#[derive(Debug, Clone)]
pub struct DenseMatrix {
    /// Matrix data in row-major order
    pub data: Vec<Vec<Scalar>>,
    /// Number of rows
    pub num_rows: usize,
    /// Number of columns
    pub num_cols: usize,
}

/// Vector operations with parallel processing support
pub struct VectorOps;

/// Matrix operations with sparse/dense optimizations
pub struct MatrixOps;

impl LinearAlgebra {
    /// Performs optimized multi-scalar multiplication
    pub fn multi_scalar_multiply(
        bases: &[Scalar],
        scalars: &[Scalar],
    ) -> Result<Scalar> {
        if bases.len() != scalars.len() {
            return Err(SonicError::LinearAlgebraError);
        }

        let result = bases.par_iter()
            .zip(scalars.par_iter())
            .map(|(base, scalar)| *base * *scalar)
            .reduce(|| Scalar::zero(), |a, b| a + b);

        Ok(result)
    }

    /// Computes inner product with parallel processing
    pub fn parallel_inner_product(
        a: &[Scalar],
        b: &[Scalar],
    ) -> Result<Scalar> {
        if a.len() != b.len() {
            return Err(SonicError::LinearAlgebraError);
        }

        let result = a.par_iter()
            .zip(b.par_iter())
            .map(|(ai, bi)| *ai * *bi)
            .reduce(|| Scalar::zero(), |a, b| a + b);

        Ok(result)
    }

    /// Performs batch vector addition with parallelization
    pub fn batch_vector_add(
        vectors: &[Vec<Scalar>],
    ) -> Result<Vec<Scalar>> {
        if vectors.is_empty() {
            return Err(SonicError::LinearAlgebraError);
        }

        let len = vectors[0].len();
        if !vectors.iter().all(|v| v.len() == len) {
            return Err(SonicError::LinearAlgebraError);
        }

        let result: Vec<Scalar> = (0..len)
            .into_par_iter()
            .map(|i| {
                vectors.iter().map(|v| v[i]).fold(Scalar::zero(), |acc, x| acc + x)
            })
            .collect();

        Ok(result)
    }

    /// Linear combination of vectors with coefficients
    pub fn vector_linear_combination(
        vectors: &[Vec<Scalar>],
        coefficients: &[Scalar],
    ) -> Result<Vec<Scalar>> {
        if vectors.len() != coefficients.len() {
            return Err(SonicError::LinearAlgebraError);
        }

        if vectors.is_empty() {
            return Err(SonicError::LinearAlgebraError);
        }

        let len = vectors[0].len();
        if !vectors.iter().all(|v| v.len() == len) {
            return Err(SonicError::LinearAlgebraError);
        }

        let result: Vec<Scalar> = (0..len)
            .into_par_iter()
            .map(|i| {
                vectors.iter()
                    .zip(coefficients.iter())
                    .map(|(v, &c)| v[i] * c)
                    .fold(Scalar::zero(), |acc, x| acc + x)
            })
            .collect();

        Ok(result)
    }

    /// Hadamard (element-wise) product of vectors
    pub fn hadamard_product(
        a: &[Scalar],
        b: &[Scalar],
    ) -> Result<Vec<Scalar>> {
        if a.len() != b.len() {
            return Err(SonicError::LinearAlgebraError);
        }

        let result: Vec<Scalar> = a.par_iter()
            .zip(b.par_iter())
            .map(|(ai, bi)| *ai * *bi)
            .collect();

        Ok(result)
    }
}

impl SparseMatrix {
    /// Creates a new sparse matrix
    pub fn new(num_rows: usize, num_cols: usize) -> Self {
        Self {
            entries: Vec::new(),
            num_rows,
            num_cols,
        }
    }

    /// Adds an entry to the sparse matrix
    pub fn add_entry(&mut self, row: usize, col: usize, value: Scalar) {
        if row < self.num_rows && col < self.num_cols && !value.is_zero() {
            self.entries.push((row, col, value));
        }
    }

    /// Gets the value at (row, col), returning zero if not present
    pub fn get(&self, row: usize, col: usize) -> Scalar {
        self.entries.iter()
            .find(|&&(r, c, _)| r == row && c == col)
            .map(|&(_, _, val)| val)
            .unwrap_or_else(Scalar::zero)
    }

    /// Multiplies sparse matrix by a vector
    pub fn multiply_vector(&self, vector: &[Scalar]) -> Result<Vec<Scalar>> {
        if vector.len() != self.num_cols {
            return Err(SonicError::LinearAlgebraError);
        }

        let mut result = vec![Scalar::zero(); self.num_rows];
        
        for &(row, col, value) in &self.entries {
            result[row] += value * vector[col];
        }

        Ok(result)
    }

    /// Multiplies sparse matrix by another sparse matrix
    pub fn multiply_sparse(&self, other: &SparseMatrix) -> Result<SparseMatrix> {
        if self.num_cols != other.num_rows {
            return Err(SonicError::LinearAlgebraError);
        }

        let mut result = SparseMatrix::new(self.num_rows, other.num_cols);
        
        // Simple implementation - could be optimized further
        for &(i, k, a_val) in &self.entries {
            for &(k2, j, b_val) in &other.entries {
                if k == k2 {
                    let existing_val = result.get(i, j);
                    let new_val = existing_val + a_val * b_val;
                    if !new_val.is_zero() {
                        // Remove old entry if exists, add new one
                        result.entries.retain(|&(r, c, _)| !(r == i && c == j));
                        result.add_entry(i, j, new_val);
                    }
                }
            }
        }

        Ok(result)
    }

    /// Transposes the sparse matrix
    pub fn transpose(&self) -> SparseMatrix {
        let mut result = SparseMatrix::new(self.num_cols, self.num_rows);
        
        for &(row, col, value) in &self.entries {
            result.add_entry(col, row, value);
        }

        result
    }

    /// Converts to dense matrix representation
    pub fn to_dense(&self) -> DenseMatrix {
        let mut data = vec![vec![Scalar::zero(); self.num_cols]; self.num_rows];
        
        for &(row, col, value) in &self.entries {
            data[row][col] = value;
        }

        DenseMatrix {
            data,
            num_rows: self.num_rows,
            num_cols: self.num_cols,
        }
    }

    /// Returns the number of non-zero entries
    pub fn nnz(&self) -> usize {
        self.entries.len()
    }
}

impl DenseMatrix {
    /// Creates a new dense matrix filled with zeros
    pub fn zeros(num_rows: usize, num_cols: usize) -> Self {
        Self {
            data: vec![vec![Scalar::zero(); num_cols]; num_rows],
            num_rows,
            num_cols,
        }
    }

    /// Creates an identity matrix
    pub fn identity(size: usize) -> Self {
        let mut matrix = Self::zeros(size, size);
        for i in 0..size {
            matrix.data[i][i] = Scalar::one();
        }
        matrix
    }

    /// Gets the value at (row, col)
    pub fn get(&self, row: usize, col: usize) -> Result<Scalar> {
        if row >= self.num_rows || col >= self.num_cols {
            return Err(SonicError::LinearAlgebraError);
        }
        Ok(self.data[row][col])
    }

    /// Sets the value at (row, col)
    pub fn set(&mut self, row: usize, col: usize, value: Scalar) -> Result<()> {
        if row >= self.num_rows || col >= self.num_cols {
            return Err(SonicError::LinearAlgebraError);
        }
        self.data[row][col] = value;
        Ok(())
    }

    /// Multiplies dense matrix by a vector
    pub fn multiply_vector(&self, vector: &[Scalar]) -> Result<Vec<Scalar>> {
        if vector.len() != self.num_cols {
            return Err(SonicError::LinearAlgebraError);
        }

        let result: Vec<Scalar> = (0..self.num_rows)
            .into_par_iter()
            .map(|row| {
                self.data[row].iter()
                    .zip(vector.iter())
                    .map(|(a, b)| *a * *b)
                    .fold(Scalar::zero(), |acc, x| acc + x)
            })
            .collect();

        Ok(result)
    }

    /// Multiplies two dense matrices
    pub fn multiply(&self, other: &DenseMatrix) -> Result<DenseMatrix> {
        if self.num_cols != other.num_rows {
            return Err(SonicError::LinearAlgebraError);
        }

        let mut result = DenseMatrix::zeros(self.num_rows, other.num_cols);

        result.data = (0..self.num_rows)
            .into_par_iter()
            .map(|i| {
                (0..other.num_cols)
                    .map(|j| {
                        (0..self.num_cols)
                            .map(|k| self.data[i][k] * other.data[k][j])
                            .fold(Scalar::zero(), |acc, x| acc + x)
                    })
                    .collect()
            })
            .collect();

        Ok(result)
    }

    /// Converts to sparse matrix representation
    pub fn to_sparse(&self) -> SparseMatrix {
        let mut sparse = SparseMatrix::new(self.num_rows, self.num_cols);
        
        for (i, row) in self.data.iter().enumerate() {
            for (j, &value) in row.iter().enumerate() {
                if !value.is_zero() {
                    sparse.add_entry(i, j, value);
                }
            }
        }

        sparse
    }
}

impl VectorOps {
    /// Computes the norm of a vector
    pub fn norm_squared(vector: &[Scalar]) -> Scalar {
        vector.iter().map(|&x| x * x).fold(Scalar::zero(), |acc, x| acc + x)
    }

    /// Normalizes a vector (if possible)
    pub fn normalize(vector: &[Scalar]) -> Result<Vec<Scalar>> {
        let norm_sq = Self::norm_squared(vector);
        if norm_sq.is_zero() {
            return Err(SonicError::LinearAlgebraError);
        }

        // For field elements, we can't compute square root directly
        // This is a simplified normalization
        let inv_norm_sq = norm_sq.inverse().ok_or(SonicError::LinearAlgebraError)?;
        Ok(vector.iter().map(|&x| x * inv_norm_sq).collect())
    }

    /// Computes the sum of all elements in a vector
    pub fn sum(vector: &[Scalar]) -> Scalar {
        vector.iter().fold(Scalar::zero(), |acc, &x| acc + x)
    }

    /// Scales a vector by a scalar
    pub fn scale(vector: &[Scalar], scalar: Scalar) -> Vec<Scalar> {
        vector.iter().map(|&x| x * scalar).collect()
    }

    /// Adds two vectors element-wise
    pub fn add(a: &[Scalar], b: &[Scalar]) -> Result<Vec<Scalar>> {
        if a.len() != b.len() {
            return Err(SonicError::LinearAlgebraError);
        }

        Ok(a.iter().zip(b.iter()).map(|(&ai, &bi)| ai + bi).collect())
    }

    /// Subtracts two vectors element-wise
    pub fn subtract(a: &[Scalar], b: &[Scalar]) -> Result<Vec<Scalar>> {
        if a.len() != b.len() {
            return Err(SonicError::LinearAlgebraError);
        }

        Ok(a.iter().zip(b.iter()).map(|(&ai, &bi)| ai - bi).collect())
    }
}

impl MatrixOps {
    /// Computes the Kronecker product of two matrices
    pub fn kronecker_product(
        a: &DenseMatrix,
        b: &DenseMatrix,
    ) -> DenseMatrix {
        let result_rows = a.num_rows * b.num_rows;
        let result_cols = a.num_cols * b.num_cols;
        let mut result = DenseMatrix::zeros(result_rows, result_cols);

        for i in 0..a.num_rows {
            for j in 0..a.num_cols {
                for p in 0..b.num_rows {
                    for q in 0..b.num_cols {
                        let row = i * b.num_rows + p;
                        let col = j * b.num_cols + q;
                        result.data[row][col] = a.data[i][j] * b.data[p][q];
                    }
                }
            }
        }

        result
    }

    /// Computes the trace of a square matrix
    pub fn trace(matrix: &DenseMatrix) -> Result<Scalar> {
        if matrix.num_rows != matrix.num_cols {
            return Err(SonicError::LinearAlgebraError);
        }

        let trace = (0..matrix.num_rows)
            .map(|i| matrix.data[i][i])
            .fold(Scalar::zero(), |acc, x| acc + x);

        Ok(trace)
    }

    /// Computes matrix transpose
    pub fn transpose(matrix: &DenseMatrix) -> DenseMatrix {
        let mut result = DenseMatrix::zeros(matrix.num_cols, matrix.num_rows);
        
        for i in 0..matrix.num_rows {
            for j in 0..matrix.num_cols {
                result.data[j][i] = matrix.data[i][j];
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_algebra_basic() {
        let a = vec![Scalar::one(), Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(4u64), Scalar::from(5u64), Scalar::from(6u64)];

        let result = LinearAlgebra::parallel_inner_product(&a, &b).unwrap();
        // Expected: 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        assert_eq!(result, Scalar::from(32u64));
    }

    #[test]
    fn test_sparse_matrix() {
        let mut matrix = SparseMatrix::new(3, 3);
        matrix.add_entry(0, 0, Scalar::one());
        matrix.add_entry(1, 1, Scalar::from(2u64));
        matrix.add_entry(2, 2, Scalar::from(3u64));

        let vector = vec![Scalar::one(), Scalar::from(2u64), Scalar::from(3u64)];
        let result = matrix.multiply_vector(&vector).unwrap();
        
        assert_eq!(result[0], Scalar::one());
        assert_eq!(result[1], Scalar::from(4u64));
        assert_eq!(result[2], Scalar::from(9u64));
    }

    #[test]
    fn test_dense_matrix() {
        let identity = DenseMatrix::identity(3);
        let vector = vec![Scalar::one(), Scalar::from(2u64), Scalar::from(3u64)];
        let result = identity.multiply_vector(&vector).unwrap();
        
        assert_eq!(result, vector); // Identity matrix should return same vector
    }

    #[test]
    fn test_vector_ops() {
        let a = vec![Scalar::one(), Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(4u64), Scalar::from(5u64), Scalar::from(6u64)];

        let sum = VectorOps::add(&a, &b).unwrap();
        assert_eq!(sum[0], Scalar::from(5u64));
        assert_eq!(sum[1], Scalar::from(7u64));
        assert_eq!(sum[2], Scalar::from(9u64));

        let scaled = VectorOps::scale(&a, Scalar::from(2u64));
        assert_eq!(scaled[0], Scalar::from(2u64));
        assert_eq!(scaled[1], Scalar::from(4u64));
        assert_eq!(scaled[2], Scalar::from(6u64));
    }

    #[test]
    fn test_matrix_ops() {
        let matrix = DenseMatrix::identity(2);
        let trace = MatrixOps::trace(&matrix).unwrap();
        assert_eq!(trace, Scalar::from(2u64)); // Trace of 2x2 identity is 2

        let transposed = MatrixOps::transpose(&matrix);
        assert_eq!(transposed.data, matrix.data); // Identity is symmetric
    }

    #[test]
    fn test_batch_operations() {
        let vectors = vec![
            vec![Scalar::one(), Scalar::from(2u64)],
            vec![Scalar::from(3u64), Scalar::from(4u64)],
            vec![Scalar::from(5u64), Scalar::from(6u64)],
        ];

        let sum = LinearAlgebra::batch_vector_add(&vectors).unwrap();
        assert_eq!(sum[0], Scalar::from(9u64)); // 1 + 3 + 5
        assert_eq!(sum[1], Scalar::from(12u64)); // 2 + 4 + 6

        let coeffs = vec![Scalar::one(), Scalar::from(2u64), Scalar::from(3u64)];
        let linear_comb = LinearAlgebra::vector_linear_combination(&vectors, &coeffs).unwrap();
        assert_eq!(linear_comb[0], Scalar::from(22u64)); // 1*1 + 2*3 + 3*5 = 1 + 6 + 15 = 22
        assert_eq!(linear_comb[1], Scalar::from(28u64)); // 1*2 + 2*4 + 3*6 = 2 + 8 + 18 = 28
    }
}