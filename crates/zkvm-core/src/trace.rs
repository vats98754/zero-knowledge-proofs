use serde::{Deserialize, Serialize};

/// A single row in the execution trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRow {
    pub cells: Vec<u64>,
}

impl TraceRow {
    pub fn new(cells: Vec<u64>) -> Self {
        Self { cells }
    }

    pub fn len(&self) -> usize {
        self.cells.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<u64> {
        self.cells.get(index).copied()
    }
}

/// Execution trace containing the complete execution history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    width: usize,
    rows: Vec<TraceRow>,
}

impl ExecutionTrace {
    pub fn new(width: usize) -> Self {
        Self {
            width,
            rows: Vec::new(),
        }
    }

    pub fn add_row(&mut self, row: TraceRow) {
        assert_eq!(row.len(), self.width, "Row width must match trace width");
        self.rows.push(row);
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn length(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn rows(&self) -> &[TraceRow] {
        &self.rows
    }

    pub fn get_row(&self, index: usize) -> Option<&TraceRow> {
        self.rows.get(index)
    }

    pub fn get_column(&self, col_index: usize) -> Vec<u64> {
        self.rows
            .iter()
            .map(|row| row.get(col_index).unwrap_or(0))
            .collect()
    }

    /// Convert trace to matrix format for backend consumption
    pub fn to_matrix(&self) -> Vec<Vec<u64>> {
        self.rows.iter().map(|row| row.cells.clone()).collect()
    }

    /// Get trace statistics for debugging and optimization
    pub fn stats(&self) -> TraceStats {
        TraceStats {
            width: self.width,
            length: self.length(),
            total_cells: self.width * self.length(),
            non_zero_cells: self.rows
                .iter()
                .flat_map(|row| &row.cells)
                .filter(|&&cell| cell != 0)
                .count(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStats {
    pub width: usize,
    pub length: usize,
    pub total_cells: usize,
    pub non_zero_cells: usize,
}

impl TraceStats {
    pub fn sparsity(&self) -> f64 {
        if self.total_cells == 0 {
            0.0
        } else {
            self.non_zero_cells as f64 / self.total_cells as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_creation() {
        let trace = ExecutionTrace::new(10);
        assert_eq!(trace.width(), 10);
        assert_eq!(trace.length(), 0);
        assert!(trace.is_empty());
    }

    #[test]
    fn test_trace_operations() {
        let mut trace = ExecutionTrace::new(3);
        
        let row1 = TraceRow::new(vec![1, 2, 3]);
        let row2 = TraceRow::new(vec![4, 5, 6]);
        
        trace.add_row(row1);
        trace.add_row(row2);
        
        assert_eq!(trace.length(), 2);
        assert!(!trace.is_empty());
        
        let column0 = trace.get_column(0);
        assert_eq!(column0, vec![1, 4]);
        
        let matrix = trace.to_matrix();
        assert_eq!(matrix, vec![vec![1, 2, 3], vec![4, 5, 6]]);
    }

    #[test]
    fn test_trace_stats() {
        let mut trace = ExecutionTrace::new(3);
        trace.add_row(TraceRow::new(vec![1, 0, 3]));
        trace.add_row(TraceRow::new(vec![0, 5, 0]));
        
        let stats = trace.stats();
        assert_eq!(stats.width, 3);
        assert_eq!(stats.length, 2);
        assert_eq!(stats.total_cells, 6);
        assert_eq!(stats.non_zero_cells, 3);
        assert_eq!(stats.sparsity(), 0.5);
    }

    #[test]
    #[should_panic(expected = "Row width must match trace width")]
    fn test_mismatched_row_width() {
        let mut trace = ExecutionTrace::new(3);
        let row = TraceRow::new(vec![1, 2]); // Wrong width
        trace.add_row(row);
    }
}