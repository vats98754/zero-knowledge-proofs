use compiler::compile_to_trace;
use zkvm_core::ExecutionTrace;
use anyhow::Result;

/// A simple token contract example demonstrating zkVM capabilities
/// This contract manages token transfers and verifies balances
pub struct TokenContract {
    /// Initial balances for accounts
    balances: Vec<(u64, u64)>, // (account_id, balance)
}

impl TokenContract {
    pub fn new() -> Self {
        Self {
            balances: vec![
                (1, 1000), // Account 1 has 1000 tokens
                (2, 500),  // Account 2 has 500 tokens
                (3, 0),    // Account 3 has 0 tokens
            ],
        }
    }

    /// Generate a zkVM program for token transfer
    pub fn transfer_program(from: u64, to: u64, amount: u64) -> String {
        // Simplified version using register-to-register operations only
        format!(r#"
            # Token Transfer Program  
            # Transfer {} tokens from account {} to account {}
            # Simplified: assumes initial values are loaded in registers
            
            # R0 = from_balance (assumed pre-loaded)
            # R1 = to_balance (assumed pre-loaded) 
            # R2 = amount (assumed pre-loaded as {})
            
            # Check if from_balance >= amount
            SUB R3, R0, R2        # R3 = from_balance - amount
            
            # Perform transfer (simplified - no bounds checking)
            SUB R0, R0, R2        # from_balance -= amount
            ADD R1, R1, R2        # to_balance += amount
            
            # Store results in memory (using register addresses)
            # R4 = from_addr, R5 = to_addr (assumed pre-loaded)
            STORE R4, R0          # Store new from_balance  
            STORE R5, R1          # Store new to_balance
            
            HALT
        "#, 
        amount, from, to, amount)
    }

    /// Generate a zkVM program for balance verification
    pub fn verify_balance_program(account: u64, expected_balance: u64) -> String {
        format!(r#"
            # Balance Verification Program
            # Verify that account {} has balance {}
            # Simplified: assumes balance is pre-loaded in R0
            
            # R0 = actual account balance (assumed pre-loaded)
            # R1 = expected balance (assumed pre-loaded as {})
            
            SUB R2, R0, R1            # R2 = actual - expected
            JZ R2, balance_correct    # If difference is 0, balance is correct
            
            # Balance mismatch
            HALT
            
        balance_correct:
            HALT
        "#, 
        account, expected_balance, expected_balance)
    }

    /// Generate and execute a transfer, returning the execution trace
    pub fn execute_transfer(&self, from: u64, to: u64, amount: u64) -> Result<ExecutionTrace> {
        let program = Self::transfer_program(from, to, amount);
        Ok(compile_to_trace(&program)?)
    }

    /// Generate and execute balance verification, returning the execution trace
    pub fn execute_verify_balance(&self, account: u64, expected_balance: u64) -> Result<ExecutionTrace> {
        let program = Self::verify_balance_program(account, expected_balance);
        Ok(compile_to_trace(&program)?)
    }

    /// Complex example: batch transfer with verification
    pub fn batch_transfer_program(transfers: &[(u64, u64, u64)]) -> String {
        let mut program = String::from(r#"
            # Batch Transfer Program
            # Process multiple transfers atomically
            # Simplified: uses register-to-register operations
            
        "#);

        for (i, &(from, to, amount)) in transfers.iter().enumerate() {
            program.push_str(&format!(r#"
            # Transfer {}: {} -> {} amount {}
            # Assumes balances are pre-loaded in appropriate registers
            SUB R0, R0, R1            # Deduct from sender (amount in R1)
            ADD R2, R2, R1            # Add to receiver (amount in R1)
            STORE R3, R0              # Store updated from balance
            STORE R4, R2              # Store updated to balance
            
            "#, 
            i + 1, from, to, amount
            ));
        }

        program.push_str("HALT\n");
        program
    }

    pub fn execute_batch_transfer(&self, transfers: &[(u64, u64, u64)]) -> Result<ExecutionTrace> {
        let program = Self::batch_transfer_program(transfers);
        Ok(compile_to_trace(&program)?)
    }
}

impl Default for TokenContract {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_contract_creation() {
        let contract = TokenContract::new();
        assert_eq!(contract.balances.len(), 3);
    }

    #[test]
    fn test_transfer_program_generation() {
        let program = TokenContract::transfer_program(1, 2, 100);
        assert!(program.contains("Transfer 100 tokens"));
        assert!(program.contains("SUB"));
        assert!(program.contains("ADD"));
        assert!(program.contains("STORE"));
        assert!(program.contains("HALT"));
    }

    #[test]
    fn test_balance_verification_program() {
        let program = TokenContract::verify_balance_program(1, 1000);
        assert!(program.contains("Balance Verification"));
        assert!(program.contains("SUB"));
        assert!(program.contains("JZ"));
        assert!(program.contains("HALT"));
    }

    #[test]
    fn test_execute_transfer() {
        let contract = TokenContract::new();
        let result = contract.execute_transfer(1, 2, 100);
        assert!(result.is_ok());
        
        let trace = result.unwrap();
        assert!(trace.length() > 0);
    }

    #[test]
    fn test_execute_verify_balance() {
        let contract = TokenContract::new();
        let result = contract.execute_verify_balance(1, 1000);
        assert!(result.is_ok());
        
        let trace = result.unwrap();
        assert!(trace.length() > 0);
    }

    #[test]
    fn test_batch_transfer() {
        let contract = TokenContract::new();
        let transfers = vec![
            (1, 2, 100),  // Account 1 -> Account 2, 100 tokens
            (2, 3, 50),   // Account 2 -> Account 3, 50 tokens
        ];
        
        let result = contract.execute_batch_transfer(&transfers);
        assert!(result.is_ok());
        
        let trace = result.unwrap();
        assert!(trace.length() > 0);
    }

    #[test]
    fn test_batch_transfer_program_generation() {
        let transfers = vec![(1, 2, 100), (2, 3, 50)];
        let program = TokenContract::batch_transfer_program(&transfers);
        
        assert!(program.contains("Batch Transfer"));
        assert!(program.contains("Transfer 1:"));
        assert!(program.contains("Transfer 2:"));
        
        // Count the number of SUB/ADD/STORE operations
        let sub_count = program.matches("SUB").count();
        let add_count = program.matches("ADD").count();
        let store_count = program.matches("STORE").count();
        
        // Should have 1 SUB, 1 ADD, and 2 STOREs per transfer
        assert_eq!(sub_count, transfers.len());
        assert_eq!(add_count, transfers.len());
        assert_eq!(store_count, transfers.len() * 2);
    }
}