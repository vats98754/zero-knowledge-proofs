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
        format!(r#"
            # Token Transfer Program
            # Transfer {} tokens from account {} to account {}
            
            # Load from account balance (simplified - from memory address {})
            LOAD R0, #{from_addr}     # R0 = from_balance
            
            # Load to account balance (from memory address {})
            LOAD R1, #{to_addr}       # R1 = to_balance
            
            # Check if from_balance >= amount
            SUB R2, R0, #{amount}     # R2 = from_balance - amount
            JZ R2, insufficient_funds # If result is 0, might be issue (simplified)
            
            # Perform transfer
            SUB R0, R0, #{amount}     # from_balance -= amount
            ADD R1, R1, #{amount}     # to_balance += amount
            
            # Store updated balances
            STORE #{from_addr}, R0    # Store new from_balance
            STORE #{to_addr}, R1      # Store new to_balance
            
            JUMP success
            
        insufficient_funds:
            # Set error flag
            HALT
            
        success:
            HALT
        "#, 
        amount, from, to,
        from_addr = from * 10,  // Simplified address mapping
        to_addr = to * 10,
        amount = amount,
        )
    }

    /// Generate a zkVM program for balance verification
    pub fn verify_balance_program(account: u64, expected_balance: u64) -> String {
        format!(r#"
            # Balance Verification Program
            # Verify that account {} has balance {}
            
            LOAD R0, #{addr}          # Load account balance
            SUB R1, R0, #{expected}   # R1 = actual - expected
            JZ R1, balance_correct    # If difference is 0, balance is correct
            
            # Balance mismatch
            HALT
            
        balance_correct:
            HALT
        "#, 
        account, expected_balance,
        addr = account * 10,
        expected = expected_balance,
        )
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
            
        "#);

        for (i, &(from, to, amount)) in transfers.iter().enumerate() {
            program.push_str(&format!(r#"
            # Transfer {}: {} -> {} amount {}
            LOAD R0, #{}              # Load from balance
            LOAD R1, #{}              # Load to balance
            SUB R0, R0, #{}           # Deduct from sender
            ADD R1, R1, #{}           # Add to receiver
            STORE #{}, R0             # Store updated from balance
            STORE #{}, R1             # Store updated to balance
            
            "#, 
            i + 1, from, to, amount,
            from * 10,     // from address
            to * 10,       // to address
            amount,        // amount to deduct
            amount,        // amount to add
            from * 10,     // store from address
            to * 10,       // store to address
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
        assert!(program.contains("LOAD"));
        assert!(program.contains("STORE"));
        assert!(program.contains("HALT"));
    }

    #[test]
    fn test_balance_verification_program() {
        let program = TokenContract::verify_balance_program(1, 1000);
        assert!(program.contains("Balance Verification"));
        assert!(program.contains("LOAD"));
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
        
        // Count the number of LOAD/STORE operations
        let load_count = program.matches("LOAD").count();
        let store_count = program.matches("STORE").count();
        
        // Should have 2 loads and 2 stores per transfer
        assert_eq!(load_count, transfers.len() * 2);
        assert_eq!(store_count, transfers.len() * 2);
    }
}