//! Transaction types for ChainMesh
//!
//! Supports multiple transaction types:
//! - Transfer: Send MUC between accounts
//! - Stake: Stake MUC for validation
//! - Unstake: Withdraw staked MUC
//! - ContractCall: Execute smart contract
//! - ContractDeploy: Deploy new contract
//! - NFTMint: Create new NFT
//! - NFTTransfer: Transfer NFT ownership

use super::{Address, MuCoin, TokenId};
use libmu_crypto::{MuHash, MuKeyPair, MuSignature};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt;

/// Transaction hash (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct TxHash(pub [u8; 32]);

impl TxHash {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse from hex
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Convert to raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for TxHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for TxHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<TxHash> for [u8; 32] {
    fn from(hash: TxHash) -> [u8; 32] {
        hash.0
    }
}

impl fmt::Debug for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxHash({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Transaction types
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionType {
    /// Transfer MUC between accounts
    Transfer {
        to: Address,
        amount: MuCoin,
    },

    /// Transfer custom token
    TokenTransfer {
        token_id: TokenId,
        to: Address,
        amount: u64,
    },

    /// Stake MUC for validation
    Stake {
        amount: MuCoin,
    },

    /// Unstake MUC (begins unbonding period)
    Unstake {
        amount: MuCoin,
    },

    /// Withdraw unbonded stake
    WithdrawStake,

    /// Delegate stake to validator
    Delegate {
        validator: Address,
        amount: MuCoin,
    },

    /// Undelegate from validator
    Undelegate {
        validator: Address,
        amount: MuCoin,
    },

    /// Deploy smart contract
    ContractDeploy {
        code: Vec<u8>,
        init_args: Vec<u8>,
    },

    /// Call smart contract
    ContractCall {
        contract: Address,
        method: String,
        args: Vec<u8>,
        value: MuCoin,
    },

    /// Mint new NFT
    NFTMint {
        collection: Address,
        metadata_uri: String,
        content_hash: [u8; 32],
        royalty_bps: u16,
    },

    /// Transfer NFT
    NFTTransfer {
        token_id: [u8; 32],
        to: Address,
    },

    /// Burn NFT
    NFTBurn {
        token_id: [u8; 32],
    },

    /// Create NFT collection
    CreateCollection {
        name: String,
        symbol: String,
        max_supply: Option<u64>,
    },

    /// Register as validator
    RegisterValidator {
        commission_rate: u16, // basis points
        metadata: String,
    },

    /// Update validator info
    UpdateValidator {
        commission_rate: Option<u16>,
        metadata: Option<String>,
    },

    /// Vote on governance proposal
    GovernanceVote {
        proposal_id: u64,
        vote: bool,
    },
}

impl TransactionType {
    /// Get transaction type name
    pub fn name(&self) -> &'static str {
        match self {
            TransactionType::Transfer { .. } => "Transfer",
            TransactionType::TokenTransfer { .. } => "TokenTransfer",
            TransactionType::Stake { .. } => "Stake",
            TransactionType::Unstake { .. } => "Unstake",
            TransactionType::WithdrawStake => "WithdrawStake",
            TransactionType::Delegate { .. } => "Delegate",
            TransactionType::Undelegate { .. } => "Undelegate",
            TransactionType::ContractDeploy { .. } => "ContractDeploy",
            TransactionType::ContractCall { .. } => "ContractCall",
            TransactionType::NFTMint { .. } => "NFTMint",
            TransactionType::NFTTransfer { .. } => "NFTTransfer",
            TransactionType::NFTBurn { .. } => "NFTBurn",
            TransactionType::CreateCollection { .. } => "CreateCollection",
            TransactionType::RegisterValidator { .. } => "RegisterValidator",
            TransactionType::UpdateValidator { .. } => "UpdateValidator",
            TransactionType::GovernanceVote { .. } => "GovernanceVote",
        }
    }

    /// Estimate gas for this transaction type
    pub fn estimate_gas(&self) -> u64 {
        match self {
            TransactionType::Transfer { .. } => 21_000,
            TransactionType::TokenTransfer { .. } => 35_000,
            TransactionType::Stake { .. } => 50_000,
            TransactionType::Unstake { .. } => 50_000,
            TransactionType::WithdrawStake => 30_000,
            TransactionType::Delegate { .. } => 50_000,
            TransactionType::Undelegate { .. } => 50_000,
            TransactionType::ContractDeploy { code, .. } => {
                100_000 + (code.len() as u64 * 200)
            }
            TransactionType::ContractCall { args, .. } => {
                50_000 + (args.len() as u64 * 10)
            }
            TransactionType::NFTMint { .. } => 100_000,
            TransactionType::NFTTransfer { .. } => 50_000,
            TransactionType::NFTBurn { .. } => 30_000,
            TransactionType::CreateCollection { .. } => 150_000,
            TransactionType::RegisterValidator { .. } => 100_000,
            TransactionType::UpdateValidator { .. } => 50_000,
            TransactionType::GovernanceVote { .. } => 30_000,
        }
    }
}

/// Unsigned transaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction version
    pub version: u32,
    /// Chain ID (to prevent replay attacks)
    pub chain_id: u64,
    /// Sender address
    pub from: Address,
    /// Sender's nonce (prevents replay)
    pub nonce: u64,
    /// Transaction type and data
    pub tx_type: TransactionType,
    /// Gas price in muons per gas unit
    pub gas_price: u64,
    /// Maximum gas to use
    pub gas_limit: u64,
    /// Expiry timestamp (0 = no expiry)
    pub expires_at: u64,
}

impl Transaction {
    /// Current transaction version
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new transfer transaction
    pub fn transfer(
        chain_id: u64,
        from: Address,
        to: Address,
        amount: MuCoin,
        nonce: u64,
        gas_price: u64,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            chain_id,
            from,
            nonce,
            tx_type: TransactionType::Transfer { to, amount },
            gas_price,
            gas_limit: 21_000,
            expires_at: 0,
        }
    }

    /// Create a stake transaction
    pub fn stake(
        chain_id: u64,
        from: Address,
        amount: MuCoin,
        nonce: u64,
        gas_price: u64,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            chain_id,
            from,
            nonce,
            tx_type: TransactionType::Stake { amount },
            gas_price,
            gas_limit: 50_000,
            expires_at: 0,
        }
    }

    /// Create a contract call transaction
    pub fn contract_call(
        chain_id: u64,
        from: Address,
        contract: Address,
        method: String,
        args: Vec<u8>,
        value: MuCoin,
        nonce: u64,
        gas_price: u64,
        gas_limit: u64,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            chain_id,
            from,
            nonce,
            tx_type: TransactionType::ContractCall {
                contract,
                method,
                args,
                value,
            },
            gas_price,
            gas_limit,
            expires_at: 0,
        }
    }

    /// Compute transaction hash
    pub fn hash(&self) -> TxHash {
        let encoded = bincode::serialize(self).unwrap_or_default();
        TxHash(MuHash::hash(&encoded))
    }

    /// Get signing message
    pub fn signing_message(&self) -> [u8; 32] {
        let mut hasher = MuHash::new();
        hasher.update(&self.hash().0);
        hasher.update(b"chainmesh-tx-sign-v1");
        hasher.finalize()
    }

    /// Calculate maximum fee for this transaction
    pub fn max_fee(&self) -> MuCoin {
        MuCoin::from_muons(self.gas_price.saturating_mul(self.gas_limit))
    }

    /// Validate transaction structure
    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.version != Self::CURRENT_VERSION {
            return Err(TransactionError::InvalidVersion);
        }

        if self.gas_limit == 0 {
            return Err(TransactionError::InvalidGasLimit);
        }

        if self.gas_price == 0 {
            return Err(TransactionError::InvalidGasPrice);
        }

        // Type-specific validation
        match &self.tx_type {
            TransactionType::Transfer { amount, .. } => {
                if amount.is_zero() {
                    return Err(TransactionError::ZeroAmount);
                }
            }
            TransactionType::Stake { amount } => {
                if amount.is_zero() {
                    return Err(TransactionError::ZeroAmount);
                }
            }
            TransactionType::ContractDeploy { code, .. } => {
                if code.is_empty() {
                    return Err(TransactionError::EmptyCode);
                }
                if code.len() > 24 * 1024 { // 24KB limit
                    return Err(TransactionError::CodeTooLarge);
                }
            }
            _ => {}
        }

        Ok(())
    }
}

/// Signed transaction ready for broadcast
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The unsigned transaction
    pub transaction: Transaction,
    /// Signature over the transaction
    #[serde_as(as = "[_; 64]")]
    pub signature: [u8; 64],
}

impl SignedTransaction {
    /// Sign a transaction
    pub fn sign(transaction: Transaction, keypair: &MuKeyPair) -> Self {
        let message = transaction.signing_message();
        let sig = keypair.sign(&message);

        Self {
            transaction,
            signature: sig.to_bytes(),
        }
    }

    /// Get transaction hash
    pub fn hash(&self) -> TxHash {
        self.transaction.hash()
    }

    /// Verify signature with known public key
    pub fn verify_with_key(&self, public_key: &libmu_crypto::MuPublicKey) -> Result<(), TransactionError> {
        let message = self.transaction.signing_message();
        let sig = MuSignature::from_bytes(&self.signature)
            .map_err(|_| TransactionError::InvalidSignature)?;

        public_key.verify(&message, &sig)
            .map_err(|_| TransactionError::InvalidSignature)
    }

    /// Simple signature verification (placeholder)
    /// In production, this would recover the public key from the signature
    /// and verify against the sender address
    pub fn verify(&self) -> bool {
        // For now, just check that signature is not all zeros
        // Real implementation would use signature recovery
        !self.signature.iter().all(|&b| b == 0)
    }

    /// Get sender address
    pub fn sender(&self) -> &Address {
        &self.transaction.from
    }

    /// Get transaction type name
    pub fn tx_type_name(&self) -> &'static str {
        self.transaction.tx_type.name()
    }
}

/// Transaction receipt (result of execution)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Transaction hash
    pub tx_hash: TxHash,
    /// Block hash containing this transaction
    pub block_hash: super::BlockHash,
    /// Block height
    pub block_height: u64,
    /// Index in block
    pub tx_index: u32,
    /// Sender
    pub from: Address,
    /// Recipient (if applicable)
    pub to: Option<Address>,
    /// Contract address (if contract creation)
    pub contract_address: Option<Address>,
    /// Gas used
    pub gas_used: u64,
    /// Execution status
    pub status: ExecutionStatus,
    /// Log events emitted
    pub logs: Vec<LogEntry>,
    /// Return data (if any)
    pub return_data: Vec<u8>,
}

/// Execution status
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Transaction succeeded
    Success,
    /// Transaction failed with error
    Failed(String),
    /// Transaction reverted
    Reverted,
    /// Out of gas
    OutOfGas,
}

impl ExecutionStatus {
    /// Check if successful
    pub fn is_success(&self) -> bool {
        matches!(self, ExecutionStatus::Success)
    }
}

/// Log entry from contract execution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    /// Contract that emitted the log
    pub address: Address,
    /// Indexed topics (up to 4)
    pub topics: Vec<[u8; 32]>,
    /// Log data
    pub data: Vec<u8>,
}

/// Transaction-related errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransactionError {
    #[error("Invalid transaction version")]
    InvalidVersion,
    #[error("Invalid gas limit")]
    InvalidGasLimit,
    #[error("Invalid gas price")]
    InvalidGasPrice,
    #[error("Zero amount not allowed")]
    ZeroAmount,
    #[error("Empty contract code")]
    EmptyCode,
    #[error("Contract code too large")]
    CodeTooLarge,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Transaction expired")]
    Expired,
    #[error("Transaction already in pool")]
    AlreadyInPool,
    #[error("Transaction not found")]
    NotFound,
}

#[cfg(test)]
mod tests {
    use super::*;
    use libmu_crypto::MuKeyPair;

    fn test_address() -> Address {
        let keypair = MuKeyPair::from_seed(b"test");
        Address::from_public_key(keypair.public_key())
    }

    #[test]
    fn test_transfer_transaction() {
        let from = test_address();
        let to = Address::from_hex("0000000000000000000000000000000000000001").unwrap();

        let tx = Transaction::transfer(
            1, // chain_id
            from.clone(),
            to,
            MuCoin::from_muc(100),
            0, // nonce
            1000, // gas_price
        );

        assert!(tx.validate().is_ok());
        assert_eq!(tx.tx_type.name(), "Transfer");
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = MuKeyPair::from_seed(b"signer");
        let from = Address::from_public_key(keypair.public_key());
        let to = Address::zero();

        let tx = Transaction::transfer(
            1,
            from,
            to,
            MuCoin::from_muc(50),
            0,
            1000,
        );

        let signed = SignedTransaction::sign(tx, &keypair);

        assert!(signed.verify_with_key(keypair.public_key()).is_ok());
        assert!(signed.verify()); // Simple verification
    }

    #[test]
    fn test_tx_hash_deterministic() {
        let from = test_address();
        let to = Address::zero();

        let tx1 = Transaction::transfer(1, from.clone(), to.clone(), MuCoin::from_muc(1), 0, 1000);
        let tx2 = Transaction::transfer(1, from, to, MuCoin::from_muc(1), 0, 1000);

        assert_eq!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_gas_estimation() {
        let transfer = TransactionType::Transfer {
            to: Address::zero(),
            amount: MuCoin::from_muc(1),
        };
        assert_eq!(transfer.estimate_gas(), 21_000);

        let deploy = TransactionType::ContractDeploy {
            code: vec![0u8; 1000],
            init_args: vec![],
        };
        assert_eq!(deploy.estimate_gas(), 100_000 + 1000 * 200);
    }
}
