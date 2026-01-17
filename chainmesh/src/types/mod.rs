//! Core types for the ChainMesh blockchain
//!
//! This module defines the fundamental data structures:
//! - Blocks and block headers
//! - Transactions and transaction types
//! - Accounts and balances
//! - Addresses and identifiers

pub mod address;
pub mod block;
pub mod transaction;
pub mod account;
pub mod token;

pub use address::{Address, AddressType};
pub use block::{Block, BlockHeader, BlockHash};
pub use transaction::{Transaction, TransactionType, TxHash, SignedTransaction};
pub use account::{Account, AccountState};
pub use token::{MuCoin, TokenId, NFT};
