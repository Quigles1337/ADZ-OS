//! ChainMesh addresses
//!
//! Addresses are derived from public keys using μ-Hash.
//! Format: Base58Check encoding with version prefix.

use libmu_crypto::{MuHash, MuPublicKey};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Address length in bytes (20 bytes = 160 bits)
pub const ADDRESS_LENGTH: usize = 20;

/// Address type prefix for encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressType {
    /// Standard user account
    User = 0x00,
    /// Contract account
    Contract = 0x01,
    /// Validator account
    Validator = 0x02,
    /// System/reserved account
    System = 0xFF,
}

impl AddressType {
    /// Get version byte for address encoding
    pub fn version_byte(&self) -> u8 {
        match self {
            AddressType::User => 0x00,
            AddressType::Contract => 0x01,
            AddressType::Validator => 0x02,
            AddressType::System => 0xFF,
        }
    }

    /// Parse from version byte
    pub fn from_version_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(AddressType::User),
            0x01 => Some(AddressType::Contract),
            0x02 => Some(AddressType::Validator),
            0xFF => Some(AddressType::System),
            _ => None,
        }
    }
}

/// A ChainMesh address
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    /// Address type
    pub address_type: AddressType,
    /// The 20-byte address hash
    pub bytes: [u8; ADDRESS_LENGTH],
}

impl Address {
    /// Create a new address from raw bytes
    pub fn new(address_type: AddressType, bytes: [u8; ADDRESS_LENGTH]) -> Self {
        Self { address_type, bytes }
    }

    /// Derive address from public key
    pub fn from_public_key(public_key: &MuPublicKey) -> Self {
        let pk_bytes = public_key.to_bytes();
        let hash = MuHash::hash(&pk_bytes);

        // Take last 20 bytes of hash
        let mut bytes = [0u8; ADDRESS_LENGTH];
        bytes.copy_from_slice(&hash[12..32]);

        Self {
            address_type: AddressType::User,
            bytes,
        }
    }

    /// Create a contract address from deployer and nonce
    pub fn contract_address(deployer: &Address, nonce: u64) -> Self {
        let mut hasher = MuHash::new();
        hasher.update(&deployer.bytes);
        hasher.update(&nonce.to_le_bytes());
        hasher.update(b"contract");
        let hash = hasher.finalize();

        let mut bytes = [0u8; ADDRESS_LENGTH];
        bytes.copy_from_slice(&hash[12..32]);

        Self {
            address_type: AddressType::Contract,
            bytes,
        }
    }

    /// Create validator address from public key
    pub fn validator_address(public_key: &MuPublicKey) -> Self {
        let pk_bytes = public_key.to_bytes();
        let mut hasher = MuHash::new();
        hasher.update(&pk_bytes);
        hasher.update(b"validator");
        let hash = hasher.finalize();

        let mut bytes = [0u8; ADDRESS_LENGTH];
        bytes.copy_from_slice(&hash[12..32]);

        Self {
            address_type: AddressType::Validator,
            bytes,
        }
    }

    /// System address for protocol operations
    pub fn system() -> Self {
        Self {
            address_type: AddressType::System,
            bytes: [0u8; ADDRESS_LENGTH],
        }
    }

    /// Zero address (burn address)
    pub fn zero() -> Self {
        Self {
            address_type: AddressType::User,
            bytes: [0u8; ADDRESS_LENGTH],
        }
    }

    /// Check if this is the zero address
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    /// Encode to Base58Check string
    pub fn to_base58(&self) -> String {
        let mut data = Vec::with_capacity(ADDRESS_LENGTH + 5);
        data.push(self.address_type.version_byte());
        data.extend_from_slice(&self.bytes);

        // Checksum: first 4 bytes of double hash
        let hash1 = MuHash::hash(&data);
        let hash2 = MuHash::hash(&hash1);
        data.extend_from_slice(&hash2[0..4]);

        bs58::encode(data).into_string()
    }

    /// Decode from Base58Check string
    pub fn from_base58(s: &str) -> Result<Self, AddressError> {
        let data = bs58::decode(s)
            .into_vec()
            .map_err(|_| AddressError::InvalidBase58)?;

        if data.len() != ADDRESS_LENGTH + 5 {
            return Err(AddressError::InvalidLength);
        }

        // Verify checksum
        let payload = &data[..ADDRESS_LENGTH + 1];
        let checksum = &data[ADDRESS_LENGTH + 1..];

        let hash1 = MuHash::hash(payload);
        let hash2 = MuHash::hash(&hash1);

        if &hash2[0..4] != checksum {
            return Err(AddressError::InvalidChecksum);
        }

        let address_type = AddressType::from_version_byte(data[0])
            .ok_or(AddressError::InvalidVersion)?;

        let mut bytes = [0u8; ADDRESS_LENGTH];
        bytes.copy_from_slice(&data[1..ADDRESS_LENGTH + 1]);

        Ok(Self { address_type, bytes })
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Parse from hex string (assumes User type)
    pub fn from_hex(s: &str) -> Result<Self, AddressError> {
        let bytes_vec = hex::decode(s).map_err(|_| AddressError::InvalidHex)?;
        if bytes_vec.len() != ADDRESS_LENGTH {
            return Err(AddressError::InvalidLength);
        }

        let mut bytes = [0u8; ADDRESS_LENGTH];
        bytes.copy_from_slice(&bytes_vec);

        Ok(Self {
            address_type: AddressType::User,
            bytes,
        })
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({:?}, {})", self.address_type, self.to_base58())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

/// Address parsing errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("Invalid Base58 encoding")]
    InvalidBase58,
    #[error("Invalid address length")]
    InvalidLength,
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Invalid version byte")]
    InvalidVersion,
    #[error("Invalid hex encoding")]
    InvalidHex,
}

#[cfg(test)]
mod tests {
    use super::*;
    use libmu_crypto::MuKeyPair;

    #[test]
    fn test_address_from_public_key() {
        let keypair = MuKeyPair::from_seed(b"test seed");
        let address = Address::from_public_key(keypair.public_key());

        assert_eq!(address.address_type, AddressType::User);
        assert!(!address.is_zero());
    }

    #[test]
    fn test_address_base58_roundtrip() {
        let keypair = MuKeyPair::from_seed(b"roundtrip test");
        let address = Address::from_public_key(keypair.public_key());

        let encoded = address.to_base58();
        let decoded = Address::from_base58(&encoded).unwrap();

        assert_eq!(address, decoded);
    }

    #[test]
    fn test_contract_address() {
        let deployer = Address::from_hex("0000000000000000000000000000000000000001").unwrap();
        let contract1 = Address::contract_address(&deployer, 0);
        let contract2 = Address::contract_address(&deployer, 1);

        assert_eq!(contract1.address_type, AddressType::Contract);
        assert_ne!(contract1, contract2);
    }

    #[test]
    fn test_zero_address() {
        let zero = Address::zero();
        assert!(zero.is_zero());
    }
}
