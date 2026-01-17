//! MuonNet: Privacy Networking Layer for μOS
//!
//! A Tor-inspired onion routing network using μ-cryptography for
//! privacy-preserving communication.
//!
//! # Architecture
//!
//! MuonNet consists of several layers:
//!
//! 1. **Crypto Layer** - Onion encryption using μ-Spiral cipher
//! 2. **Cell Layer** - Fixed-size cells for traffic analysis resistance
//! 3. **Circuit Layer** - 3-hop circuits through relay network
//! 4. **Stream Layer** - Multiplexed TCP streams over circuits
//! 5. **Hidden Services** - .muon addresses for anonymous services
//!
//! # Key Concepts
//!
//! - **Relay**: A node that forwards encrypted traffic
//! - **Circuit**: A path through 3+ relays with layered encryption
//! - **Cell**: Fixed 512-byte unit of communication
//! - **Stream**: A TCP connection tunneled through a circuit
//! - **Hidden Service**: A service accessible only through MuonNet
//!
//! # μ-Cryptography Integration
//!
//! MuonNet uses the μ-cryptography primitives:
//! - μ-Spiral AEAD for cell encryption
//! - μ-KDF for key derivation during circuit building
//! - μ-Signatures for relay identity verification
//! - μ-Hash for .muon address generation
//!
//! # Example
//!
//! ```ignore
//! use muonnet::prelude::*;
//!
//! // Create a MuonNet client
//! let client = MuonClient::new(config).await?;
//!
//! // Build a circuit through the network
//! let circuit = client.create_circuit().await?;
//!
//! // Open a stream to a destination
//! let stream = circuit.connect("example.com:80").await?;
//!
//! // Or connect to a hidden service
//! let stream = circuit.connect("abc123...xyz.muon:80").await?;
//! ```

pub mod crypto;
pub mod cell;
pub mod circuit;
pub mod relay;
pub mod stream;
pub mod hidden;
pub mod directory;
pub mod client;
pub mod config;
pub mod error;

pub use error::{MuonError, MuonResult};
pub use config::MuonConfig;
pub use client::MuonClient;
pub use circuit::{Circuit, CircuitId, CircuitBuilder};
pub use relay::{RelayDescriptor, RelayId, RelayFlags};
pub use hidden::{HiddenService, MuonAddress, HiddenServiceDescriptor};
pub use stream::{MuonStream, StreamManager};
pub use directory::{DirectoryCache, Consensus};

/// Prelude for common imports
pub mod prelude {
    pub use crate::{
        MuonError, MuonResult, MuonConfig, MuonClient,
        Circuit, CircuitId, CircuitBuilder,
        RelayDescriptor, RelayId, RelayFlags,
        HiddenService, MuonAddress,
        MuonStream, StreamManager,
        DirectoryCache, Consensus,
        cell::{Cell, CellType, RelayCell},
    };
}

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Default cell size (bytes)
pub const CELL_SIZE: usize = 512;

/// Default circuit length (hops)
pub const DEFAULT_CIRCUIT_LENGTH: usize = 3;

/// Maximum circuit length
pub const MAX_CIRCUIT_LENGTH: usize = 8;

/// Maximum streams per circuit
pub const MAX_STREAMS_PER_CIRCUIT: usize = 65535;

/// Cell payload size (cell size minus header)
pub const CELL_PAYLOAD_SIZE: usize = CELL_SIZE - 5; // 5 byte header

/// .muon address length (base32 encoded)
pub const MUON_ADDRESS_LENGTH: usize = 56;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(CELL_SIZE, 512);
        assert_eq!(DEFAULT_CIRCUIT_LENGTH, 3);
        assert_eq!(CELL_PAYLOAD_SIZE, 507);
    }
}
