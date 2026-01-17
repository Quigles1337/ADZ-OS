//! Error types for MuonNet
//!
//! Comprehensive error handling for all MuonNet operations.

use thiserror::Error;

/// Result type for MuonNet operations
pub type MuonResult<T> = Result<T, MuonError>;

/// MuonNet error types
#[derive(Debug, Error)]
pub enum MuonError {
    // ========== Crypto Errors ==========

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid key material
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Key exchange failed
    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),

    // ========== Cell Errors ==========

    /// Invalid cell format
    #[error("Invalid cell: {0}")]
    InvalidCell(String),

    /// Cell too large
    #[error("Cell payload too large: {0} bytes (max {1})")]
    CellTooLarge(usize, usize),

    /// Unknown cell type
    #[error("Unknown cell type: {0}")]
    UnknownCellType(u8),

    /// Cell integrity check failed
    #[error("Cell integrity check failed")]
    CellIntegrityFailed,

    // ========== Circuit Errors ==========

    /// Circuit creation failed
    #[error("Circuit creation failed: {0}")]
    CircuitCreationFailed(String),

    /// Circuit not found
    #[error("Circuit not found: {0}")]
    CircuitNotFound(u32),

    /// Circuit closed
    #[error("Circuit closed")]
    CircuitClosed,

    /// Circuit timeout
    #[error("Circuit timeout")]
    CircuitTimeout,

    /// No path available
    #[error("No path available through network")]
    NoPathAvailable,

    /// Too many circuits
    #[error("Maximum circuits reached")]
    TooManyCircuits,

    /// Invalid circuit state
    #[error("Invalid circuit state: {0}")]
    InvalidCircuitState(String),

    /// Circuit too short
    #[error("Circuit too short: {0} hops (minimum 3)")]
    CircuitTooShort(usize),

    /// Circuit not ready
    #[error("Circuit not ready: {0}")]
    CircuitNotReady(u32),

    /// No path available
    #[error("No path available: {0}")]
    NoPath(String),

    // ========== Stream Errors ==========

    /// Stream creation failed
    #[error("Stream creation failed: {0}")]
    StreamCreationFailed(String),

    /// Stream not found
    #[error("Stream not found: {0}")]
    StreamNotFound(u16),

    /// Stream closed
    #[error("Stream closed: {0}")]
    StreamClosed(u16),

    /// Stream limit reached
    #[error("Stream limit reached for circuit {0}")]
    StreamLimitReached(u32),

    /// Flow control violation
    #[error("Flow control violation: {0}")]
    FlowControlViolation(String),

    /// Connection refused
    #[error("Connection refused: {0}")]
    ConnectionRefused(String),

    /// Connection timeout
    #[error("Connection timeout")]
    ConnectionTimeout,

    /// Invalid address
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    // ========== Relay Errors ==========

    /// Relay not found
    #[error("Relay not found: {0}")]
    RelayNotFound(String),

    /// Relay connection failed
    #[error("Relay connection failed: {0}")]
    RelayConnectionFailed(String),

    /// Relay handshake failed
    #[error("Relay handshake failed: {0}")]
    RelayHandshakeFailed(String),

    /// Invalid relay descriptor
    #[error("Invalid relay descriptor: {0}")]
    InvalidRelayDescriptor(String),

    /// Relay overloaded
    #[error("Relay overloaded")]
    RelayOverloaded,

    // ========== Hidden Service Errors ==========

    /// Invalid .muon address
    #[error("Invalid .muon address: {0}")]
    InvalidMuonAddress(String),

    /// Hidden service not found
    #[error("Hidden service not found")]
    HiddenServiceNotFound,

    /// Introduction point failed
    #[error("Introduction point failed: {0}")]
    IntroductionFailed(String),

    /// Rendezvous failed
    #[error("Rendezvous failed: {0}")]
    RendezvousFailed(String),

    /// Hidden service failed
    #[error("Hidden service failed: {0}")]
    HiddenServiceFailed(String),

    // ========== Directory Errors ==========

    /// Directory fetch failed
    #[error("Directory fetch failed: {0}")]
    DirectoryFetchFailed(String),

    /// Invalid consensus
    #[error("Invalid consensus: {0}")]
    InvalidConsensus(String),

    /// Consensus expired
    #[error("Consensus expired")]
    ConsensusExpired,

    /// Consensus failed
    #[error("Consensus failed: {0}")]
    ConsensusFailed(String),

    /// No directory available
    #[error("No directory available")]
    NoDirectoryAvailable,

    // ========== Protocol Errors ==========

    /// Protocol version mismatch
    #[error("Protocol version mismatch: expected {0}, got {1}")]
    ProtocolVersionMismatch(u8, u8),

    /// Invalid protocol message
    #[error("Invalid protocol message: {0}")]
    InvalidProtocolMessage(String),

    /// Unexpected message
    #[error("Unexpected message: {0}")]
    UnexpectedMessage(String),

    // ========== Network Errors ==========

    /// IO error
    #[error("IO error: {0}")]
    Io(String),

    /// Network unreachable
    #[error("Network unreachable")]
    NetworkUnreachable,

    /// DNS resolution failed
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    // ========== Configuration Errors ==========

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Missing configuration
    #[error("Missing configuration: {0}")]
    MissingConfiguration(String),

    // ========== Internal Errors ==========

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Channel closed
    #[error("Channel closed")]
    ChannelClosed,

    /// Shutdown in progress
    #[error("Shutdown in progress")]
    ShuttingDown,
}

impl MuonError {
    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(self,
            MuonError::CircuitTimeout |
            MuonError::ConnectionTimeout |
            MuonError::RelayOverloaded |
            MuonError::NetworkUnreachable
        )
    }

    /// Check if this error should trigger circuit rebuild
    pub fn should_rebuild_circuit(&self) -> bool {
        matches!(self,
            MuonError::CircuitClosed |
            MuonError::CellIntegrityFailed |
            MuonError::RelayConnectionFailed(_) |
            MuonError::DecryptionFailed(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = MuonError::CircuitNotFound(42);
        assert_eq!(err.to_string(), "Circuit not found: 42");
    }

    #[test]
    fn test_is_recoverable() {
        assert!(MuonError::CircuitTimeout.is_recoverable());
        assert!(!MuonError::CircuitClosed.is_recoverable());
    }

    #[test]
    fn test_should_rebuild() {
        assert!(MuonError::CircuitClosed.should_rebuild_circuit());
        assert!(!MuonError::InvalidAddress("test".into()).should_rebuild_circuit());
    }
}
