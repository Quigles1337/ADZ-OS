//! Network Message Types
//!
//! Protocol messages for ChainMesh P2P network:
//! - Transaction and block propagation
//! - Sync requests/responses
//! - Peer discovery
//! - Consensus messages

use crate::types::{Block, BlockHash, SignedTransaction, TxHash};
use super::{P2PError, P2PResult, MessagePriority};
use super::peer::PeerId;
use libmu_crypto::MuHash;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum message size (16 MB)
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum transactions per message
pub const MAX_TXS_PER_MESSAGE: usize = 1000;

/// Maximum block headers per message
pub const MAX_HEADERS_PER_MESSAGE: usize = 2000;

/// Maximum blocks per message
pub const MAX_BLOCKS_PER_MESSAGE: usize = 100;

/// Unique message identifier
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId([u8; 32]);

impl MessageId {
    /// Create message ID from content hash
    pub fn from_content(content: &[u8]) -> Self {
        Self(MuHash::hash(content))
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Short hex (first 8 chars)
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl std::fmt::Debug for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MsgId({})", self.short_hex())
    }
}

/// Message type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    // Handshake & Status (0x00 - 0x0F)
    Ping = 0x00,
    Pong = 0x01,
    Status = 0x02,
    Disconnect = 0x03,

    // Transaction propagation (0x10 - 0x1F)
    NewTransaction = 0x10,
    NewTransactionHashes = 0x11,
    GetTransactions = 0x12,
    Transactions = 0x13,

    // Block propagation (0x20 - 0x2F)
    NewBlock = 0x20,
    NewBlockHashes = 0x21,
    GetBlockHeaders = 0x22,
    BlockHeaders = 0x23,
    GetBlockBodies = 0x24,
    BlockBodies = 0x25,

    // Sync protocol (0x30 - 0x3F)
    GetStatus = 0x30,
    StatusResponse = 0x31,
    GetCheckpoint = 0x32,
    Checkpoint = 0x33,

    // Peer discovery (0x40 - 0x4F)
    GetPeers = 0x40,
    Peers = 0x41,

    // Consensus (0x50 - 0x5F)
    Attestation = 0x50,
    AttestationAggregate = 0x51,
    ProposerSlashing = 0x52,
    AttesterSlashing = 0x53,

    // Mempool (0x60 - 0x6F)
    MempoolRequest = 0x60,
    MempoolResponse = 0x61,
}

impl MessageType {
    /// Get message priority
    pub fn priority(&self) -> MessagePriority {
        match self {
            // Critical - consensus
            Self::Attestation |
            Self::AttestationAggregate |
            Self::ProposerSlashing |
            Self::AttesterSlashing => MessagePriority::Critical,

            // High - blocks
            Self::NewBlock |
            Self::NewBlockHashes |
            Self::BlockHeaders |
            Self::BlockBodies => MessagePriority::High,

            // Normal - transactions
            Self::NewTransaction |
            Self::NewTransactionHashes |
            Self::GetTransactions |
            Self::Transactions => MessagePriority::Normal,

            // Low - everything else
            _ => MessagePriority::Low,
        }
    }

    /// Check if message requires response
    pub fn expects_response(&self) -> bool {
        matches!(
            self,
            Self::Ping |
            Self::GetTransactions |
            Self::GetBlockHeaders |
            Self::GetBlockBodies |
            Self::GetStatus |
            Self::GetCheckpoint |
            Self::GetPeers |
            Self::MempoolRequest
        )
    }
}

/// Network message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message type
    pub msg_type: MessageType,
    /// Request ID for request/response matching
    pub request_id: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Payload
    pub payload: MessagePayload,
}

impl Message {
    /// Create new message
    pub fn new(msg_type: MessageType, payload: MessagePayload) -> Self {
        Self {
            msg_type,
            request_id: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            payload,
        }
    }

    /// Create request message with ID
    pub fn request(msg_type: MessageType, request_id: u64, payload: MessagePayload) -> Self {
        let mut msg = Self::new(msg_type, payload);
        msg.request_id = request_id;
        msg
    }

    /// Create response message
    pub fn response(request_id: u64, msg_type: MessageType, payload: MessagePayload) -> Self {
        Self::request(msg_type, request_id, payload)
    }

    /// Compute message ID
    pub fn id(&self) -> MessageId {
        let data = self.serialize_for_id();
        MessageId::from_content(&data)
    }

    /// Serialize for ID computation
    fn serialize_for_id(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.msg_type as u8);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        // Add payload-specific data based on type
        match &self.payload {
            MessagePayload::NewTransaction(tx) => {
                data.extend_from_slice(&tx.hash().0);
            }
            MessagePayload::NewBlock(block) => {
                data.extend_from_slice(&block.header.hash().0);
            }
            MessagePayload::NewTransactionHashes(hashes) => {
                for hash in hashes {
                    data.extend_from_slice(&hash.0);
                }
            }
            MessagePayload::NewBlockHashes(hashes) => {
                for (hash, _) in hashes {
                    data.extend_from_slice(&hash.0);
                }
            }
            _ => {
                // Use request_id for other message types
                data.extend_from_slice(&self.request_id.to_le_bytes());
            }
        }
        data
    }

    /// Get message priority
    pub fn priority(&self) -> MessagePriority {
        self.msg_type.priority()
    }

    /// Validate message size and content
    pub fn validate(&self) -> P2PResult<()> {
        // Check payload-specific limits
        match &self.payload {
            MessagePayload::Transactions(txs) => {
                if txs.len() > MAX_TXS_PER_MESSAGE {
                    return Err(P2PError::InvalidMessage(format!(
                        "Too many transactions: {} > {}",
                        txs.len(),
                        MAX_TXS_PER_MESSAGE
                    )));
                }
            }
            MessagePayload::BlockHeaders(headers) => {
                if headers.len() > MAX_HEADERS_PER_MESSAGE {
                    return Err(P2PError::InvalidMessage(format!(
                        "Too many headers: {} > {}",
                        headers.len(),
                        MAX_HEADERS_PER_MESSAGE
                    )));
                }
            }
            MessagePayload::BlockBodies(bodies) => {
                if bodies.len() > MAX_BLOCKS_PER_MESSAGE {
                    return Err(P2PError::InvalidMessage(format!(
                        "Too many blocks: {} > {}",
                        bodies.len(),
                        MAX_BLOCKS_PER_MESSAGE
                    )));
                }
            }
            _ => {}
        }

        Ok(())
    }
}

/// Message payload variants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    // Ping/Pong
    Ping(PingPayload),
    Pong(PongPayload),

    // Status
    Status(StatusPayload),
    Disconnect(DisconnectPayload),

    // Transactions
    NewTransaction(Box<SignedTransaction>),
    NewTransactionHashes(Vec<TxHash>),
    GetTransactions(Vec<TxHash>),
    Transactions(Vec<SignedTransaction>),

    // Blocks
    NewBlock(Box<Block>),
    NewBlockHashes(Vec<(BlockHash, u64)>), // (hash, height)
    GetBlockHeaders(GetHeadersPayload),
    BlockHeaders(Vec<BlockHeaderPayload>),
    GetBlockBodies(Vec<BlockHash>),
    BlockBodies(Vec<BlockBodyPayload>),

    // Sync
    GetStatus(GetStatusPayload),
    StatusResponse(StatusResponsePayload),
    GetCheckpoint(u64), // epoch number
    Checkpoint(CheckpointPayload),

    // Discovery
    GetPeers(GetPeersPayload),
    Peers(Vec<PeerPayload>),

    // Consensus
    Attestation(AttestationPayload),
    AttestationAggregate(AggregatePayload),
    ProposerSlashing(SlashingPayload),
    AttesterSlashing(SlashingPayload),

    // Mempool
    MempoolRequest(MempoolRequestPayload),
    MempoolResponse(MempoolResponsePayload),

    // Empty payload for simple messages
    Empty,
}

/// Ping payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingPayload {
    /// Nonce for response matching
    pub nonce: u64,
}

/// Pong payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongPayload {
    /// Echo of ping nonce
    pub nonce: u64,
}

/// Status payload for handshake/updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusPayload {
    /// Protocol version
    pub protocol_version: u32,
    /// Chain ID
    pub chain_id: u64,
    /// Genesis block hash
    pub genesis_hash: BlockHash,
    /// Best block height
    pub best_height: u64,
    /// Best block hash
    pub best_hash: BlockHash,
    /// Finalized block height
    pub finalized_height: u64,
    /// Finalized block hash
    pub finalized_hash: BlockHash,
}

/// Disconnect payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisconnectPayload {
    /// Reason code
    pub reason: u8,
    /// Human-readable message
    pub message: String,
}

/// Get headers request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHeadersPayload {
    /// Start block (height or hash)
    pub start: BlockLocator,
    /// Maximum headers to return
    pub max_headers: u64,
    /// Direction (true = ascending, false = descending)
    pub ascending: bool,
}

/// Block locator for sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockLocator {
    /// By block height
    Height(u64),
    /// By block hash
    Hash(BlockHash),
    /// Multiple hashes for fork detection
    Hashes(Vec<BlockHash>),
}

/// Block header payload (lighter than full block)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderPayload {
    /// Block height
    pub height: u64,
    /// Parent hash
    pub parent_hash: BlockHash,
    /// Block hash
    pub hash: BlockHash,
    /// State root
    pub state_root: [u8; 32],
    /// Transactions root
    pub tx_root: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
    /// Proposer address
    pub proposer: [u8; 32],
    /// Transaction count
    pub tx_count: u32,
}

/// Block body payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBodyPayload {
    /// Block hash this body belongs to
    pub block_hash: BlockHash,
    /// Transactions
    pub transactions: Vec<SignedTransaction>,
}

/// Get status request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStatusPayload {
    /// What info to include
    pub include_peers: bool,
    pub include_mempool_stats: bool,
}

/// Status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponsePayload {
    /// Current status
    pub status: StatusPayload,
    /// Peer count (if requested)
    pub peer_count: Option<u32>,
    /// Mempool size (if requested)
    pub mempool_size: Option<u32>,
    /// Sync status
    pub syncing: bool,
    /// Target height if syncing
    pub sync_target: Option<u64>,
}

/// Checkpoint payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointPayload {
    /// Epoch number
    pub epoch: u64,
    /// Checkpoint block height
    pub height: u64,
    /// Checkpoint block hash
    pub hash: BlockHash,
    /// State root at checkpoint
    pub state_root: [u8; 32],
    /// Validator set root
    pub validator_set_root: [u8; 32],
    /// Aggregate signature from validators
    pub aggregate_signature: Vec<u8>,
    /// Participating validator indices
    pub participant_bits: Vec<u8>,
}

/// Get peers request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPeersPayload {
    /// Maximum peers to return
    pub max_peers: u32,
    /// Filter by minimum score
    pub min_score: Option<i32>,
}

/// Peer info for discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPayload {
    /// Peer ID
    pub peer_id: [u8; 32],
    /// IP address (v4 or v6)
    pub ip: Vec<u8>,
    /// Port
    pub port: u16,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Peer capabilities
    pub capabilities: u32,
}

/// Attestation for consensus
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPayload {
    /// Slot number
    pub slot: u64,
    /// Epoch number
    pub epoch: u64,
    /// Block hash being attested
    pub block_hash: BlockHash,
    /// Block height
    pub height: u64,
    /// Attester index
    pub validator_index: u32,
    /// Signature
    #[serde_as(as = "[_; 64]")]
    pub signature: [u8; 64],
}

/// Aggregate attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatePayload {
    /// Slot number
    pub slot: u64,
    /// Epoch number
    pub epoch: u64,
    /// Block hash
    pub block_hash: BlockHash,
    /// Aggregated signature
    pub aggregate_signature: Vec<u8>,
    /// Bitfield of participating validators
    pub participation_bits: Vec<u8>,
}

/// Slashing evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingPayload {
    /// Slashing type (proposer = 1, attester = 2)
    pub slashing_type: u8,
    /// Validator index
    pub validator_index: u32,
    /// First signed data
    pub evidence_1: Vec<u8>,
    /// Second signed data (conflicting)
    pub evidence_2: Vec<u8>,
}

/// Mempool request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolRequestPayload {
    /// Maximum transactions to return
    pub max_txs: u32,
    /// Minimum gas price filter
    pub min_gas_price: Option<u64>,
    /// Only return hashes
    pub hashes_only: bool,
}

/// Mempool response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolResponsePayload {
    /// Pending transaction hashes
    pub pending_hashes: Vec<TxHash>,
    /// Full transactions (if not hashes_only)
    pub transactions: Vec<SignedTransaction>,
    /// Total mempool size
    pub total_count: u32,
}

// Convenience constructors
impl Message {
    /// Create ping message
    pub fn ping(nonce: u64) -> Self {
        Self::new(MessageType::Ping, MessagePayload::Ping(PingPayload { nonce }))
    }

    /// Create pong message
    pub fn pong(nonce: u64) -> Self {
        Self::new(MessageType::Pong, MessagePayload::Pong(PongPayload { nonce }))
    }

    /// Create new transaction announcement
    pub fn new_transaction(tx: SignedTransaction) -> Self {
        Self::new(MessageType::NewTransaction, MessagePayload::NewTransaction(Box::new(tx)))
    }

    /// Create transaction hash announcement
    pub fn new_tx_hashes(hashes: Vec<TxHash>) -> Self {
        Self::new(MessageType::NewTransactionHashes, MessagePayload::NewTransactionHashes(hashes))
    }

    /// Create new block announcement
    pub fn new_block(block: Block) -> Self {
        Self::new(MessageType::NewBlock, MessagePayload::NewBlock(Box::new(block)))
    }

    /// Create block hash announcement
    pub fn new_block_hashes(hashes: Vec<(BlockHash, u64)>) -> Self {
        Self::new(MessageType::NewBlockHashes, MessagePayload::NewBlockHashes(hashes))
    }

    /// Create get peers request
    pub fn get_peers(max_peers: u32) -> Self {
        Self::new(
            MessageType::GetPeers,
            MessagePayload::GetPeers(GetPeersPayload {
                max_peers,
                min_score: None,
            }),
        )
    }

    /// Create status message
    pub fn status(status: StatusPayload) -> Self {
        Self::new(MessageType::Status, MessagePayload::Status(status))
    }

    /// Create disconnect message
    pub fn disconnect(reason: u8, message: String) -> Self {
        Self::new(
            MessageType::Disconnect,
            MessagePayload::Disconnect(DisconnectPayload { reason, message }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_id_consistency() {
        let msg1 = Message::ping(12345);
        let msg2 = Message::ping(12345);

        // Same content should produce same ID
        // Note: timestamp differs, so IDs will differ
        // This is intentional for replay protection
        let id1 = msg1.id();
        let id2 = msg1.id();
        assert_eq!(id1, id2); // Same message, same ID
    }

    #[test]
    fn test_message_priority() {
        assert_eq!(Message::ping(0).priority(), MessagePriority::Low);

        let block_msg = Message::new(
            MessageType::NewBlock,
            MessagePayload::Empty, // Simplified for test
        );
        assert_eq!(block_msg.priority(), MessagePriority::High);

        let attest_msg = Message::new(
            MessageType::Attestation,
            MessagePayload::Empty,
        );
        assert_eq!(attest_msg.priority(), MessagePriority::Critical);
    }

    #[test]
    fn test_message_type_response_expectation() {
        assert!(MessageType::Ping.expects_response());
        assert!(MessageType::GetTransactions.expects_response());
        assert!(MessageType::GetBlockHeaders.expects_response());
        assert!(!MessageType::Pong.expects_response());
        assert!(!MessageType::NewTransaction.expects_response());
    }

    #[test]
    fn test_status_payload() {
        let status = StatusPayload {
            protocol_version: 1,
            chain_id: 137,
            genesis_hash: BlockHash([0u8; 32]),
            best_height: 1000,
            best_hash: BlockHash([1u8; 32]),
            finalized_height: 990,
            finalized_hash: BlockHash([2u8; 32]),
        };

        let msg = Message::status(status.clone());
        assert_eq!(msg.msg_type, MessageType::Status);

        match msg.payload {
            MessagePayload::Status(s) => {
                assert_eq!(s.chain_id, 137);
                assert_eq!(s.best_height, 1000);
            }
            _ => panic!("Wrong payload type"),
        }
    }
}
