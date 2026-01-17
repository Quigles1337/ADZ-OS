//! Gossip Protocol Engine
//!
//! Epidemic message propagation with:
//! - Probabilistic fan-out
//! - Deduplication with seen cache
//! - Priority-based queuing
//! - Bandwidth-aware throttling
//! - Lazy push for large messages

use super::{
    message::{Message, MessageId, MessageType, MessagePayload},
    peer::{PeerId, PeerInfo},
    scoring::PeerScorer,
    P2PError, P2PResult, MessagePriority,
};
use crate::types::{Block, BlockHash, SignedTransaction, TxHash};
use std::collections::{HashMap, HashSet, VecDeque, BinaryHeap};
use std::time::{Duration, Instant};
use std::cmp::Ordering;

/// Gossip protocol configuration
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Number of peers to gossip to (fan-out)
    pub fanout: usize,
    /// Additional peers for high-priority messages
    pub high_priority_fanout: usize,
    /// Size of seen message cache
    pub seen_cache_size: usize,
    /// TTL for seen messages
    pub seen_ttl: Duration,
    /// Maximum pending messages in queue
    pub max_queue_size: usize,
    /// Batch size for message sending
    pub batch_size: usize,
    /// Minimum interval between same message to same peer
    pub message_cooldown: Duration,
    /// Use lazy push for messages larger than this
    pub lazy_push_threshold: usize,
    /// Maximum hops for gossip propagation
    pub max_hops: u8,
    /// Probability of forwarding (0.0 - 1.0)
    pub forward_probability: f64,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            fanout: 6,
            high_priority_fanout: 10,
            seen_cache_size: 100_000,
            seen_ttl: Duration::from_secs(120), // 2 minutes
            max_queue_size: 10_000,
            batch_size: 100,
            message_cooldown: Duration::from_millis(100),
            lazy_push_threshold: 64 * 1024, // 64 KB
            max_hops: 6,
            forward_probability: 1.0, // Always forward by default
        }
    }
}

impl GossipConfig {
    /// High-throughput configuration
    pub fn high_throughput() -> Self {
        Self {
            fanout: 8,
            high_priority_fanout: 12,
            max_queue_size: 50_000,
            batch_size: 200,
            ..Default::default()
        }
    }

    /// Low-bandwidth configuration
    pub fn low_bandwidth() -> Self {
        Self {
            fanout: 4,
            high_priority_fanout: 6,
            max_queue_size: 5_000,
            batch_size: 50,
            forward_probability: 0.8,
            ..Default::default()
        }
    }
}

/// Gossip event for upstream notification
#[derive(Debug, Clone)]
pub enum GossipEvent {
    /// New transaction received
    NewTransaction {
        tx: SignedTransaction,
        from_peer: PeerId,
    },
    /// New block received
    NewBlock {
        block: Block,
        from_peer: PeerId,
    },
    /// Transaction hashes received (need to fetch)
    TransactionHashes {
        hashes: Vec<TxHash>,
        from_peer: PeerId,
    },
    /// Block hashes received (need to fetch)
    BlockHashes {
        hashes: Vec<(BlockHash, u64)>,
        from_peer: PeerId,
    },
    /// Message propagation complete
    PropagationComplete {
        message_id: MessageId,
        peers_sent: usize,
    },
}

/// Entry in the seen cache
#[derive(Debug)]
struct SeenEntry {
    /// When first seen
    first_seen: Instant,
    /// Peers we received this from
    received_from: HashSet<PeerId>,
    /// Peers we sent this to
    sent_to: HashSet<PeerId>,
    /// Number of times seen
    count: u32,
}

/// Priority queue entry
#[derive(Debug)]
struct QueueEntry {
    /// Message to send
    message: Message,
    /// Target peer
    target: PeerId,
    /// Priority
    priority: MessagePriority,
    /// When queued
    queued_at: Instant,
    /// Retry count
    retries: u8,
}

impl Eq for QueueEntry {}

impl PartialEq for QueueEntry {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.queued_at == other.queued_at
    }
}

impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first, then older messages first
        match self.priority.cmp(&other.priority) {
            Ordering::Equal => other.queued_at.cmp(&self.queued_at),
            other => other,
        }
    }
}

impl PartialOrd for QueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Gossip protocol engine
#[derive(Debug)]
pub struct GossipEngine {
    /// Configuration
    config: GossipConfig,
    /// Seen message cache
    seen: HashMap<MessageId, SeenEntry>,
    /// Seen cache order for eviction (FIFO)
    seen_order: VecDeque<(MessageId, Instant)>,
    /// Outgoing message queue (priority heap)
    outgoing: BinaryHeap<QueueEntry>,
    /// Last send time per peer per message type
    last_send: HashMap<(PeerId, MessageType), Instant>,
    /// Messages pending fetch (hash -> requesters)
    pending_fetch: HashMap<[u8; 32], Vec<PeerId>>,
    /// Statistics
    stats: GossipStats,
}

/// Gossip statistics
#[derive(Debug, Clone, Default)]
pub struct GossipStats {
    /// Messages received
    pub messages_received: u64,
    /// Messages propagated
    pub messages_propagated: u64,
    /// Duplicate messages received
    pub duplicates_received: u64,
    /// Messages dropped (queue full)
    pub messages_dropped: u64,
    /// Total peers gossiped to
    pub peers_gossiped: u64,
    /// Transactions received
    pub txs_received: u64,
    /// Blocks received
    pub blocks_received: u64,
}

impl GossipEngine {
    /// Create new gossip engine
    pub fn new(config: GossipConfig) -> Self {
        Self {
            config,
            seen: HashMap::new(),
            seen_order: VecDeque::new(),
            outgoing: BinaryHeap::new(),
            last_send: HashMap::new(),
            pending_fetch: HashMap::new(),
            stats: GossipStats::default(),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &GossipStats {
        &self.stats
    }

    /// Check if message was already seen
    pub fn is_seen(&self, message_id: &MessageId) -> bool {
        if let Some(entry) = self.seen.get(message_id) {
            entry.first_seen.elapsed() < self.config.seen_ttl
        } else {
            false
        }
    }

    /// Mark message as seen from a peer
    pub fn mark_seen(&mut self, message_id: MessageId, from_peer: PeerId) -> bool {
        let now = Instant::now();

        if let Some(entry) = self.seen.get_mut(&message_id) {
            entry.received_from.insert(from_peer);
            entry.count += 1;
            self.stats.duplicates_received += 1;
            false // Was already seen
        } else {
            // Evict old entries if needed
            self.cleanup_seen();

            let mut entry = SeenEntry {
                first_seen: now,
                received_from: HashSet::new(),
                sent_to: HashSet::new(),
                count: 1,
            };
            entry.received_from.insert(from_peer);

            self.seen.insert(message_id, entry);
            self.seen_order.push_back((message_id, now));
            true // First time seen
        }
    }

    /// Cleanup expired seen entries
    fn cleanup_seen(&mut self) {
        let now = Instant::now();
        let ttl = self.config.seen_ttl;

        // Remove expired entries from front
        while let Some((msg_id, time)) = self.seen_order.front() {
            if now.duration_since(*time) > ttl {
                let msg_id = *msg_id;
                self.seen_order.pop_front();
                self.seen.remove(&msg_id);
            } else {
                break;
            }
        }

        // Also evict if over size limit
        while self.seen.len() > self.config.seen_cache_size {
            if let Some((msg_id, _)) = self.seen_order.pop_front() {
                self.seen.remove(&msg_id);
            } else {
                break;
            }
        }
    }

    /// Process incoming message and determine if it should be propagated
    pub fn process_incoming(
        &mut self,
        message: &Message,
        from_peer: PeerId,
    ) -> P2PResult<Option<GossipEvent>> {
        let message_id = message.id();
        self.stats.messages_received += 1;

        // Check if already seen
        if !self.mark_seen(message_id, from_peer) {
            return Ok(None); // Duplicate
        }

        // Validate message
        message.validate()?;

        // Generate appropriate event
        let event = match &message.payload {
            MessagePayload::NewTransaction(tx) => {
                self.stats.txs_received += 1;
                Some(GossipEvent::NewTransaction {
                    tx: (**tx).clone(),
                    from_peer,
                })
            }
            MessagePayload::NewBlock(block) => {
                self.stats.blocks_received += 1;
                Some(GossipEvent::NewBlock {
                    block: (**block).clone(),
                    from_peer,
                })
            }
            MessagePayload::NewTransactionHashes(hashes) => {
                Some(GossipEvent::TransactionHashes {
                    hashes: hashes.clone(),
                    from_peer,
                })
            }
            MessagePayload::NewBlockHashes(hashes) => {
                Some(GossipEvent::BlockHashes {
                    hashes: hashes.clone(),
                    from_peer,
                })
            }
            _ => None,
        };

        Ok(event)
    }

    /// Queue message for propagation to peers
    pub fn propagate(
        &mut self,
        message: Message,
        exclude_peer: Option<PeerId>,
        peers: &[&PeerInfo],
        scorer: &PeerScorer,
    ) -> usize {
        let message_id = message.id();
        let priority = message.priority();

        // Determine fanout based on priority
        let fanout = match priority {
            MessagePriority::Critical | MessagePriority::High => self.config.high_priority_fanout,
            _ => self.config.fanout,
        };

        // Select peers to gossip to
        let selected = self.select_peers(
            peers,
            fanout,
            exclude_peer,
            &message_id,
            scorer,
        );

        // Queue messages
        let mut queued = 0;
        for peer_id in selected {
            if self.queue_message(message.clone(), peer_id, priority) {
                // Mark as sent
                if let Some(entry) = self.seen.get_mut(&message_id) {
                    entry.sent_to.insert(peer_id);
                }
                queued += 1;
            }
        }

        self.stats.messages_propagated += 1;
        self.stats.peers_gossiped += queued as u64;

        queued
    }

    /// Select peers for gossip using probabilistic selection
    fn select_peers(
        &self,
        peers: &[&PeerInfo],
        fanout: usize,
        exclude: Option<PeerId>,
        message_id: &MessageId,
        scorer: &PeerScorer,
    ) -> Vec<PeerId> {
        // Filter out excluded peer and peers we already sent to
        let sent_to = self.seen.get(message_id)
            .map(|e| &e.sent_to)
            .cloned()
            .unwrap_or_default();

        let mut candidates: Vec<_> = peers
            .iter()
            .filter(|p| {
                p.is_active() &&
                Some(p.id) != exclude &&
                !sent_to.contains(&p.id)
            })
            .collect();

        if candidates.is_empty() {
            return Vec::new();
        }

        // Sort by score (higher = better)
        candidates.sort_by(|a, b| {
            let score_a = scorer.get_score(&a.id).map(|s| s.total()).unwrap_or(0.0);
            let score_b = scorer.get_score(&b.id).map(|s| s.total()).unwrap_or(0.0);
            score_b.partial_cmp(&score_a).unwrap_or(Ordering::Equal)
        });

        // Select top peers, with some randomization
        let mut selected = Vec::with_capacity(fanout.min(candidates.len()));

        // Always include top-scored peers
        let guaranteed = fanout / 2;
        for peer in candidates.iter().take(guaranteed) {
            selected.push(peer.id);
        }

        // Randomly select remaining from rest
        if candidates.len() > guaranteed && selected.len() < fanout {
            // Simple deterministic "random" based on message ID
            let seed = u64::from_le_bytes(message_id.as_bytes()[0..8].try_into().unwrap());
            let remaining: Vec<_> = candidates.iter().skip(guaranteed).collect();

            for (i, peer) in remaining.iter().enumerate() {
                if selected.len() >= fanout {
                    break;
                }
                // Pseudo-random selection based on message ID and index
                let select = ((seed.wrapping_mul(i as u64 + 1)) % 100) < 70;
                if select {
                    selected.push(peer.id);
                }
            }

            // Fill remaining if needed
            for peer in remaining {
                if selected.len() >= fanout {
                    break;
                }
                if !selected.contains(&peer.id) {
                    selected.push(peer.id);
                }
            }
        }

        selected
    }

    /// Queue a message for sending
    fn queue_message(&mut self, message: Message, target: PeerId, priority: MessagePriority) -> bool {
        // Check queue size limit
        if self.outgoing.len() >= self.config.max_queue_size {
            self.stats.messages_dropped += 1;
            return false;
        }

        // Check cooldown
        let key = (target, message.msg_type);
        if let Some(last) = self.last_send.get(&key) {
            if last.elapsed() < self.config.message_cooldown {
                return false;
            }
        }

        self.outgoing.push(QueueEntry {
            message,
            target,
            priority,
            queued_at: Instant::now(),
            retries: 0,
        });

        true
    }

    /// Get next batch of messages to send
    pub fn drain_outgoing(&mut self, max: usize) -> Vec<(PeerId, Message)> {
        let mut batch = Vec::with_capacity(max.min(self.config.batch_size));
        let now = Instant::now();

        while batch.len() < max && !self.outgoing.is_empty() {
            if let Some(entry) = self.outgoing.pop() {
                // Update last send time
                self.last_send.insert((entry.target, entry.message.msg_type), now);
                batch.push((entry.target, entry.message));
            }
        }

        batch
    }

    /// Get queue size
    pub fn queue_size(&self) -> usize {
        self.outgoing.len()
    }

    /// Create lazy push message (announce hashes instead of full data)
    pub fn create_lazy_push(&self, message: &Message) -> Option<Message> {
        match &message.payload {
            MessagePayload::NewTransaction(tx) => {
                Some(Message::new_tx_hashes(vec![tx.hash()]))
            }
            MessagePayload::NewBlock(block) => {
                let hash = block.header.hash();
                let height = block.header.height;
                Some(Message::new_block_hashes(vec![(hash, height)]))
            }
            _ => None,
        }
    }

    /// Record that we need to fetch data for a hash
    pub fn request_data(&mut self, hash: [u8; 32], from_peer: PeerId) {
        self.pending_fetch
            .entry(hash)
            .or_insert_with(Vec::new)
            .push(from_peer);
    }

    /// Get pending fetch requests
    pub fn pending_fetches(&self) -> &HashMap<[u8; 32], Vec<PeerId>> {
        &self.pending_fetch
    }

    /// Clear pending fetch
    pub fn clear_pending(&mut self, hash: &[u8; 32]) {
        self.pending_fetch.remove(hash);
    }

    /// Cleanup stale data
    pub fn cleanup(&mut self) {
        self.cleanup_seen();

        // Cleanup old last_send entries
        let cutoff = Instant::now() - Duration::from_secs(60);
        self.last_send.retain(|_, time| *time > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Address;
    use libmu_crypto::MuKeyPair;

    fn make_peer(seed: &[u8]) -> PeerInfo {
        let keypair = MuKeyPair::from_seed(seed);
        let peer_id = PeerId::from_public_key(keypair.public_key());
        let mut info = PeerInfo::new_outbound("127.0.0.1:30303".parse().unwrap());
        info.id = peer_id;
        info.state = super::super::peer::PeerState::Connected;
        info
    }

    #[test]
    fn test_seen_cache() {
        let config = GossipConfig::default();
        let mut engine = GossipEngine::new(config);

        let msg = Message::ping(12345);
        let msg_id = msg.id();
        let peer_id = PeerId::from_bytes([1u8; 32]);

        // First time should not be seen
        assert!(!engine.is_seen(&msg_id));

        // Mark as seen
        assert!(engine.mark_seen(msg_id, peer_id));

        // Now should be seen
        assert!(engine.is_seen(&msg_id));

        // Marking again should return false (duplicate)
        assert!(!engine.mark_seen(msg_id, peer_id));
    }

    #[test]
    fn test_message_queuing() {
        let config = GossipConfig::default();
        let mut engine = GossipEngine::new(config);

        let msg = Message::ping(12345);
        let peer_id = PeerId::from_bytes([1u8; 32]);

        // Queue message
        assert!(engine.queue_message(msg.clone(), peer_id, MessagePriority::Normal));

        // Should have one message
        assert_eq!(engine.queue_size(), 1);

        // Drain
        let batch = engine.drain_outgoing(10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].0, peer_id);

        // Queue should be empty
        assert_eq!(engine.queue_size(), 0);
    }

    #[test]
    fn test_priority_ordering() {
        let config = GossipConfig::default();
        let mut engine = GossipEngine::new(config);

        let peer_id = PeerId::from_bytes([1u8; 32]);

        // Queue low priority first
        let msg_low = Message::ping(1);
        engine.queue_message(msg_low, peer_id, MessagePriority::Low);

        // Queue high priority second
        let msg_high = Message::new(MessageType::NewBlock, MessagePayload::Empty);
        let peer_id2 = PeerId::from_bytes([2u8; 32]);
        engine.queue_message(msg_high, peer_id2, MessagePriority::High);

        // High priority should come first
        let batch = engine.drain_outgoing(10);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].0, peer_id2); // High priority peer
        assert_eq!(batch[1].0, peer_id); // Low priority peer
    }

    #[test]
    fn test_gossip_stats() {
        let config = GossipConfig::default();
        let mut engine = GossipEngine::new(config);

        let msg = Message::ping(12345);
        let peer_id = PeerId::from_bytes([1u8; 32]);

        // Process message
        let _ = engine.process_incoming(&msg, peer_id);

        assert_eq!(engine.stats().messages_received, 1);

        // Process duplicate
        let _ = engine.process_incoming(&msg, peer_id);

        assert_eq!(engine.stats().messages_received, 2);
        assert_eq!(engine.stats().duplicates_received, 1);
    }

    #[test]
    fn test_peer_selection() {
        let config = GossipConfig {
            fanout: 3,
            ..Default::default()
        };
        let engine = GossipEngine::new(config);
        let scorer = PeerScorer::new(Default::default());

        let peer1 = make_peer(b"peer_selection_test_1");
        let peer2 = make_peer(b"peer_selection_test_2");
        let peer3 = make_peer(b"peer_selection_test_3");
        let peer4 = make_peer(b"peer_selection_test_4");

        let peers: Vec<&PeerInfo> = vec![&peer1, &peer2, &peer3, &peer4];
        let msg_id = MessageId::from_bytes([0u8; 32]);

        let selected = engine.select_peers(&peers, 3, None, &msg_id, &scorer);

        // Should select up to fanout peers
        assert!(selected.len() <= 3);
        assert!(!selected.is_empty());
    }
}
