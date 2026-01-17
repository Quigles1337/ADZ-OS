//! Sync Protocol
//!
//! Blockchain synchronization with multiple strategies:
//! - Full sync (download all blocks)
//! - Fast sync (download state at checkpoint)
//! - Snap sync (download state trie nodes)
//! - Light sync (headers only)

use super::{
    peer::{PeerId, PeerInfo},
    message::{BlockLocator, BlockHeaderPayload, GetHeadersPayload, CheckpointPayload},
    P2PError, P2PResult,
};
use crate::types::{Block, BlockHash};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Sync configuration
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum concurrent block downloads
    pub max_concurrent_downloads: usize,
    /// Maximum blocks per request
    pub max_blocks_per_request: usize,
    /// Maximum headers per request
    pub max_headers_per_request: usize,
    /// Request timeout
    pub request_timeout: Duration,
    /// Minimum peers to start sync
    pub min_peers_to_sync: usize,
    /// Sync batch size (headers to process at once)
    pub batch_size: usize,
    /// Pivot block distance from head for fast sync
    pub pivot_distance: u64,
    /// Maximum orphan blocks to keep
    pub max_orphans: usize,
    /// Skeleton sync stride
    pub skeleton_stride: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_concurrent_downloads: 16,
            max_blocks_per_request: 64,
            max_headers_per_request: 512,
            request_timeout: Duration::from_secs(30),
            min_peers_to_sync: 3,
            batch_size: 256,
            pivot_distance: 64,
            max_orphans: 1000,
            skeleton_stride: 192, // ~32 minutes of blocks at 10s each
        }
    }
}

/// Sync state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Not syncing (fully synced or waiting)
    Idle,
    /// Finding common ancestor
    FindingAncestor,
    /// Downloading block headers
    DownloadingHeaders,
    /// Downloading block bodies
    DownloadingBodies,
    /// Processing downloaded blocks
    Processing,
    /// Downloading state (fast sync)
    DownloadingState,
    /// Synced and following chain tip
    Synced,
}

/// Sync request tracking
#[derive(Debug)]
struct SyncRequest {
    /// Request type
    request_type: SyncRequestType,
    /// Peer handling request
    peer: PeerId,
    /// Request time
    sent_at: Instant,
    /// Items requested (hashes or heights)
    items: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Copy)]
enum SyncRequestType {
    Headers,
    Bodies,
    State,
    Checkpoint,
}

/// Block in the sync queue
#[derive(Debug, Clone)]
struct QueuedBlock {
    /// Block height
    height: u64,
    /// Block hash
    hash: BlockHash,
    /// Parent hash
    parent_hash: BlockHash,
    /// Header received
    header: Option<BlockHeaderPayload>,
    /// Full block (if downloaded)
    block: Option<Block>,
    /// Peer that provided this
    from_peer: Option<PeerId>,
}

/// Sync engine
#[derive(Debug)]
pub struct SyncEngine {
    /// Configuration
    config: SyncConfig,
    /// Current state
    state: SyncState,
    /// Our current height
    current_height: u64,
    /// Our current best hash
    current_hash: BlockHash,
    /// Target height to sync to
    target_height: u64,
    /// Target hash
    target_hash: BlockHash,
    /// Best peer for syncing
    sync_peer: Option<PeerId>,
    /// Active requests by ID
    requests: HashMap<u64, SyncRequest>,
    /// Next request ID
    next_request_id: u64,
    /// Headers queue (ordered by height)
    header_queue: VecDeque<QueuedBlock>,
    /// Bodies to download (hash -> height)
    bodies_needed: HashMap<BlockHash, u64>,
    /// Blocks ready to process (hash -> block)
    ready_blocks: HashMap<BlockHash, Block>,
    /// Orphan blocks (parent hash -> blocks)
    orphans: HashMap<BlockHash, Vec<Block>>,
    /// Finalized checkpoint (epoch, height, hash)
    checkpoint: Option<(u64, u64, BlockHash)>,
    /// Pivot block for fast sync
    pivot_block: Option<(u64, BlockHash)>,
    /// Downloaded state pieces
    state_pieces: HashSet<[u8; 32]>,
    /// Sync started at
    started_at: Option<Instant>,
    /// Statistics
    stats: SyncStats,
}

/// Sync statistics
#[derive(Debug, Clone, Default)]
pub struct SyncStats {
    /// Headers downloaded
    pub headers_downloaded: u64,
    /// Blocks downloaded
    pub blocks_downloaded: u64,
    /// Blocks processed
    pub blocks_processed: u64,
    /// State pieces downloaded
    pub state_pieces_downloaded: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Timeouts
    pub timeouts: u64,
    /// Current sync speed (blocks/sec)
    pub sync_speed: f64,
}

/// Sync request to send
#[derive(Debug, Clone)]
pub struct SyncRequest2 {
    /// Request ID
    pub id: u64,
    /// Target peer
    pub peer: PeerId,
    /// Request payload
    pub payload: SyncRequestPayload,
}

/// Sync request payload
#[derive(Debug, Clone)]
pub enum SyncRequestPayload {
    /// Get headers starting from locator
    GetHeaders {
        locator: BlockLocator,
        max_headers: u64,
    },
    /// Get block bodies by hash
    GetBodies(Vec<BlockHash>),
    /// Get state at checkpoint
    GetState {
        state_root: [u8; 32],
        paths: Vec<Vec<u8>>,
    },
    /// Get checkpoint for epoch
    GetCheckpoint(u64),
}

/// Sync response received
#[derive(Debug, Clone)]
pub enum SyncResponse {
    /// Headers received
    Headers(Vec<BlockHeaderPayload>),
    /// Block bodies received
    Bodies(Vec<Block>),
    /// State pieces received
    State(Vec<(Vec<u8>, Vec<u8>)>),
    /// Checkpoint received
    Checkpoint(CheckpointPayload),
}

impl SyncEngine {
    /// Create new sync engine
    pub fn new(config: SyncConfig, current_height: u64, current_hash: BlockHash) -> Self {
        Self {
            config,
            state: SyncState::Idle,
            current_height,
            current_hash,
            target_height: current_height,
            target_hash: current_hash,
            sync_peer: None,
            requests: HashMap::new(),
            next_request_id: 1,
            header_queue: VecDeque::new(),
            bodies_needed: HashMap::new(),
            ready_blocks: HashMap::new(),
            orphans: HashMap::new(),
            checkpoint: None,
            pivot_block: None,
            state_pieces: HashSet::new(),
            started_at: None,
            stats: SyncStats::default(),
        }
    }

    /// Get current state
    pub fn state(&self) -> SyncState {
        self.state
    }

    /// Get sync progress (0.0 - 1.0)
    pub fn progress(&self) -> f64 {
        if self.target_height <= self.current_height {
            1.0
        } else {
            let total = self.target_height - self.current_height;
            let done = self.stats.blocks_processed;
            (done as f64 / total as f64).min(1.0)
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &SyncStats {
        &self.stats
    }

    /// Check if syncing
    pub fn is_syncing(&self) -> bool {
        !matches!(self.state, SyncState::Idle | SyncState::Synced)
    }

    /// Start sync with target
    pub fn start_sync(&mut self, target_height: u64, target_hash: BlockHash, peer: PeerId) {
        if target_height <= self.current_height {
            return; // Already synced
        }

        self.target_height = target_height;
        self.target_hash = target_hash;
        self.sync_peer = Some(peer);
        self.state = SyncState::FindingAncestor;
        self.started_at = Some(Instant::now());
    }

    /// Update current chain tip
    pub fn set_current(&mut self, height: u64, hash: BlockHash) {
        self.current_height = height;
        self.current_hash = hash;

        // Check if synced
        if height >= self.target_height {
            self.state = SyncState::Synced;
        }
    }

    /// Generate next sync requests
    pub fn generate_requests(&mut self, peers: &[&PeerInfo]) -> Vec<SyncRequest2> {
        let mut requests = Vec::new();

        // Check for timeouts first
        self.check_timeouts();

        // Generate requests based on state
        match self.state {
            SyncState::Idle => {}
            SyncState::FindingAncestor | SyncState::DownloadingHeaders => {
                requests.extend(self.generate_header_requests(peers));
            }
            SyncState::DownloadingBodies => {
                requests.extend(self.generate_body_requests(peers));
            }
            SyncState::DownloadingState => {
                requests.extend(self.generate_state_requests(peers));
            }
            SyncState::Processing | SyncState::Synced => {}
        }

        requests
    }

    /// Generate header requests
    fn generate_header_requests(&mut self, peers: &[&PeerInfo]) -> Vec<SyncRequest2> {
        let mut requests = Vec::new();

        // Check if we have capacity
        if self.requests.len() >= self.config.max_concurrent_downloads {
            return requests;
        }

        // Find best peer to sync from
        let sync_peer = peers
            .iter()
            .filter(|p| p.is_active() && p.best_height > self.current_height)
            .max_by_key(|p| p.best_height);

        if let Some(peer) = sync_peer {
            let id = self.next_request_id;
            self.next_request_id += 1;

            // Build locator
            let locator = self.build_locator();

            requests.push(SyncRequest2 {
                id,
                peer: peer.id,
                payload: SyncRequestPayload::GetHeaders {
                    locator,
                    max_headers: self.config.max_headers_per_request as u64,
                },
            });

            self.requests.insert(id, SyncRequest {
                request_type: SyncRequestType::Headers,
                peer: peer.id,
                sent_at: Instant::now(),
                items: Vec::new(),
            });
        }

        requests
    }

    /// Build block locator for header sync
    fn build_locator(&self) -> BlockLocator {
        // Start from current hash
        let mut hashes = vec![self.current_hash];

        // Add some recent headers from queue
        for block in self.header_queue.iter().rev().take(10) {
            hashes.push(block.hash);
        }

        BlockLocator::Hashes(hashes)
    }

    /// Generate body requests
    fn generate_body_requests(&mut self, peers: &[&PeerInfo]) -> Vec<SyncRequest2> {
        let mut requests = Vec::new();

        // Check capacity
        let available = self.config.max_concurrent_downloads.saturating_sub(self.requests.len());
        if available == 0 {
            return requests;
        }

        // Get bodies needed
        let mut to_request: Vec<_> = self.bodies_needed
            .iter()
            .take(available * self.config.max_blocks_per_request)
            .map(|(hash, _)| *hash)
            .collect();

        if to_request.is_empty() {
            // All bodies downloaded, move to processing
            if !self.ready_blocks.is_empty() {
                self.state = SyncState::Processing;
            }
            return requests;
        }

        // Distribute requests across peers
        let batch_size = self.config.max_blocks_per_request;
        for chunk in to_request.chunks(batch_size) {
            // Find suitable peer
            if let Some(peer) = peers.iter().find(|p| p.is_active()) {
                let id = self.next_request_id;
                self.next_request_id += 1;

                requests.push(SyncRequest2 {
                    id,
                    peer: peer.id,
                    payload: SyncRequestPayload::GetBodies(chunk.to_vec()),
                });

                self.requests.insert(id, SyncRequest {
                    request_type: SyncRequestType::Bodies,
                    peer: peer.id,
                    sent_at: Instant::now(),
                    items: chunk.iter().map(|h| h.0).collect(),
                });
            }
        }

        requests
    }

    /// Generate state requests (for fast sync)
    fn generate_state_requests(&mut self, _peers: &[&PeerInfo]) -> Vec<SyncRequest2> {
        // State sync implementation would go here
        Vec::new()
    }

    /// Process sync response
    pub fn process_response(
        &mut self,
        request_id: u64,
        response: SyncResponse,
        from_peer: PeerId,
    ) -> P2PResult<Vec<Block>> {
        // Remove request tracking
        let request = self.requests.remove(&request_id);
        if request.is_none() {
            return Ok(Vec::new()); // Unknown request
        }

        let request = request.unwrap();
        if request.peer != from_peer {
            // Wrong peer responded
            return Err(P2PError::ProtocolError("Response from wrong peer".into()));
        }

        match response {
            SyncResponse::Headers(headers) => {
                self.process_headers(headers, from_peer)
            }
            SyncResponse::Bodies(blocks) => {
                self.process_bodies(blocks, from_peer)
            }
            SyncResponse::State(pieces) => {
                self.process_state(pieces);
                Ok(Vec::new())
            }
            SyncResponse::Checkpoint(checkpoint) => {
                self.process_checkpoint(checkpoint);
                Ok(Vec::new())
            }
        }
    }

    /// Process received headers
    fn process_headers(
        &mut self,
        headers: Vec<BlockHeaderPayload>,
        from_peer: PeerId,
    ) -> P2PResult<Vec<Block>> {
        if headers.is_empty() {
            return Ok(Vec::new());
        }

        self.stats.headers_downloaded += headers.len() as u64;

        // Validate chain continuity
        let mut last_hash = if let Some(last) = self.header_queue.back() {
            last.hash
        } else {
            self.current_hash
        };

        for header in headers {
            // Check parent linkage
            if header.parent_hash != last_hash && header.height > 0 {
                // Gap in headers - might need to find ancestor
                if self.state == SyncState::FindingAncestor {
                    // Expected during ancestor finding
                } else {
                    self.state = SyncState::FindingAncestor;
                    return Ok(Vec::new());
                }
            }

            let queued = QueuedBlock {
                height: header.height,
                hash: header.hash,
                parent_hash: header.parent_hash,
                header: Some(header.clone()),
                block: None,
                from_peer: Some(from_peer),
            };

            self.header_queue.push_back(queued);
            self.bodies_needed.insert(header.hash, header.height);
            last_hash = header.hash;
        }

        // Transition to body download
        if self.header_queue.len() >= self.config.batch_size {
            self.state = SyncState::DownloadingBodies;
        }

        Ok(Vec::new())
    }

    /// Process received block bodies
    fn process_bodies(
        &mut self,
        blocks: Vec<Block>,
        _from_peer: PeerId,
    ) -> P2PResult<Vec<Block>> {
        let mut ready = Vec::new();

        for block in blocks {
            let hash = block.header.hash();
            self.bodies_needed.remove(&hash);
            self.stats.blocks_downloaded += 1;

            // Check if parent exists
            if block.header.height == 0 ||
               self.ready_blocks.contains_key(&block.header.parent_hash) ||
               block.header.parent_hash == self.current_hash {
                ready.push(block);
            } else {
                // Orphan block
                self.orphans
                    .entry(block.header.parent_hash)
                    .or_insert_with(Vec::new)
                    .push(block);
            }
        }

        // Check for orphans that can now be connected
        let mut newly_ready = Vec::new();
        for block in &ready {
            let hash = block.header.hash();
            if let Some(orphans) = self.orphans.remove(&hash) {
                newly_ready.extend(orphans);
            }
        }
        ready.extend(newly_ready);

        // Limit orphan cache
        while self.orphans.len() > self.config.max_orphans {
            if let Some(key) = self.orphans.keys().next().cloned() {
                self.orphans.remove(&key);
            }
        }

        Ok(ready)
    }

    /// Process state pieces
    fn process_state(&mut self, pieces: Vec<(Vec<u8>, Vec<u8>)>) {
        for (key, _value) in pieces {
            let mut hash = [0u8; 32];
            if key.len() >= 32 {
                hash.copy_from_slice(&key[..32]);
            }
            self.state_pieces.insert(hash);
            self.stats.state_pieces_downloaded += 1;
        }
    }

    /// Process checkpoint
    fn process_checkpoint(&mut self, checkpoint: CheckpointPayload) {
        self.checkpoint = Some((checkpoint.epoch, checkpoint.height, checkpoint.hash));
    }

    /// Check for request timeouts
    fn check_timeouts(&mut self) {
        let timeout = self.config.request_timeout;
        let now = Instant::now();

        let timed_out: Vec<_> = self.requests
            .iter()
            .filter(|(_, req)| now.duration_since(req.sent_at) > timeout)
            .map(|(id, _)| *id)
            .collect();

        for id in timed_out {
            if let Some(req) = self.requests.remove(&id) {
                self.stats.timeouts += 1;

                // Re-add bodies to needed list
                if matches!(req.request_type, SyncRequestType::Bodies) {
                    for hash in req.items {
                        // Would need height - simplified here
                        self.bodies_needed.insert(BlockHash(hash), 0);
                    }
                }
            }
        }
    }

    /// Mark block as processed
    pub fn mark_processed(&mut self, hash: BlockHash, height: u64) {
        self.stats.blocks_processed += 1;

        // Update current
        if height > self.current_height {
            self.current_height = height;
            self.current_hash = hash;
        }

        // Remove from queues
        while let Some(front) = self.header_queue.front() {
            if front.height <= height {
                self.header_queue.pop_front();
            } else {
                break;
            }
        }

        // Check if synced
        if self.current_height >= self.target_height {
            self.state = SyncState::Synced;
            self.update_sync_speed();
        }
    }

    /// Update sync speed statistic
    fn update_sync_speed(&mut self) {
        if let Some(started) = self.started_at {
            let elapsed = started.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                self.stats.sync_speed = self.stats.blocks_processed as f64 / elapsed;
            }
        }
    }

    /// Handle new block announcement
    pub fn handle_block_announce(
        &mut self,
        height: u64,
        hash: BlockHash,
        peer: PeerId,
    ) {
        if height > self.target_height {
            self.target_height = height;
            self.target_hash = hash;

            // Start or continue sync
            if matches!(self.state, SyncState::Idle | SyncState::Synced) {
                if height > self.current_height + 1 {
                    self.start_sync(height, hash, peer);
                }
            }
        }
    }

    /// Reset sync state
    pub fn reset(&mut self) {
        self.state = SyncState::Idle;
        self.requests.clear();
        self.header_queue.clear();
        self.bodies_needed.clear();
        self.ready_blocks.clear();
        self.orphans.clear();
        self.sync_peer = None;
        self.started_at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_engine_creation() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config, 100, BlockHash([1u8; 32]));

        assert_eq!(engine.state(), SyncState::Idle);
        assert_eq!(engine.current_height, 100);
        assert!(!engine.is_syncing());
    }

    #[test]
    fn test_sync_start() {
        let config = SyncConfig::default();
        let mut engine = SyncEngine::new(config, 100, BlockHash([1u8; 32]));

        let peer_id = PeerId::from_bytes([1u8; 32]);
        engine.start_sync(200, BlockHash([2u8; 32]), peer_id);

        assert!(engine.is_syncing());
        assert_eq!(engine.state(), SyncState::FindingAncestor);
        assert_eq!(engine.target_height, 200);
    }

    #[test]
    fn test_sync_progress() {
        let config = SyncConfig::default();
        let mut engine = SyncEngine::new(config, 100, BlockHash([1u8; 32]));

        // Before sync
        assert_eq!(engine.progress(), 1.0);

        // During sync
        let peer_id = PeerId::from_bytes([1u8; 32]);
        engine.start_sync(200, BlockHash([2u8; 32]), peer_id);
        assert_eq!(engine.progress(), 0.0);

        // Partial progress
        engine.stats.blocks_processed = 50;
        assert!(engine.progress() > 0.0);
        assert!(engine.progress() < 1.0);
    }

    #[test]
    fn test_mark_processed() {
        let config = SyncConfig::default();
        let mut engine = SyncEngine::new(config, 100, BlockHash([1u8; 32]));

        let peer_id = PeerId::from_bytes([1u8; 32]);
        engine.start_sync(105, BlockHash([2u8; 32]), peer_id);

        // Process blocks
        engine.mark_processed(BlockHash([10u8; 32]), 101);
        engine.mark_processed(BlockHash([11u8; 32]), 102);

        assert_eq!(engine.stats.blocks_processed, 2);
        assert_eq!(engine.current_height, 102);
    }

    #[test]
    fn test_sync_completes() {
        let config = SyncConfig::default();
        let mut engine = SyncEngine::new(config, 100, BlockHash([1u8; 32]));

        let peer_id = PeerId::from_bytes([1u8; 32]);
        engine.start_sync(102, BlockHash([2u8; 32]), peer_id);

        // Process to target
        engine.mark_processed(BlockHash([10u8; 32]), 101);
        engine.mark_processed(BlockHash([2u8; 32]), 102);

        assert_eq!(engine.state(), SyncState::Synced);
        assert!(!engine.is_syncing());
    }

    #[test]
    fn test_block_announce_handling() {
        let config = SyncConfig::default();
        let mut engine = SyncEngine::new(config, 100, BlockHash([1u8; 32]));

        let peer_id = PeerId::from_bytes([1u8; 32]);

        // Announce much higher block
        engine.handle_block_announce(150, BlockHash([5u8; 32]), peer_id);

        assert!(engine.is_syncing());
        assert_eq!(engine.target_height, 150);
    }
}
