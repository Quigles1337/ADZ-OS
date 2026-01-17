//! Peer Scoring and Reputation
//!
//! Comprehensive peer scoring system:
//! - Multi-dimensional scoring (behavior, performance, reliability)
//! - Decay over time
//! - Threshold-based actions (disconnect, ban)
//! - Score persistence

use super::peer::PeerId;
use super::PeerOffense;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Scoring parameters
#[derive(Debug, Clone)]
pub struct ScoreParams {
    /// Base score for new peers
    pub base_score: f64,
    /// Maximum positive score
    pub max_score: f64,
    /// Minimum score before ban
    pub ban_threshold: f64,
    /// Score below which disconnect is considered
    pub disconnect_threshold: f64,
    /// Score decay per hour
    pub decay_per_hour: f64,
    /// Penalty for invalid message
    pub invalid_message_penalty: f64,
    /// Penalty for invalid transaction
    pub invalid_tx_penalty: f64,
    /// Penalty for invalid block
    pub invalid_block_penalty: f64,
    /// Penalty for slow response
    pub slow_response_penalty: f64,
    /// Penalty for unresponsive
    pub unresponsive_penalty: f64,
    /// Penalty for excessive duplicates
    pub duplicate_penalty: f64,
    /// Penalty for spam
    pub spam_penalty: f64,
    /// Reward for valid block
    pub valid_block_reward: f64,
    /// Reward for valid transaction
    pub valid_tx_reward: f64,
    /// Reward for fast response
    pub fast_response_reward: f64,
    /// Reward for useful peer exchange
    pub useful_pex_reward: f64,
}

impl Default for ScoreParams {
    fn default() -> Self {
        Self {
            base_score: 100.0,
            max_score: 1000.0,
            ban_threshold: -100.0,
            disconnect_threshold: 0.0,
            decay_per_hour: 5.0,
            invalid_message_penalty: -10.0,
            invalid_tx_penalty: -20.0,
            invalid_block_penalty: -50.0,
            slow_response_penalty: -5.0,
            unresponsive_penalty: -30.0,
            duplicate_penalty: -2.0,
            spam_penalty: -50.0,
            valid_block_reward: 10.0,
            valid_tx_reward: 1.0,
            fast_response_reward: 2.0,
            useful_pex_reward: 5.0,
        }
    }
}

/// Score decay configuration
#[derive(Debug, Clone)]
pub struct ScoreDecay {
    /// Decay interval
    pub interval: Duration,
    /// Decay rate (0.0-1.0, portion to retain)
    pub rate: f64,
}

impl Default for ScoreDecay {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(3600), // 1 hour
            rate: 0.95, // Retain 95% per interval
        }
    }
}

/// Individual score components
#[derive(Debug, Clone, Default)]
pub struct PeerScore {
    /// Behavior score (message validity)
    pub behavior: f64,
    /// Performance score (latency, responsiveness)
    pub performance: f64,
    /// Reliability score (uptime, connection stability)
    pub reliability: f64,
    /// Contribution score (blocks, transactions provided)
    pub contribution: f64,
    /// Last update time
    pub last_update: Option<Instant>,
    /// Last decay time
    pub last_decay: Option<Instant>,
    /// Number of offenses
    pub offenses: u32,
    /// Number of rewards
    pub rewards: u32,
}

impl PeerScore {
    /// Create new score with base values
    pub fn new(base: f64) -> Self {
        let component = base / 4.0;
        Self {
            behavior: component,
            performance: component,
            reliability: component,
            contribution: component,
            last_update: Some(Instant::now()),
            last_decay: Some(Instant::now()),
            offenses: 0,
            rewards: 0,
        }
    }

    /// Calculate total score
    pub fn total(&self) -> f64 {
        self.behavior + self.performance + self.reliability + self.contribution
    }

    /// Apply decay
    pub fn apply_decay(&mut self, decay: &ScoreDecay) {
        if let Some(last) = self.last_decay {
            let elapsed = last.elapsed();
            if elapsed >= decay.interval {
                let intervals = (elapsed.as_secs_f64() / decay.interval.as_secs_f64()) as u32;
                let factor = decay.rate.powi(intervals as i32);

                self.behavior *= factor;
                self.performance *= factor;
                self.reliability *= factor;
                self.contribution *= factor;
                self.last_decay = Some(Instant::now());
            }
        }
    }

    /// Add to behavior score
    pub fn adjust_behavior(&mut self, delta: f64) {
        self.behavior += delta;
        self.last_update = Some(Instant::now());
        if delta < 0.0 {
            self.offenses += 1;
        } else if delta > 0.0 {
            self.rewards += 1;
        }
    }

    /// Add to performance score
    pub fn adjust_performance(&mut self, delta: f64) {
        self.performance += delta;
        self.last_update = Some(Instant::now());
    }

    /// Add to reliability score
    pub fn adjust_reliability(&mut self, delta: f64) {
        self.reliability += delta;
        self.last_update = Some(Instant::now());
    }

    /// Add to contribution score
    pub fn adjust_contribution(&mut self, delta: f64) {
        self.contribution += delta;
        self.last_update = Some(Instant::now());
        if delta > 0.0 {
            self.rewards += 1;
        }
    }

    /// Clamp score to limits
    pub fn clamp(&mut self, min: f64, max: f64) {
        let total = self.total();
        if total > max {
            let factor = max / total;
            self.behavior *= factor;
            self.performance *= factor;
            self.reliability *= factor;
            self.contribution *= factor;
        } else if total < min {
            // Keep at minimum but preserve ratios
            let factor = if total.abs() > 0.001 { min / total } else { 1.0 };
            self.behavior = (self.behavior * factor).max(-50.0);
            self.performance = (self.performance * factor).max(-50.0);
            self.reliability = (self.reliability * factor).max(-50.0);
            self.contribution = (self.contribution * factor).max(-50.0);
        }
    }
}

/// Scoring action to take
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoreAction {
    /// No action needed
    None,
    /// Consider disconnecting
    Disconnect,
    /// Ban the peer
    Ban,
}

/// Peer scorer
#[derive(Debug)]
pub struct PeerScorer {
    /// Score parameters
    params: ScoreParams,
    /// Decay configuration
    decay: ScoreDecay,
    /// Peer scores
    scores: HashMap<PeerId, PeerScore>,
    /// Score history for analytics
    history: HashMap<PeerId, Vec<(Instant, f64, String)>>,
    /// Maximum history entries per peer
    max_history: usize,
}

impl PeerScorer {
    /// Create new scorer
    pub fn new(params: ScoreParams) -> Self {
        Self {
            params,
            decay: ScoreDecay::default(),
            scores: HashMap::new(),
            history: HashMap::new(),
            max_history: 100,
        }
    }

    /// Create with custom decay
    pub fn with_decay(params: ScoreParams, decay: ScoreDecay) -> Self {
        Self {
            params,
            decay,
            scores: HashMap::new(),
            history: HashMap::new(),
            max_history: 100,
        }
    }

    /// Get score for peer (creates if not exists)
    pub fn get_or_create(&mut self, peer_id: &PeerId) -> &mut PeerScore {
        if !self.scores.contains_key(peer_id) {
            self.scores.insert(*peer_id, PeerScore::new(self.params.base_score));
        }
        self.scores.get_mut(peer_id).unwrap()
    }

    /// Get score if exists
    pub fn get_score(&self, peer_id: &PeerId) -> Option<&PeerScore> {
        self.scores.get(peer_id)
    }

    /// Record an offense
    pub fn record_offense(&mut self, peer_id: &PeerId, offense: &PeerOffense) -> ScoreAction {
        let penalty = self.offense_penalty(offense);
        let reason = format!("{:?}", offense);

        // Capture params to avoid borrow conflicts
        let ban_threshold = self.params.ban_threshold;
        let max_score = self.params.max_score;
        let disconnect_threshold = self.params.disconnect_threshold;

        // Ensure score exists
        if !self.scores.contains_key(peer_id) {
            self.scores.insert(*peer_id, PeerScore::new(self.params.base_score));
        }

        // Apply penalty to appropriate component
        let score = self.scores.get_mut(peer_id).unwrap();
        match offense {
            PeerOffense::InvalidMessageFormat |
            PeerOffense::InvalidTransaction |
            PeerOffense::InvalidBlock |
            PeerOffense::VersionMismatch => {
                score.adjust_behavior(penalty);
            }
            PeerOffense::SlowResponse |
            PeerOffense::Unresponsive => {
                score.adjust_performance(penalty);
            }
            PeerOffense::ExcessiveDuplicates |
            PeerOffense::UnsolicitedMessage |
            PeerOffense::Spam |
            PeerOffense::EclipseAttempt => {
                score.adjust_behavior(penalty);
                score.adjust_reliability(penalty / 2.0);
            }
        }

        // Clamp
        score.clamp(ban_threshold, max_score);
        let total = score.total();

        // Record history
        self.record_history(peer_id, penalty, reason);

        // Determine action
        if total <= ban_threshold {
            ScoreAction::Ban
        } else if total <= disconnect_threshold {
            ScoreAction::Disconnect
        } else {
            ScoreAction::None
        }
    }

    /// Get penalty for offense
    fn offense_penalty(&self, offense: &PeerOffense) -> f64 {
        match offense {
            PeerOffense::InvalidMessageFormat => self.params.invalid_message_penalty,
            PeerOffense::InvalidTransaction => self.params.invalid_tx_penalty,
            PeerOffense::InvalidBlock => self.params.invalid_block_penalty,
            PeerOffense::SlowResponse => self.params.slow_response_penalty,
            PeerOffense::Unresponsive => self.params.unresponsive_penalty,
            PeerOffense::ExcessiveDuplicates => self.params.duplicate_penalty,
            PeerOffense::Spam => self.params.spam_penalty,
            PeerOffense::UnsolicitedMessage => self.params.invalid_message_penalty,
            PeerOffense::EclipseAttempt => self.params.spam_penalty * 2.0,
            PeerOffense::VersionMismatch => self.params.invalid_message_penalty,
        }
    }

    /// Record a positive contribution
    pub fn record_contribution(&mut self, peer_id: &PeerId, contribution: PeerContribution) {
        let reward = self.contribution_reward(&contribution);
        let reason = format!("{:?}", contribution);

        // Capture params to avoid borrow conflicts
        let ban_threshold = self.params.ban_threshold;
        let max_score = self.params.max_score;
        let base_score = self.params.base_score;

        // Ensure score exists
        if !self.scores.contains_key(peer_id) {
            self.scores.insert(*peer_id, PeerScore::new(base_score));
        }

        let score = self.scores.get_mut(peer_id).unwrap();
        match contribution {
            PeerContribution::ValidBlock => {
                score.adjust_contribution(reward);
                score.adjust_reliability(reward / 5.0);
            }
            PeerContribution::ValidTransaction => {
                score.adjust_contribution(reward);
            }
            PeerContribution::FastResponse => {
                score.adjust_performance(reward);
            }
            PeerContribution::UsefulPeers => {
                score.adjust_contribution(reward);
            }
            PeerContribution::Attestation => {
                score.adjust_contribution(reward * 2.0);
                score.adjust_reliability(reward);
            }
        }

        score.clamp(ban_threshold, max_score);
        self.record_history(peer_id, reward, reason);
    }

    /// Get reward for contribution
    fn contribution_reward(&self, contribution: &PeerContribution) -> f64 {
        match contribution {
            PeerContribution::ValidBlock => self.params.valid_block_reward,
            PeerContribution::ValidTransaction => self.params.valid_tx_reward,
            PeerContribution::FastResponse => self.params.fast_response_reward,
            PeerContribution::UsefulPeers => self.params.useful_pex_reward,
            PeerContribution::Attestation => self.params.valid_block_reward / 2.0,
        }
    }

    /// Record in history
    fn record_history(&mut self, peer_id: &PeerId, delta: f64, reason: String) {
        let entry = (Instant::now(), delta, reason);
        let history = self.history.entry(*peer_id).or_insert_with(Vec::new);
        history.push(entry);

        // Trim history
        if history.len() > self.max_history {
            history.remove(0);
        }
    }

    /// Apply decay to all scores
    pub fn apply_decay(&mut self) {
        for score in self.scores.values_mut() {
            score.apply_decay(&self.decay);
        }
    }

    /// Remove peer score
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.scores.remove(peer_id);
        self.history.remove(peer_id);
    }

    /// Get all peers below threshold
    pub fn peers_below_threshold(&self, threshold: f64) -> Vec<PeerId> {
        self.scores
            .iter()
            .filter(|(_, score)| score.total() < threshold)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get top-scored peers
    pub fn top_peers(&self, n: usize) -> Vec<(PeerId, f64)> {
        let mut peers: Vec<_> = self.scores
            .iter()
            .map(|(id, score)| (*id, score.total()))
            .collect();

        peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        peers.truncate(n);
        peers
    }

    /// Get scoring statistics
    pub fn stats(&self) -> ScorerStats {
        let scores: Vec<_> = self.scores.values().map(|s| s.total()).collect();

        ScorerStats {
            peer_count: self.scores.len(),
            avg_score: if scores.is_empty() { 0.0 } else { scores.iter().sum::<f64>() / scores.len() as f64 },
            min_score: scores.iter().cloned().fold(f64::INFINITY, f64::min),
            max_score: scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
            below_disconnect: self.peers_below_threshold(self.params.disconnect_threshold).len(),
            below_ban: self.peers_below_threshold(self.params.ban_threshold).len(),
        }
    }
}

/// Positive contributions
#[derive(Debug, Clone)]
pub enum PeerContribution {
    /// Provided valid block
    ValidBlock,
    /// Provided valid transaction
    ValidTransaction,
    /// Responded quickly
    FastResponse,
    /// Provided useful peer addresses
    UsefulPeers,
    /// Provided valid attestation
    Attestation,
}

/// Scorer statistics
#[derive(Debug, Clone)]
pub struct ScorerStats {
    pub peer_count: usize,
    pub avg_score: f64,
    pub min_score: f64,
    pub max_score: f64,
    pub below_disconnect: usize,
    pub below_ban: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_score_creation() {
        let score = PeerScore::new(100.0);
        assert_eq!(score.total(), 100.0);
        assert_eq!(score.behavior, 25.0);
        assert_eq!(score.performance, 25.0);
    }

    #[test]
    fn test_score_adjustments() {
        let mut score = PeerScore::new(100.0);

        score.adjust_behavior(-10.0);
        assert!(score.total() < 100.0);
        assert_eq!(score.offenses, 1);

        score.adjust_contribution(20.0);
        assert!(score.total() > 90.0);
        assert_eq!(score.rewards, 1);
    }

    #[test]
    fn test_score_clamping() {
        let mut score = PeerScore::new(100.0);

        // Exceed max
        score.adjust_contribution(2000.0);
        score.clamp(-100.0, 1000.0);
        assert!(score.total() <= 1000.0);

        // Go below min
        let mut score2 = PeerScore::new(100.0);
        score2.adjust_behavior(-500.0);
        score2.clamp(-100.0, 1000.0);
        // Score should be clamped but still negative
        assert!(score2.total() >= -100.0);
    }

    #[test]
    fn test_scorer_offense_recording() {
        let params = ScoreParams::default();
        let mut scorer = PeerScorer::new(params);

        let peer_id = PeerId::from_bytes([1u8; 32]);

        // Record offense
        let action = scorer.record_offense(&peer_id, &PeerOffense::InvalidTransaction);
        assert_eq!(action, ScoreAction::None);

        let score = scorer.get_score(&peer_id).unwrap();
        assert!(score.total() < 100.0);
        assert_eq!(score.offenses, 1);
    }

    #[test]
    fn test_scorer_contribution_recording() {
        let params = ScoreParams::default();
        let mut scorer = PeerScorer::new(params);

        let peer_id = PeerId::from_bytes([1u8; 32]);

        // Record contribution
        scorer.record_contribution(&peer_id, PeerContribution::ValidBlock);

        let score = scorer.get_score(&peer_id).unwrap();
        assert!(score.total() > 100.0);
        assert_eq!(score.rewards, 1);
    }

    #[test]
    fn test_scorer_ban_threshold() {
        let params = ScoreParams {
            base_score: 20.0, // Start low
            ban_threshold: -30.0, // Ban below this
            disconnect_threshold: 10.0, // Disconnect below this
            invalid_block_penalty: -100.0, // Single severe offense
            ..Default::default()
        };
        let mut scorer = PeerScorer::new(params);

        let peer_id = PeerId::from_bytes([1u8; 32]);

        // First, apply multiple offenses to drive score below ban threshold
        // Base: 20, each offense reduces behavior by 100, clamped per-component
        // After multiple offenses, total should drop below ban_threshold
        scorer.record_offense(&peer_id, &PeerOffense::InvalidBlock);
        scorer.record_offense(&peer_id, &PeerOffense::InvalidBlock);
        let action = scorer.record_offense(&peer_id, &PeerOffense::InvalidBlock);

        // After 3 severe offenses, score should be well below ban threshold
        assert_eq!(action, ScoreAction::Ban);
    }

    #[test]
    fn test_scorer_stats() {
        let params = ScoreParams::default();
        let mut scorer = PeerScorer::new(params);

        let peer1 = PeerId::from_bytes([1u8; 32]);
        let peer2 = PeerId::from_bytes([2u8; 32]);

        scorer.get_or_create(&peer1);
        scorer.get_or_create(&peer2);

        let stats = scorer.stats();
        assert_eq!(stats.peer_count, 2);
        assert!(stats.avg_score > 0.0);
    }

    #[test]
    fn test_top_peers() {
        let params = ScoreParams::default();
        let mut scorer = PeerScorer::new(params);

        let peer1 = PeerId::from_bytes([1u8; 32]);
        let peer2 = PeerId::from_bytes([2u8; 32]);
        let peer3 = PeerId::from_bytes([3u8; 32]);

        scorer.get_or_create(&peer1);
        scorer.record_contribution(&peer2, PeerContribution::ValidBlock);
        scorer.record_contribution(&peer2, PeerContribution::ValidBlock);
        scorer.record_offense(&peer3, &PeerOffense::InvalidTransaction);

        let top = scorer.top_peers(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, peer2); // Highest score
    }
}
