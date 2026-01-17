//! Stream Multiplexing
//!
//! Streams are multiplexed TCP-like connections over circuits.
//!
//! # Stream Lifecycle
//!
//! 1. Client sends BEGIN with target address
//! 2. Exit relay connects to destination
//! 3. Exit sends CONNECTED on success
//! 4. DATA cells flow bidirectionally
//! 5. END cell closes stream
//!
//! # Flow Control
//!
//! - Window-based flow control per stream
//! - SENDME cells to acknowledge received data
//! - Prevents memory exhaustion attacks

use crate::{MuonResult, MuonError, CELL_PAYLOAD_SIZE};
use crate::cell::{RelayCell, RelayCommand, EndReason};
use crate::circuit::{Circuit, CircuitId};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Maximum relay payload for data
pub const MAX_STREAM_DATA: usize = CELL_PAYLOAD_SIZE - 5; // 5 byte relay header

/// Default stream window size (in cells)
pub const DEFAULT_STREAM_WINDOW: u32 = 500;

/// SENDME threshold (send SENDME after receiving this many cells)
pub const SENDME_THRESHOLD: u32 = 50;

/// Unique stream identifier (within a circuit)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId {
    /// Parent circuit ID
    pub circuit_id: CircuitId,
    /// Stream ID (local to circuit)
    pub stream_id: u16,
}

impl StreamId {
    /// Create new stream ID
    pub fn new(circuit_id: CircuitId, stream_id: u16) -> Self {
        Self { circuit_id, stream_id }
    }
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:Stream({})", self.circuit_id, self.stream_id)
    }
}

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuonStreamState {
    /// Waiting for CONNECTED
    Connecting,
    /// Stream is open
    Open,
    /// Stream half-closed (read)
    HalfClosedRead,
    /// Stream half-closed (write)
    HalfClosedWrite,
    /// Stream closing
    Closing,
    /// Stream closed normally
    Closed,
    /// Stream closed due to error
    Error,
}

impl MuonStreamState {
    /// Check if stream can send data
    pub fn can_write(&self) -> bool {
        matches!(self, MuonStreamState::Open | MuonStreamState::HalfClosedRead)
    }

    /// Check if stream can receive data
    pub fn can_read(&self) -> bool {
        matches!(self, MuonStreamState::Open | MuonStreamState::HalfClosedWrite)
    }

    /// Check if stream is terminal
    pub fn is_terminal(&self) -> bool {
        matches!(self, MuonStreamState::Closed | MuonStreamState::Error)
    }
}

/// A multiplexed stream over a circuit
#[derive(Debug)]
pub struct MuonStream {
    /// Stream identifier
    id: StreamId,
    /// Target address (host:port)
    target: String,
    /// Current state
    state: MuonStreamState,
    /// Receive buffer
    recv_buffer: BytesMut,
    /// Send buffer (pending data)
    send_buffer: VecDeque<Bytes>,
    /// Receive window (cells we can receive)
    recv_window: u32,
    /// Send window (cells we can send)
    send_window: u32,
    /// Cells received since last SENDME
    recv_since_sendme: u32,
    /// End reason (if closed)
    end_reason: Option<EndReason>,
    /// Creation time
    created_at: Instant,
    /// Last activity
    last_activity: Instant,
    /// Total bytes sent
    bytes_sent: u64,
    /// Total bytes received
    bytes_received: u64,
}

impl MuonStream {
    /// Create a new stream
    pub fn new(circuit_id: CircuitId, stream_id: u16, target: String) -> Self {
        Self {
            id: StreamId::new(circuit_id, stream_id),
            target,
            state: MuonStreamState::Connecting,
            recv_buffer: BytesMut::new(),
            send_buffer: VecDeque::new(),
            recv_window: DEFAULT_STREAM_WINDOW,
            send_window: DEFAULT_STREAM_WINDOW,
            recv_since_sendme: 0,
            end_reason: None,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Get stream ID
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Get raw stream ID (within circuit)
    pub fn stream_id(&self) -> u16 {
        self.id.stream_id
    }

    /// Get circuit ID
    pub fn circuit_id(&self) -> CircuitId {
        self.id.circuit_id
    }

    /// Get target address
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Get current state
    pub fn state(&self) -> MuonStreamState {
        self.state
    }

    /// Check if stream is connected
    pub fn is_connected(&self) -> bool {
        self.state == MuonStreamState::Open
    }

    /// Mark stream as connected
    pub fn mark_connected(&mut self) {
        if self.state == MuonStreamState::Connecting {
            self.state = MuonStreamState::Open;
            self.last_activity = Instant::now();
        }
    }

    /// Check if stream can send
    pub fn can_write(&self) -> bool {
        self.state.can_write() && self.send_window > 0
    }

    /// Check if stream can receive
    pub fn can_read(&self) -> bool {
        self.state.can_read()
    }

    /// Get available send window
    pub fn send_window(&self) -> u32 {
        self.send_window
    }

    /// Get pending data in receive buffer
    pub fn available(&self) -> usize {
        self.recv_buffer.len()
    }

    /// Queue data for sending
    pub fn queue_send(&mut self, data: Bytes) -> MuonResult<()> {
        if !self.can_write() {
            return Err(MuonError::StreamClosed(self.id.stream_id));
        }

        self.send_buffer.push_back(data);
        Ok(())
    }

    /// Get next chunk of data to send
    pub fn next_send_chunk(&mut self) -> Option<Bytes> {
        if self.send_window == 0 {
            return None;
        }

        if let Some(data) = self.send_buffer.pop_front() {
            // Split if too large
            if data.len() > MAX_STREAM_DATA {
                let chunk = data.slice(0..MAX_STREAM_DATA);
                let remainder = data.slice(MAX_STREAM_DATA..);
                self.send_buffer.push_front(remainder);
                self.send_window -= 1;
                self.bytes_sent += chunk.len() as u64;
                return Some(chunk);
            }

            self.send_window -= 1;
            self.bytes_sent += data.len() as u64;
            return Some(data);
        }

        None
    }

    /// Check if there's data pending to send
    pub fn has_pending_send(&self) -> bool {
        !self.send_buffer.is_empty()
    }

    /// Receive data from relay cell
    pub fn receive_data(&mut self, data: &[u8]) -> MuonResult<()> {
        if !self.can_read() {
            return Err(MuonError::StreamClosed(self.id.stream_id));
        }

        if self.recv_window == 0 {
            return Err(MuonError::FlowControlViolation(
                format!("Stream {} receive window exhausted", self.id)
            ));
        }

        self.recv_buffer.extend_from_slice(data);
        self.recv_window -= 1;
        self.recv_since_sendme += 1;
        self.bytes_received += data.len() as u64;
        self.last_activity = Instant::now();

        Ok(())
    }

    /// Read data from receive buffer
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let len = std::cmp::min(buf.len(), self.recv_buffer.len());
        buf[..len].copy_from_slice(&self.recv_buffer[..len]);
        self.recv_buffer.advance(len);
        len
    }

    /// Read all available data
    pub fn read_all(&mut self) -> Bytes {
        self.recv_buffer.split().freeze()
    }

    /// Check if SENDME should be sent
    pub fn should_send_sendme(&self) -> bool {
        self.recv_since_sendme >= SENDME_THRESHOLD
    }

    /// Create SENDME cell
    pub fn create_sendme(&mut self) -> RelayCell {
        self.recv_since_sendme = 0;
        self.recv_window += SENDME_THRESHOLD;
        RelayCell::new(self.id.stream_id, RelayCommand::SendMe, Bytes::new())
    }

    /// Process SENDME from peer
    pub fn process_sendme(&mut self) {
        self.send_window += SENDME_THRESHOLD;
        self.last_activity = Instant::now();
    }

    /// Handle END cell
    pub fn handle_end(&mut self, reason: EndReason) {
        self.state = if reason == EndReason::Done {
            MuonStreamState::Closed
        } else {
            MuonStreamState::Error
        };
        self.end_reason = Some(reason);
    }

    /// Close the stream (local)
    pub fn close(&mut self) -> Option<RelayCell> {
        match self.state {
            MuonStreamState::Open | MuonStreamState::HalfClosedRead => {
                self.state = MuonStreamState::Closing;
                Some(RelayCell::end(self.id.stream_id, EndReason::Done))
            }
            MuonStreamState::Connecting => {
                self.state = MuonStreamState::Closing;
                Some(RelayCell::end(self.id.stream_id, EndReason::Misc))
            }
            _ => None,
        }
    }

    /// Mark stream as fully closed
    pub fn mark_closed(&mut self) {
        self.state = MuonStreamState::Closed;
    }

    /// Get end reason
    pub fn end_reason(&self) -> Option<EndReason> {
        self.end_reason
    }

    /// Get stream age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Get bytes sent
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Get bytes received
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }
}

/// Stream manager for a circuit
#[derive(Debug)]
pub struct StreamManager {
    /// Circuit ID
    circuit_id: CircuitId,
    /// Active streams
    streams: std::collections::HashMap<u16, MuonStream>,
    /// Next stream ID
    next_id: u16,
    /// Maximum concurrent streams
    max_streams: usize,
}

impl StreamManager {
    /// Create new stream manager
    pub fn new(circuit_id: CircuitId, max_streams: usize) -> Self {
        Self {
            circuit_id,
            streams: std::collections::HashMap::new(),
            next_id: 1,
            max_streams,
        }
    }

    /// Create a new stream
    pub fn create_stream(&mut self, target: String) -> MuonResult<&mut MuonStream> {
        if self.streams.len() >= self.max_streams {
            return Err(MuonError::StreamLimitReached(self.circuit_id.value()));
        }

        let stream_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            self.next_id = 1;
        }

        let stream = MuonStream::new(self.circuit_id, stream_id, target);
        self.streams.insert(stream_id, stream);

        Ok(self.streams.get_mut(&stream_id).unwrap())
    }

    /// Get stream by ID
    pub fn get(&self, stream_id: u16) -> Option<&MuonStream> {
        self.streams.get(&stream_id)
    }

    /// Get mutable stream by ID
    pub fn get_mut(&mut self, stream_id: u16) -> Option<&mut MuonStream> {
        self.streams.get_mut(&stream_id)
    }

    /// Remove stream
    pub fn remove(&mut self, stream_id: u16) -> Option<MuonStream> {
        self.streams.remove(&stream_id)
    }

    /// Get number of active streams
    pub fn active_count(&self) -> usize {
        self.streams.values()
            .filter(|s| !s.state().is_terminal())
            .count()
    }

    /// Get total stream count
    pub fn total_count(&self) -> usize {
        self.streams.len()
    }

    /// Clean up closed streams
    pub fn cleanup(&mut self) {
        self.streams.retain(|_, stream| !stream.state().is_terminal());
    }

    /// Iterate over all streams
    pub fn iter(&self) -> impl Iterator<Item = (&u16, &MuonStream)> {
        self.streams.iter()
    }

    /// Iterate over mutable streams
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&u16, &mut MuonStream)> {
        self.streams.iter_mut()
    }

    /// Process incoming relay cell for streams
    pub fn process_relay(&mut self, cell: &RelayCell) -> MuonResult<()> {
        let stream_id = cell.stream_id;

        match cell.command {
            RelayCommand::Connected => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.mark_connected();
                }
            }
            RelayCommand::Data => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.receive_data(&cell.data)?;
                }
            }
            RelayCommand::End => {
                let reason = if cell.data.is_empty() {
                    EndReason::Misc
                } else {
                    // Parse end reason
                    match cell.data[0] {
                        1 => EndReason::Misc,
                        2 => EndReason::ResolveFailed,
                        3 => EndReason::ConnectRefused,
                        4 => EndReason::ExitPolicy,
                        5 => EndReason::Destroy,
                        6 => EndReason::Done,
                        7 => EndReason::Timeout,
                        _ => EndReason::Misc,
                    }
                };
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.handle_end(reason);
                }
            }
            RelayCommand::SendMe => {
                if stream_id != 0 {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.process_sendme();
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Get streams that need SENDME
    pub fn streams_needing_sendme(&mut self) -> Vec<u16> {
        self.streams.iter()
            .filter(|(_, s)| s.should_send_sendme())
            .map(|(id, _)| *id)
            .collect()
    }
}

/// Async-compatible stream wrapper (for use with tokio)
pub struct AsyncMuonStream {
    stream: MuonStream,
}

impl AsyncMuonStream {
    /// Create from MuonStream
    pub fn new(stream: MuonStream) -> Self {
        Self { stream }
    }

    /// Get inner stream
    pub fn inner(&self) -> &MuonStream {
        &self.stream
    }

    /// Get mutable inner stream
    pub fn inner_mut(&mut self) -> &mut MuonStream {
        &mut self.stream
    }

    /// Into inner
    pub fn into_inner(self) -> MuonStream {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_circuit_id() -> CircuitId {
        CircuitId::new(42)
    }

    #[test]
    fn test_stream_creation() {
        let stream = MuonStream::new(test_circuit_id(), 1, "example.com:80".into());

        assert_eq!(stream.stream_id(), 1);
        assert_eq!(stream.target(), "example.com:80");
        assert_eq!(stream.state(), MuonStreamState::Connecting);
    }

    #[test]
    fn test_stream_connect() {
        let mut stream = MuonStream::new(test_circuit_id(), 1, "example.com:80".into());

        assert!(!stream.is_connected());
        stream.mark_connected();
        assert!(stream.is_connected());
        assert!(stream.can_write());
        assert!(stream.can_read());
    }

    #[test]
    fn test_stream_data() {
        let mut stream = MuonStream::new(test_circuit_id(), 1, "example.com:80".into());
        stream.mark_connected();

        // Receive data
        stream.receive_data(b"Hello").unwrap();
        stream.receive_data(b" World").unwrap();

        assert_eq!(stream.available(), 11);

        // Read data
        let data = stream.read_all();
        assert_eq!(&data[..], b"Hello World");
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn test_stream_send_buffer() {
        let mut stream = MuonStream::new(test_circuit_id(), 1, "example.com:80".into());
        stream.mark_connected();

        stream.queue_send(Bytes::from("test data")).unwrap();
        assert!(stream.has_pending_send());

        let chunk = stream.next_send_chunk().unwrap();
        assert_eq!(&chunk[..], b"test data");
        assert!(!stream.has_pending_send());
    }

    #[test]
    fn test_flow_control() {
        let mut stream = MuonStream::new(test_circuit_id(), 1, "example.com:80".into());
        stream.mark_connected();

        // Receive cells up to SENDME threshold
        for _ in 0..SENDME_THRESHOLD {
            stream.receive_data(b"x").unwrap();
        }

        assert!(stream.should_send_sendme());

        let _sendme = stream.create_sendme();
        assert!(!stream.should_send_sendme());
    }

    #[test]
    fn test_stream_manager() {
        let mut manager = StreamManager::new(test_circuit_id(), 100);

        let stream = manager.create_stream("example.com:80".into()).unwrap();
        let id = stream.stream_id();

        assert!(manager.get(id).is_some());
        assert_eq!(manager.total_count(), 1);

        manager.remove(id);
        assert!(manager.get(id).is_none());
    }

    #[test]
    fn test_stream_close() {
        let mut stream = MuonStream::new(test_circuit_id(), 1, "example.com:80".into());
        stream.mark_connected();

        let end_cell = stream.close();
        assert!(end_cell.is_some());
        assert_eq!(stream.state(), MuonStreamState::Closing);
    }
}
