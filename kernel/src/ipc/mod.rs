//! Inter-Process Communication (IPC)
//!
//! Message-passing IPC inspired by seL4:
//! - Synchronous IPC (call/reply)
//! - Asynchronous notifications
//! - Capability transfer
//!
//! # Message Format
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │                      IPC Message                           │
//! ├──────────────┬──────────────┬──────────────────────────────┤
//! │  Label (64)  │  Length (32) │  Caps Count (32)             │
//! ├──────────────┴──────────────┴──────────────────────────────┤
//! │                    Inline Data (up to 256 bytes)           │
//! ├────────────────────────────────────────────────────────────┤
//! │                    Capability Slots                        │
//! └────────────────────────────────────────────────────────────┘
//! ```

use crate::{KernelResult, KernelError};
use crate::caps::{CapId, CapRights, Capability};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;

/// Maximum inline message data
pub const MAX_MSG_SIZE: usize = 256;

/// Maximum capabilities per message
pub const MAX_MSG_CAPS: usize = 4;

/// Maximum pending messages per endpoint
pub const MAX_PENDING: usize = 64;

/// Global endpoint registry
static ENDPOINTS: Mutex<EndpointRegistry> = Mutex::new(EndpointRegistry::new());

/// Initialize IPC subsystem
pub fn init() -> KernelResult<()> {
    log::debug!("IPC subsystem initialized");
    Ok(())
}

/// IPC message
#[derive(Clone)]
pub struct Message {
    /// Message label (opcode/type)
    pub label: u64,
    /// Inline data
    pub data: [u8; MAX_MSG_SIZE],
    /// Data length
    pub data_len: usize,
    /// Transferred capabilities
    pub caps: [Option<CapId>; MAX_MSG_CAPS],
    /// Number of capabilities
    pub cap_count: usize,
    /// Sender badge (set by kernel)
    pub badge: u64,
}

impl Message {
    /// Create empty message
    pub fn new(label: u64) -> Self {
        Self {
            label,
            data: [0; MAX_MSG_SIZE],
            data_len: 0,
            caps: [None; MAX_MSG_CAPS],
            cap_count: 0,
            badge: 0,
        }
    }

    /// Create message with data
    pub fn with_data(label: u64, data: &[u8]) -> KernelResult<Self> {
        if data.len() > MAX_MSG_SIZE {
            return Err(KernelError::InvalidArgument);
        }

        let mut msg = Self::new(label);
        msg.data[..data.len()].copy_from_slice(data);
        msg.data_len = data.len();

        Ok(msg)
    }

    /// Add capability to transfer
    pub fn add_cap(&mut self, cap: CapId) -> KernelResult<()> {
        if self.cap_count >= MAX_MSG_CAPS {
            return Err(KernelError::InvalidArgument);
        }

        self.caps[self.cap_count] = Some(cap);
        self.cap_count += 1;

        Ok(())
    }

    /// Get data slice
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

impl Default for Message {
    fn default() -> Self {
        Self::new(0)
    }
}

/// IPC endpoint state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointState {
    /// Idle, no waiters
    Idle,
    /// Thread(s) waiting to send
    SendWait,
    /// Thread(s) waiting to receive
    RecvWait,
}

/// IPC endpoint
pub struct Endpoint {
    /// Endpoint ID
    pub id: u64,
    /// Current state
    pub state: EndpointState,
    /// Pending messages (for async)
    pending: VecDeque<(Message, u32)>, // (message, sender_pid)
    /// Waiting senders (thread IDs)
    send_queue: VecDeque<u32>,
    /// Waiting receivers (thread IDs)
    recv_queue: VecDeque<u32>,
    /// Badge for sends to this endpoint
    pub badge: u64,
}

impl Endpoint {
    /// Create new endpoint
    pub fn new(id: u64) -> Self {
        Self {
            id,
            state: EndpointState::Idle,
            pending: VecDeque::new(),
            send_queue: VecDeque::new(),
            recv_queue: VecDeque::new(),
            badge: 0,
        }
    }

    /// Set badge for this endpoint
    pub fn set_badge(&mut self, badge: u64) {
        self.badge = badge;
    }

    /// Enqueue a message (async send)
    pub fn enqueue(&mut self, msg: Message, sender: u32) -> KernelResult<()> {
        if self.pending.len() >= MAX_PENDING {
            return Err(KernelError::WouldBlock);
        }

        self.pending.push_back((msg, sender));

        // Wake up receiver if any
        if let Some(_receiver) = self.recv_queue.pop_front() {
            // In real implementation, unblock the receiver thread
            self.state = EndpointState::Idle;
        }

        Ok(())
    }

    /// Dequeue a message (async receive)
    pub fn dequeue(&mut self) -> Option<(Message, u32)> {
        self.pending.pop_front()
    }

    /// Add sender to wait queue
    pub fn wait_send(&mut self, tid: u32) {
        self.send_queue.push_back(tid);
        self.state = EndpointState::SendWait;
    }

    /// Add receiver to wait queue
    pub fn wait_recv(&mut self, tid: u32) {
        self.recv_queue.push_back(tid);
        self.state = EndpointState::RecvWait;
    }

    /// Get next waiting sender
    pub fn pop_sender(&mut self) -> Option<u32> {
        let sender = self.send_queue.pop_front();
        if self.send_queue.is_empty() && self.state == EndpointState::SendWait {
            self.state = EndpointState::Idle;
        }
        sender
    }

    /// Get next waiting receiver
    pub fn pop_receiver(&mut self) -> Option<u32> {
        let receiver = self.recv_queue.pop_front();
        if self.recv_queue.is_empty() && self.state == EndpointState::RecvWait {
            self.state = EndpointState::Idle;
        }
        receiver
    }
}

/// Endpoint registry
struct EndpointRegistry {
    next_id: u64,
    endpoints: Vec<Endpoint>,
}

impl EndpointRegistry {
    const fn new() -> Self {
        Self {
            next_id: 1,
            endpoints: Vec::new(),
        }
    }

    fn create(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.endpoints.push(Endpoint::new(id));
        id
    }

    fn get(&self, id: u64) -> Option<&Endpoint> {
        self.endpoints.iter().find(|e| e.id == id)
    }

    fn get_mut(&mut self, id: u64) -> Option<&mut Endpoint> {
        self.endpoints.iter_mut().find(|e| e.id == id)
    }
}

/// Create new endpoint
pub fn create_endpoint() -> u64 {
    ENDPOINTS.lock().create()
}

/// Send message to endpoint (blocking)
pub fn send(endpoint_id: u64, msg: Message, sender_pid: u32) -> KernelResult<()> {
    let mut endpoints = ENDPOINTS.lock();

    let endpoint = endpoints.get_mut(endpoint_id)
        .ok_or(KernelError::NotFound)?;

    // Check if receiver is waiting
    if let Some(_receiver_tid) = endpoint.pop_receiver() {
        // Transfer message directly to receiver
        // In real implementation, copy to receiver's buffer and unblock
        let mut tagged_msg = msg;
        tagged_msg.badge = endpoint.badge;
        endpoint.enqueue(tagged_msg, sender_pid)?;
        Ok(())
    } else {
        // No receiver, queue the message
        let mut tagged_msg = msg;
        tagged_msg.badge = endpoint.badge;
        endpoint.enqueue(tagged_msg, sender_pid)
    }
}

/// Receive message from endpoint (blocking)
pub fn receive(endpoint_id: u64, _receiver_tid: u32) -> KernelResult<(Message, u32)> {
    let mut endpoints = ENDPOINTS.lock();

    let endpoint = endpoints.get_mut(endpoint_id)
        .ok_or(KernelError::NotFound)?;

    // Check for pending message
    if let Some((msg, sender)) = endpoint.dequeue() {
        return Ok((msg, sender));
    }

    // No message available
    // In real implementation, block the thread
    Err(KernelError::WouldBlock)
}

/// Non-blocking poll for message
pub fn poll(endpoint_id: u64) -> KernelResult<Option<(Message, u32)>> {
    let mut endpoints = ENDPOINTS.lock();

    let endpoint = endpoints.get_mut(endpoint_id)
        .ok_or(KernelError::NotFound)?;

    Ok(endpoint.dequeue())
}

/// Notification word (for lightweight async signaling)
#[derive(Debug, Default)]
pub struct Notification {
    /// Notification bits
    bits: u64,
    /// Waiting thread
    waiter: Option<u32>,
}

impl Notification {
    /// Create new notification
    pub fn new() -> Self {
        Self::default()
    }

    /// Signal notification (set bits)
    pub fn signal(&mut self, bits: u64) {
        self.bits |= bits;
        // Wake waiter if any
        if let Some(_tid) = self.waiter.take() {
            // Unblock thread
        }
    }

    /// Wait for notification (returns bits and clears them)
    pub fn wait(&mut self, tid: u32) -> Option<u64> {
        if self.bits != 0 {
            let bits = self.bits;
            self.bits = 0;
            Some(bits)
        } else {
            self.waiter = Some(tid);
            None
        }
    }

    /// Poll without blocking
    pub fn poll(&mut self) -> u64 {
        let bits = self.bits;
        self.bits = 0;
        bits
    }
}

/// Reply capability (single-use, for synchronous IPC)
#[derive(Debug)]
pub struct ReplyCap {
    /// Target thread to reply to
    pub target_tid: u32,
    /// Whether reply has been used
    pub used: bool,
}

impl ReplyCap {
    /// Create new reply capability
    pub fn new(target_tid: u32) -> Self {
        Self {
            target_tid,
            used: false,
        }
    }

    /// Use the reply capability (can only be used once)
    pub fn reply(&mut self, msg: Message) -> KernelResult<()> {
        if self.used {
            return Err(KernelError::InvalidCapability);
        }

        self.used = true;

        // Transfer message to target thread
        // In real implementation, unblock target and copy message
        log::debug!("Reply to thread {} with label {}", self.target_tid, msg.label);

        Ok(())
    }
}
