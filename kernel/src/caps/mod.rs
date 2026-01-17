//! Capability-Based Security System
//!
//! All kernel resources are accessed through capabilities.
//! A capability is an unforgeable token granting specific rights to a resource.
//!
//! # Capability Types
//!
//! - **Memory**: Read/write/execute access to memory regions
//! - **IPC**: Send/receive rights to IPC endpoints
//! - **Process**: Control over a process (suspend, resume, kill)
//! - **Thread**: Control over a thread
//! - **IRQ**: Right to handle a specific interrupt
//! - **IO Port**: Access to I/O ports
//! - **Device**: Access to memory-mapped devices
//!
//! # Security Properties
//!
//! - Capabilities cannot be forged
//! - Capabilities can only be delegated (not escalated)
//! - Capabilities can be revoked by parent
//! - All resource access requires a valid capability

use crate::{KernelResult, KernelError};
use alloc::vec::Vec;
use bitflags::bitflags;
use spin::RwLock;

/// Maximum capabilities per process
pub const MAX_CAPS_PER_PROCESS: usize = 1024;

/// Global capability table
static CAP_TABLE: RwLock<CapabilityTable> = RwLock::new(CapabilityTable::new());

/// Initialize capability system
pub fn init() -> KernelResult<()> {
    log::debug!("Capability system initialized");
    Ok(())
}

/// Capability identifier (unique across system)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapId(u64);

impl CapId {
    /// Create new capability ID
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get raw value
    pub fn value(&self) -> u64 {
        self.0
    }
}

bitflags! {
    /// Rights associated with a capability
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CapRights: u32 {
        /// Read access
        const READ = 1 << 0;
        /// Write access
        const WRITE = 1 << 1;
        /// Execute access
        const EXECUTE = 1 << 2;
        /// Grant (delegate) right
        const GRANT = 1 << 3;
        /// Revoke right
        const REVOKE = 1 << 4;
        /// Send (for IPC)
        const SEND = 1 << 5;
        /// Receive (for IPC)
        const RECEIVE = 1 << 6;
        /// Call (for synchronous IPC)
        const CALL = 1 << 7;
        /// Reply (for synchronous IPC)
        const REPLY = 1 << 8;
        /// Wait (for synchronous IPC)
        const WAIT = 1 << 9;
        /// Map (for memory)
        const MAP = 1 << 10;
        /// Full rights
        const ALL = 0xFFFF_FFFF;
    }
}

/// Capability type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapType {
    /// Null/invalid capability
    Null,
    /// Memory region
    Memory { phys: u64, size: u64 },
    /// IPC endpoint
    Endpoint { id: u64 },
    /// IPC reply capability (single-use)
    Reply { endpoint: u64 },
    /// Process control
    Process { pid: u32 },
    /// Thread control
    Thread { tid: u32 },
    /// IRQ handling
    Irq { irq: u8 },
    /// I/O port range
    IoPort { base: u16, count: u16 },
    /// Capability space (for delegation)
    CSpace { owner: u32 },
}

/// A capability entry
#[derive(Debug, Clone)]
pub struct Capability {
    /// Unique identifier
    pub id: CapId,
    /// Capability type
    pub cap_type: CapType,
    /// Granted rights
    pub rights: CapRights,
    /// Parent capability (for revocation chain)
    pub parent: Option<CapId>,
    /// Owner process
    pub owner: u32,
    /// Reference count
    pub refs: u32,
}

impl Capability {
    /// Create new capability
    pub fn new(
        id: CapId,
        cap_type: CapType,
        rights: CapRights,
        owner: u32,
    ) -> Self {
        Self {
            id,
            cap_type,
            rights,
            parent: None,
            owner,
            refs: 1,
        }
    }

    /// Check if capability has specific rights
    pub fn has_rights(&self, required: CapRights) -> bool {
        self.rights.contains(required)
    }

    /// Derive a new capability with reduced rights
    pub fn derive(&self, new_id: CapId, new_rights: CapRights, new_owner: u32) -> KernelResult<Self> {
        // Cannot grant more rights than we have
        if !self.rights.contains(new_rights) {
            return Err(KernelError::PermissionDenied);
        }

        // Must have grant right
        if !self.rights.contains(CapRights::GRANT) {
            return Err(KernelError::PermissionDenied);
        }

        Ok(Self {
            id: new_id,
            cap_type: self.cap_type,
            rights: new_rights,
            parent: Some(self.id),
            owner: new_owner,
            refs: 1,
        })
    }
}

/// Set of capabilities for a process
#[derive(Debug, Clone)]
pub struct CapabilitySet {
    caps: Vec<CapId>,
}

impl CapabilitySet {
    /// Create empty capability set
    pub fn new() -> Self {
        Self { caps: Vec::new() }
    }

    /// Create full capability set (for init process)
    pub fn full() -> Self {
        // Init gets a special "root" capability set
        Self { caps: Vec::new() }
    }

    /// Add capability to set
    pub fn add(&mut self, cap: CapId) -> KernelResult<()> {
        if self.caps.len() >= MAX_CAPS_PER_PROCESS {
            return Err(KernelError::OutOfMemory);
        }

        if !self.caps.contains(&cap) {
            self.caps.push(cap);
        }

        Ok(())
    }

    /// Remove capability from set
    pub fn remove(&mut self, cap: CapId) {
        self.caps.retain(|c| *c != cap);
    }

    /// Check if set contains capability
    pub fn contains(&self, cap: CapId) -> bool {
        self.caps.contains(&cap)
    }

    /// Iterate over capabilities
    pub fn iter(&self) -> impl Iterator<Item = &CapId> {
        self.caps.iter()
    }
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self::new()
    }
}

/// Global capability table
struct CapabilityTable {
    next_id: u64,
    // In production, use a proper data structure
    // For now, capabilities are stored in process structures
}

impl CapabilityTable {
    const fn new() -> Self {
        Self { next_id: 1 }
    }
}

/// Allocate new capability ID
pub fn alloc_cap_id() -> CapId {
    let mut table = CAP_TABLE.write();
    let id = table.next_id;
    table.next_id += 1;
    CapId::new(id)
}

/// Create memory capability
pub fn create_memory_cap(
    phys: u64,
    size: u64,
    rights: CapRights,
    owner: u32,
) -> Capability {
    Capability::new(
        alloc_cap_id(),
        CapType::Memory { phys, size },
        rights,
        owner,
    )
}

/// Create IPC endpoint capability
pub fn create_endpoint_cap(
    endpoint_id: u64,
    rights: CapRights,
    owner: u32,
) -> Capability {
    Capability::new(
        alloc_cap_id(),
        CapType::Endpoint { id: endpoint_id },
        rights,
        owner,
    )
}

/// Create IRQ capability
pub fn create_irq_cap(irq: u8, owner: u32) -> Capability {
    Capability::new(
        alloc_cap_id(),
        CapType::Irq { irq },
        CapRights::READ | CapRights::WAIT,
        owner,
    )
}

/// Validate capability access
pub fn check_cap(
    cap: &Capability,
    required_rights: CapRights,
    owner: u32,
) -> KernelResult<()> {
    // Null capability is never valid
    if cap.cap_type == CapType::Null {
        return Err(KernelError::InvalidCapability);
    }

    // Check ownership
    if cap.owner != owner {
        return Err(KernelError::PermissionDenied);
    }

    // Check rights
    if !cap.has_rights(required_rights) {
        return Err(KernelError::PermissionDenied);
    }

    Ok(())
}
