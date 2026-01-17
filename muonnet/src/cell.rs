//! Cell Protocol
//!
//! Fixed-size cells for traffic analysis resistance.
//!
//! # Cell Format
//!
//! ```text
//! +----------------+--------+---------+------------------+
//! | Circuit ID (4) | Cmd(1) | Len(2)  | Payload (505)    |
//! +----------------+--------+---------+------------------+
//! |<-------------- 512 bytes total ----------------->|
//! ```
//!
//! # Cell Types
//!
//! - **Control Cells**: Circuit management (CREATE, CREATED, DESTROY)
//! - **Relay Cells**: Data and stream management (encapsulated in onion layers)
//!
//! # Relay Cell Payload
//!
//! ```text
//! +--------+----------+--------+------------------+
//! | Cmd(1) | StreamID(2) | Len(2) | Data (500)    |
//! +--------+----------+--------+------------------+
//! ```

use crate::{MuonResult, MuonError, CELL_SIZE, CELL_PAYLOAD_SIZE};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Cell command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CellType {
    /// Padding cell (ignored)
    Padding = 0,
    /// Create a new circuit
    Create = 1,
    /// Circuit created response
    Created = 2,
    /// Relay cell (encrypted payload)
    Relay = 3,
    /// Destroy circuit
    Destroy = 4,
    /// Create circuit (fast handshake)
    CreateFast = 5,
    /// Fast handshake response
    CreatedFast = 6,
    /// Version negotiation
    Versions = 7,
    /// Network status
    NetInfo = 8,
    /// Relay cell (early, for hidden services)
    RelayEarly = 9,
    /// Authentication challenge
    AuthChallenge = 130,
    /// Authentication response
    Authenticate = 131,
    /// Certificate
    Certs = 129,
}

impl TryFrom<u8> for CellType {
    type Error = MuonError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CellType::Padding),
            1 => Ok(CellType::Create),
            2 => Ok(CellType::Created),
            3 => Ok(CellType::Relay),
            4 => Ok(CellType::Destroy),
            5 => Ok(CellType::CreateFast),
            6 => Ok(CellType::CreatedFast),
            7 => Ok(CellType::Versions),
            8 => Ok(CellType::NetInfo),
            9 => Ok(CellType::RelayEarly),
            129 => Ok(CellType::Certs),
            130 => Ok(CellType::AuthChallenge),
            131 => Ok(CellType::Authenticate),
            _ => Err(MuonError::UnknownCellType(value)),
        }
    }
}

/// Relay cell command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCommand {
    /// Begin a new stream
    Begin = 1,
    /// Data on stream
    Data = 2,
    /// End stream
    End = 3,
    /// Stream connected
    Connected = 4,
    /// Send message (for hidden services)
    SendMe = 5,
    /// Extend circuit to another relay
    Extend = 6,
    /// Circuit extended response
    Extended = 7,
    /// Truncate circuit
    Truncate = 8,
    /// Circuit truncated
    Truncated = 9,
    /// Drop cell (ignored)
    Drop = 10,
    /// Resolve hostname
    Resolve = 11,
    /// Hostname resolved
    Resolved = 12,
    /// Begin directory stream
    BeginDir = 13,
    /// Extend circuit (v2)
    Extend2 = 14,
    /// Extended (v2)
    Extended2 = 15,
    /// Establish introduction point
    EstablishIntro = 32,
    /// Establish rendezvous point
    EstablishRendezvous = 33,
    /// Introduce (hidden service)
    Introduce1 = 34,
    /// Introduce response
    Introduce2 = 35,
    /// Rendezvous join
    Rendezvous1 = 36,
    /// Rendezvous joined
    Rendezvous2 = 37,
    /// Introduction established
    IntroEstablished = 38,
    /// Rendezvous established
    RendezvousEstablished = 39,
    /// Introduce acknowledgement
    IntroduceAck = 40,
}

impl TryFrom<u8> for RelayCommand {
    type Error = MuonError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(RelayCommand::Begin),
            2 => Ok(RelayCommand::Data),
            3 => Ok(RelayCommand::End),
            4 => Ok(RelayCommand::Connected),
            5 => Ok(RelayCommand::SendMe),
            6 => Ok(RelayCommand::Extend),
            7 => Ok(RelayCommand::Extended),
            8 => Ok(RelayCommand::Truncate),
            9 => Ok(RelayCommand::Truncated),
            10 => Ok(RelayCommand::Drop),
            11 => Ok(RelayCommand::Resolve),
            12 => Ok(RelayCommand::Resolved),
            13 => Ok(RelayCommand::BeginDir),
            14 => Ok(RelayCommand::Extend2),
            15 => Ok(RelayCommand::Extended2),
            32 => Ok(RelayCommand::EstablishIntro),
            33 => Ok(RelayCommand::EstablishRendezvous),
            34 => Ok(RelayCommand::Introduce1),
            35 => Ok(RelayCommand::Introduce2),
            36 => Ok(RelayCommand::Rendezvous1),
            37 => Ok(RelayCommand::Rendezvous2),
            38 => Ok(RelayCommand::IntroEstablished),
            39 => Ok(RelayCommand::RendezvousEstablished),
            40 => Ok(RelayCommand::IntroduceAck),
            _ => Err(MuonError::InvalidProtocolMessage(
                format!("Unknown relay command: {}", value)
            )),
        }
    }
}

/// A MuonNet cell
#[derive(Debug, Clone)]
pub struct Cell {
    /// Circuit ID (0 for link-level cells)
    pub circuit_id: u32,
    /// Cell type
    pub cell_type: CellType,
    /// Payload data
    pub payload: Bytes,
}

impl Cell {
    /// Create a new cell
    pub fn new(circuit_id: u32, cell_type: CellType, payload: impl Into<Bytes>) -> MuonResult<Self> {
        let payload = payload.into();
        if payload.len() > CELL_PAYLOAD_SIZE {
            return Err(MuonError::CellTooLarge(payload.len(), CELL_PAYLOAD_SIZE));
        }
        Ok(Self {
            circuit_id,
            cell_type,
            payload,
        })
    }

    /// Create padding cell
    pub fn padding(circuit_id: u32) -> Self {
        Self {
            circuit_id,
            cell_type: CellType::Padding,
            payload: Bytes::new(),
        }
    }

    /// Create destroy cell
    pub fn destroy(circuit_id: u32, reason: DestroyReason) -> Self {
        Self {
            circuit_id,
            cell_type: CellType::Destroy,
            payload: Bytes::from(vec![reason as u8]),
        }
    }

    /// Check if this is a control cell (not encrypted)
    pub fn is_control(&self) -> bool {
        matches!(self.cell_type,
            CellType::Padding |
            CellType::Create |
            CellType::Created |
            CellType::CreateFast |
            CellType::CreatedFast |
            CellType::Destroy |
            CellType::Versions |
            CellType::NetInfo |
            CellType::Certs |
            CellType::AuthChallenge |
            CellType::Authenticate
        )
    }

    /// Check if this is a relay cell
    pub fn is_relay(&self) -> bool {
        matches!(self.cell_type, CellType::Relay | CellType::RelayEarly)
    }

    /// Encode cell to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(CELL_SIZE);

        // Header
        buf.put_u32(self.circuit_id);
        buf.put_u8(self.cell_type as u8);

        // Payload with padding
        buf.put_slice(&self.payload);

        // Pad to CELL_SIZE
        let padding_len = CELL_SIZE - buf.len();
        buf.put_bytes(0, padding_len);

        buf.freeze()
    }

    /// Decode cell from bytes
    pub fn decode(data: &[u8]) -> MuonResult<Self> {
        if data.len() < CELL_SIZE {
            return Err(MuonError::InvalidCell(
                format!("Cell too small: {} bytes", data.len())
            ));
        }

        let mut buf = &data[..CELL_SIZE];

        let circuit_id = buf.get_u32();
        let cell_type = CellType::try_from(buf.get_u8())?;

        // Remaining is payload (padded)
        let payload = Bytes::copy_from_slice(buf);

        Ok(Self {
            circuit_id,
            cell_type,
            payload,
        })
    }

    /// Get payload length (excluding padding)
    /// For relay cells, this reads the length from the relay header
    pub fn payload_len(&self) -> usize {
        if self.is_relay() && self.payload.len() >= 5 {
            // Relay header: cmd(1) + stream_id(2) + len(2)
            let len = u16::from_be_bytes([self.payload[3], self.payload[4]]) as usize;
            len.min(self.payload.len() - 5)
        } else {
            self.payload.len()
        }
    }
}

/// Relay cell (decrypted payload of a Relay cell)
#[derive(Debug, Clone)]
pub struct RelayCell {
    /// Stream ID (0 for circuit-level commands)
    pub stream_id: u16,
    /// Relay command
    pub command: RelayCommand,
    /// Relay data
    pub data: Bytes,
}

impl RelayCell {
    /// Create a new relay cell
    pub fn new(stream_id: u16, command: RelayCommand, data: impl Into<Bytes>) -> Self {
        Self {
            stream_id,
            command,
            data: data.into(),
        }
    }

    /// Create BEGIN relay cell
    pub fn begin(stream_id: u16, address: &str) -> Self {
        // Format: address:port\0flags
        let data = format!("{}\0", address);
        Self::new(stream_id, RelayCommand::Begin, data.into_bytes())
    }

    /// Create DATA relay cell
    pub fn data(stream_id: u16, data: impl Into<Bytes>) -> Self {
        Self::new(stream_id, RelayCommand::Data, data)
    }

    /// Create END relay cell
    pub fn end(stream_id: u16, reason: EndReason) -> Self {
        Self::new(stream_id, RelayCommand::End, vec![reason as u8])
    }

    /// Create CONNECTED relay cell
    pub fn connected(stream_id: u16) -> Self {
        Self::new(stream_id, RelayCommand::Connected, Bytes::new())
    }

    /// Create EXTEND relay cell
    pub fn extend(link_specifiers: &[u8], handshake_data: &[u8]) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(link_specifiers);
        data.extend_from_slice(handshake_data);
        Self::new(0, RelayCommand::Extend2, data)
    }

    /// Encode relay cell to payload bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        buf.put_u8(self.command as u8);
        buf.put_u16(self.stream_id);
        buf.put_u16(self.data.len() as u16);
        buf.put_slice(&self.data);

        // Pad to max relay payload size
        let max_relay_payload = CELL_PAYLOAD_SIZE - 5; // 5 byte relay header
        if buf.len() < max_relay_payload {
            buf.put_bytes(0, max_relay_payload - buf.len());
        }

        buf.freeze()
    }

    /// Decode relay cell from payload bytes
    pub fn decode(data: &[u8]) -> MuonResult<Self> {
        if data.len() < 5 {
            return Err(MuonError::InvalidCell("Relay cell too small".into()));
        }

        let mut buf = data;
        let command = RelayCommand::try_from(buf.get_u8())?;
        let stream_id = buf.get_u16();
        let len = buf.get_u16() as usize;

        if buf.len() < len {
            return Err(MuonError::InvalidCell(
                format!("Relay data truncated: expected {}, got {}", len, buf.len())
            ));
        }

        let data = Bytes::copy_from_slice(&buf[..len]);

        Ok(Self {
            stream_id,
            command,
            data,
        })
    }
}

/// Reason for destroying a circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestroyReason {
    None = 0,
    Protocol = 1,
    Internal = 2,
    Requested = 3,
    Hibernating = 4,
    ResourceLimit = 5,
    ConnectFailed = 6,
    OrIdentity = 7,
    OrConnClosed = 8,
    Finished = 9,
    Timeout = 10,
    Destroyed = 11,
    NoSuchService = 12,
}

/// Reason for ending a stream
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EndReason {
    Misc = 1,
    ResolveFailed = 2,
    ConnectRefused = 3,
    ExitPolicy = 4,
    Destroy = 5,
    Done = 6,
    Timeout = 7,
    NoRoute = 8,
    Hibernating = 9,
    Internal = 10,
    ResourceLimit = 11,
    ConnReset = 12,
    TorProtocol = 13,
    NotDirectory = 14,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_creation() {
        let cell = Cell::new(42, CellType::Relay, vec![1, 2, 3]).unwrap();
        assert_eq!(cell.circuit_id, 42);
        assert!(cell.is_relay());
    }

    #[test]
    fn test_cell_encode_decode() {
        let cell = Cell::new(12345, CellType::Create, vec![0xab; 100]).unwrap();
        let encoded = cell.encode();

        assert_eq!(encoded.len(), CELL_SIZE);

        let decoded = Cell::decode(&encoded).unwrap();
        assert_eq!(decoded.circuit_id, cell.circuit_id);
        assert_eq!(decoded.cell_type, cell.cell_type);
    }

    #[test]
    fn test_padding_cell() {
        let cell = Cell::padding(0);
        assert!(!cell.is_relay());
        assert!(cell.is_control());
    }

    #[test]
    fn test_destroy_cell() {
        let cell = Cell::destroy(100, DestroyReason::Finished);
        assert_eq!(cell.cell_type, CellType::Destroy);
        assert_eq!(cell.payload[0], DestroyReason::Finished as u8);
    }

    #[test]
    fn test_cell_too_large() {
        let result = Cell::new(1, CellType::Relay, vec![0; CELL_PAYLOAD_SIZE + 1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_relay_cell_creation() {
        let relay = RelayCell::data(5, vec![1, 2, 3, 4, 5]);
        assert_eq!(relay.stream_id, 5);
        assert_eq!(relay.command, RelayCommand::Data);
    }

    #[test]
    fn test_relay_cell_encode_decode() {
        let relay = RelayCell::begin(10, "example.com:80");
        let encoded = relay.encode();

        let decoded = RelayCell::decode(&encoded).unwrap();
        assert_eq!(decoded.stream_id, relay.stream_id);
        assert_eq!(decoded.command, relay.command);
    }

    #[test]
    fn test_relay_cell_data() {
        let data = b"Hello, MuonNet!";
        let relay = RelayCell::data(1, data.to_vec());
        let encoded = relay.encode();
        let decoded = RelayCell::decode(&encoded).unwrap();

        assert_eq!(decoded.data.as_ref(), data);
    }

    #[test]
    fn test_cell_type_conversion() {
        assert_eq!(CellType::try_from(3).unwrap(), CellType::Relay);
        assert!(CellType::try_from(255).is_err());
    }

    #[test]
    fn test_relay_command_conversion() {
        assert_eq!(RelayCommand::try_from(1).unwrap(), RelayCommand::Begin);
        assert_eq!(RelayCommand::try_from(2).unwrap(), RelayCommand::Data);
    }
}
