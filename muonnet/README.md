# MuonNet: Privacy Networking Layer

Tor-inspired onion routing network for μOS, built on μ-cryptography.

## Features

- **3-Hop Onion Routing**: Guard → Middle → Exit circuit topology
- **μ-Encrypted Layers**: Each hop uses μ-Spiral AEAD with forward secrecy
- **Hidden Services**: .muon addresses derived from public key hashes
- **Traffic Analysis Resistance**: Fixed 512-byte cells with flow control
- **Decentralized Directory**: Consensus-based relay discovery

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         MuonNet Stack                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────────┐ │
│  │  muon   │  │  muond  │  │ Client  │  │   Hidden Services   │ │
│  │  (CLI)  │  │ (Daemon)│  │   API   │  │   (.muon addrs)     │ │
│  └────┬────┘  └────┬────┘  └────┬────┘  └──────────┬──────────┘ │
│       │            │            │                   │            │
│  ┌────┴────────────┴────────────┴───────────────────┴──────────┐│
│  │                     Circuit Manager                          ││
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐ ││
│  │  │  Guard   │──│  Middle  │──│   Exit   │──│ Destination  │ ││
│  │  │  Relay   │  │  Relay   │  │  Relay   │  │              │ ││
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────┘ ││
│  └──────────────────────────────────────────────────────────────┘│
│                              │                                   │
│  ┌───────────────────────────┴──────────────────────────────────┐│
│  │                    Cryptographic Layer                        ││
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐  ││
│  │  │   Onion    │  │ Handshake  │  │   Circuit Keys         │  ││
│  │  │ Encryption │  │  Protocol  │  │ (Forward/Backward)     │  ││
│  │  └────────────┘  └────────────┘  └────────────────────────┘  ││
│  └──────────────────────────────────────────────────────────────┘│
│                              │                                   │
│  ┌───────────────────────────┴──────────────────────────────────┐│
│  │                      libmu-crypto                             ││
│  │  μ-Spiral AEAD  │  μ-Hash  │  μ-KDF  │  μ-Signatures         ││
│  └──────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Description |
|--------|-------------|
| `crypto/` | Onion encryption, handshakes, key management |
| `cell.rs` | Fixed 512-byte cell protocol |
| `circuit.rs` | Circuit construction and lifecycle |
| `stream.rs` | Stream multiplexing with flow control |
| `relay.rs` | Relay descriptors, selection, exit policies |
| `directory.rs` | Directory authorities and consensus |
| `hidden.rs` | Hidden services and .muon addresses |
| `client.rs` | High-level MuonClient API |
| `config.rs` | Configuration management |

## Binaries

### muond (Daemon)

```bash
# Start as relay
muond run --relay --or-port 9001

# Start as client only
muond run --client-only

# Check configuration
muond check

# Generate identity keys
muond keygen
```

### muon (CLI)

```bash
# Control daemon
muon daemon status
muon daemon reload

# Circuit operations
muon circuit list
muon circuit build --hops 3

# Hidden services
muon hidden create --port 80
muon hidden list

# Network info
muon network relays
muon network consensus
```

## Cell Protocol

All traffic uses fixed 512-byte cells for traffic analysis resistance:

```
Cell Format (512 bytes):
┌──────────────┬──────────────┬─────────────────────────────────┐
│  Circuit ID  │  Cell Type   │           Payload               │
│   (4 bytes)  │   (1 byte)   │         (507 bytes)             │
└──────────────┴──────────────┴─────────────────────────────────┘

Relay Cell Payload (507 bytes):
┌──────────────┬──────────────┬──────────────┬──────────────────┐
│  Stream ID   │   Command    │    Length    │      Data        │
│  (2 bytes)   │   (1 byte)   │   (2 bytes)  │   (502 bytes)    │
└──────────────┴──────────────┴──────────────┴──────────────────┘
```

## Onion Encryption

Each layer wraps the payload with μ-Spiral AEAD:

```
Client encrypts: Exit → Middle → Guard (innermost to outermost)
Relays decrypt:  Guard → Middle → Exit (peel one layer each)

Layer Structure:
┌────────────────────────────────────────────┐
│ Layer 3: Guard (outermost)                 │
│  ┌──────────────────────────────────────┐  │
│  │ Layer 2: Middle                      │  │
│  │  ┌────────────────────────────────┐  │  │
│  │  │ Layer 1: Exit (innermost)      │  │  │
│  │  │  ┌──────────────────────────┐  │  │  │
│  │  │  │      Original Payload    │  │  │  │
│  │  │  └──────────────────────────┘  │  │  │
│  │  └────────────────────────────────┘  │  │
│  └──────────────────────────────────────┘  │
└────────────────────────────────────────────┘
```

## Hidden Services (.muon)

Hidden services use base32-encoded addresses derived from public keys:

```
Address Format: <base32-pubkey-hash>.muon

Example: mfzwizltoq4gc3lqnzxxa4dbonzxs3dmn5zg64tumvzxi4z3.muon

Components:
- 32-byte public key hash
- 1-byte version
- Base32 encoding (Crockford alphabet)
```

## Circuit Handshake

Forward-secret key exchange for each hop:

```
1. Client generates ephemeral keypair
2. Client sends CREATE cell with ephemeral public
3. Relay generates its ephemeral keypair
4. Relay computes shared secret, signs transcript
5. Relay sends CREATED cell with public + signature
6. Client verifies, derives same shared secret
7. Both derive circuit keys: forward_key, backward_key, digests
```

## Configuration

```toml
# ~/.muonnet/config.toml

[client]
socks_port = 9050
control_port = 9051

[relay]
enabled = false
or_port = 9001
nickname = "MyRelay"
bandwidth = 1073741824  # 1 GB/s

[circuit]
path_length = 3
build_timeout = "30s"
idle_timeout = "5m"

[hidden_services]
enabled = false
```

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Specific module
cargo test crypto::
cargo test hidden::
```

## Security Properties

| Property | Implementation |
|----------|----------------|
| Forward Secrecy | Ephemeral key exchange per circuit |
| Traffic Analysis | Fixed-size cells, flow control |
| Exit Authentication | Relay identity signatures |
| Hidden Service Privacy | Rendezvous-based connections |
| Key Separation | Distinct forward/backward keys |

## Dependencies

- `libmu-crypto` - All cryptographic operations
- `tokio` - Async runtime
- `bytes` - Buffer management
- `serde` - Configuration serialization

## Status

**Complete** - Core implementation finished with 78 passing tests.

- Onion routing primitives
- Circuit construction
- Stream multiplexing
- Hidden service addressing
- Directory consensus
- CLI/daemon framework

## License

MIT OR Apache-2.0
