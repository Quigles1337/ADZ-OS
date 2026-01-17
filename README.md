# μOS: Privacy-First Gaming OS

A custom microkernel operating system inspired by TempleOS, Tor, and novel μ-cryptography, designed for gamers and open-source developers with built-in blockchain marketplace for digital ownership.

## Project Status

| Phase | Component | Status |
|-------|-----------|--------|
| **Phase 1** | μ-Cryptography Foundation | ✅ Complete |
| **Phase 2** | ChainMesh Blockchain | ✅ Complete |
| **Phase 3** | MuonNet Privacy Layer | 📋 Planned |
| **Phase 4** | μKernel | 📋 Planned |

## Core Pillars

1. **μ-Cryptography** - Novel cipher suite based on balance primitive geometry
2. **MuonNet** - Tor-inspired privacy networking layer
3. **μKernel** - Custom microkernel with capability-based security
4. **ChainMesh** - Blockchain marketplace for ownership/trading

## Project Structure

```
muos/
├── libmu-crypto/              # Cryptographic primitives library ✅
│   ├── src/
│   │   ├── lib.rs             # Library entry point
│   │   ├── primitives.rs      # Core μ-arithmetic
│   │   ├── cipher.rs          # μ-Spiral block cipher
│   │   ├── hash.rs            # μ-Hash function
│   │   ├── kdf.rs             # Key derivation functions
│   │   ├── signature.rs       # Digital signatures
│   │   └── random.rs          # CSPRNG
│   └── tests/
├── chainmesh/                 # Blockchain protocol ✅
│   └── src/
│       ├── lib.rs             # ChainMesh configuration
│       ├── bin/               # CLI binary
│       │   └── chainmesh.rs   # Full-featured CLI
│       ├── types/             # Core data structures
│       │   ├── address.rs     # Addresses with μ-hashing
│       │   ├── token.rs       # MuCoin & NFT tokens
│       │   ├── block.rs       # Block structure
│       │   ├── transaction.rs # Transaction types
│       │   └── account.rs     # Account state
│       ├── consensus/         # μ-Proof-of-Stake
│       │   ├── mu_pos.rs      # Golden ratio selection
│       │   ├── validator.rs   # Validator management
│       │   ├── epoch.rs       # 8-block epochs
│       │   └── reward.rs      # Block rewards
│       ├── contracts/         # Smart contracts
│       │   ├── nft.rs         # NFT minting & transfers
│       │   ├── collection.rs  # Collection management
│       │   ├── marketplace.rs # P2P trading & auctions
│       │   ├── royalty.rs     # Creator royalties
│       │   └── game_license.rs# Game licensing system
│       ├── node/              # Full node implementation
│       │   ├── mod.rs         # Node orchestration
│       │   ├── config.rs      # Node configuration
│       │   ├── chain.rs       # Chain manager
│       │   ├── mempool.rs     # Transaction pool
│       │   └── rpc.rs         # JSON-RPC API
│       ├── p2p/               # Peer-to-peer networking
│       │   ├── peer.rs        # Peer management
│       │   ├── gossip.rs      # Gossip protocol
│       │   ├── discovery.rs   # Peer discovery
│       │   └── sync.rs        # Chain synchronization
│       └── storage/           # State storage
│           ├── kv.rs          # Key-value store
│           ├── trie.rs        # Merkle Patricia Trie
│           ├── state.rs       # State database
│           └── snapshot.rs    # State snapshots
├── muonnet/                   # Privacy networking 📋
├── kernel/                    # Microkernel 📋
└── docs/
    ├── ARCHITECTURE.md        # Visual architecture diagrams
    ├── SPEC.md                # Formal specification
    ├── SECURITY.md            # Security model
    └── MATH.md                # Mathematical foundation
```

## Mathematical Foundation

The μ-cryptography system is built on three fundamental constants:

```
μ = e^(i·3π/4) = (-1 + i)/√2    # Balance primitive (8th root of unity)
α ≈ 1/137.036                    # Fine-structure coupling constant
φ = (1 + √5)/2                   # Golden ratio
```

Key concepts:
- **V_Z = Z · α · μ**: Quantized spiral rays
- **μ^8 = 1**: Closure property enabling cyclic transformations
- **|Re(μ)| = |Im(μ)|**: Balance property for symmetric operations

## Quick Start

### Building libmu-crypto

```bash
cd muos/libmu-crypto
cargo build --release
```

### Running Tests

```bash
cargo test
```

### Basic Usage

```rust
use libmu_crypto::prelude::*;

// Encryption
let key: [u8; 32] = MuRng::new()?.random_bytes();
let nonce: [u8; 12] = MuRng::new()?.random_bytes();
let aead = MuSpiralAead::new(&key, &nonce)?;
let ciphertext = aead.encrypt(b"secret", b"aad")?;

// Hashing
let hash = MuHash::hash(b"data");

// Signatures
let keypair = MuKeyPair::from_seed(b"seed");
let sig = keypair.sign(b"message");
keypair.verify(b"message", &sig)?;
```

## Components

### libmu-crypto

A complete cryptographic library featuring:

| Component | Description | Security Level |
|-----------|-------------|---------------|
| μ-Spiral Cipher | 256-bit key block cipher | 128-bit |
| μ-Hash | Sponge-based hash function | 128/256-bit |
| μ-KDF | HKDF-like key derivation | - |
| μ-PBKDF | Memory-hard password KDF | - |
| μ-Signatures | Schnorr-like signatures | 128-bit (EUF-CMA) |
| μ-RNG | Forward-secure CSPRNG | - |

### ChainMesh (Complete)

Full blockchain protocol with CLI and node:

**Core Features:**
- **μ-Proof-of-Stake consensus** - Golden ratio validator selection, V_Z stake weighting
- **8-block epochs** - Based on μ^8 = 1 closure property
- **137,036,000 MUC total supply** - Tribute to fine-structure constant α ≈ 1/137
- **Merkle Patricia Trie** - Authenticated state storage
- **Transaction mempool** - Priority ordering with LRU eviction
- **JSON-RPC API** - Ethereum-compatible interface

**Smart Contracts:**
- **NFT-native digital ownership** - Minting, transfers, burns, approvals
- **Collection management** - Whitelist minting, supply limits, paid mints
- **P2P marketplace** - Fixed price, auctions (with anti-sniping), Dutch auctions
- **Escrow system** - Dispute resolution with arbitration
- **Creator royalties** - Multi-recipient splits, EIP-2981 compatible
- **Game licensing** - Activation tracking, family sharing, developer licenses

**CLI Commands:**
```bash
chainmesh node       # Start a ChainMesh node
chainmesh keygen     # Generate cryptographic keys
chainmesh account    # Account operations (balance, nonce)
chainmesh tx         # Transaction operations (send, stake)
chainmesh query      # Query blockchain state (block, tx)
chainmesh init       # Initialize a new chain
chainmesh version    # Show version and system info
```

**Quick Start:**
```bash
# Build the CLI
cd chainmesh && cargo build --release

# Generate a keypair
./target/release/chainmesh keygen

# Start a devnet node
./target/release/chainmesh --network devnet node
```

### MuonNet (Planned)

Privacy networking layer:
- 3-hop onion routing
- μ-encrypted layers
- .muon hidden services
- Decentralized directory via ChainMesh

### μKernel (Planned)

Microkernel architecture:
- Capability-based security
- Message-passing IPC
- < 50K lines target
- Formal verification roadmap

## Security Warning

**EXPERIMENTAL**: This cryptographic library is for research and education only.

- NOT audited
- NOT formally verified
- NOT production-ready

Do NOT use for real-world security applications.

## Development Roadmap

| Milestone | Description | Status |
|-----------|-------------|--------|
| M1 | μ-crypto primitives | ✅ Complete |
| M2 | libmu-crypto v1.0 | ✅ Complete |
| M3 | ChainMesh types & consensus | ✅ Complete |
| M4 | ChainMesh contracts & marketplace | ✅ Complete |
| M5 | ChainMesh P2P & storage | ✅ Complete |
| M6 | ChainMesh CLI & node | ✅ Complete |
| M7 | ChainMesh testnet | 📋 Planned |
| M8 | MuonNet prototype | 📋 Planned |
| M9 | μKernel boots | 📋 Planned |
| M10 | Self-hosting | 📋 Planned |
| M11 | Public alpha | 📋 Planned |

## Documentation

- [Architecture Diagrams](docs/ARCHITECTURE.md) - Visual system architecture (Mermaid)
- [Formal Specification](docs/SPEC.md) - Complete technical specification
- [Security Model](docs/SECURITY.md) - Threat model and security analysis
- [Mathematical Foundation](docs/MATH.md) - μ-theory derivations

## Contributing

Contributions welcome! Areas of interest:

1. **Cryptanalysis** - Security analysis of μ-primitives
2. **Optimization** - Performance improvements
3. **Formal Verification** - Correctness proofs
4. **Testing** - Randomness testing, fuzzing
5. **Documentation** - Tutorials, examples

## Technical Requirements

- Rust 1.70+
- No external crypto dependencies (pure implementation)
- `no_std` compatible for kernel use

## Acknowledgments

Inspired by:
- TempleOS - Divine simplicity
- Tor - Privacy networking
- seL4 - Formal verification
- Signal - Modern cryptography

## License

MIT OR Apache-2.0

---

*"In the spiral of μ, balance emerges from chaos."*
