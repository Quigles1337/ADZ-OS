# μKernel

Capability-based microkernel for μOS, targeting x86_64 bare metal.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Space                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐│
│  │   VFS    │ │ NetStack │ │ Display  │ │   Applications   ││
│  │  Server  │ │  Server  │ │  Server  │ │                  ││
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────────┬─────────┘│
│       │            │            │                 │          │
│  ═════╪════════════╪════════════╪═════════════════╪═════════ │
│       │    IPC     │            │                 │          │
│       ▼            ▼            ▼                 ▼          │
├─────────────────────────────────────────────────────────────┤
│                      μKernel                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ Capabilities │  │     IPC      │  │ Memory Manager   │   │
│  │    System    │  │   Subsystem  │  │ (Physical/Virt)  │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Scheduler   │  │   Drivers    │  │   μ-Crypto       │   │
│  │              │  │ (Timer, IRQ) │  │  Integration     │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Features

### Capability-Based Security
All kernel resources are accessed through capabilities - unforgeable tokens that grant specific rights. Capabilities can be delegated but never escalated.

**Capability Types:**
- Memory (read/write/execute regions)
- IPC Endpoints (send/receive rights)
- Process/Thread control
- IRQ handling
- I/O port access

### Message-Passing IPC
Inspired by seL4, all inter-process communication uses synchronous message passing:
- Send/Receive with timeout
- Call/Reply for RPC-style communication
- Capability transfer in messages
- Notifications for lightweight async signaling

### Memory Management
- **Physical:** Bitmap-based frame allocator
- **Virtual:** 4-level page tables (PML4)
- **Per-process address spaces**
- **Kernel heap:** Bump allocator

### Scheduler
- 256 priority levels (0 = highest)
- Preemptive round-robin within priorities
- 100Hz timer tick for time slicing

## Building

Requires Rust nightly:

```bash
# Install nightly toolchain
rustup install nightly
rustup component add rust-src --toolchain nightly

# Build
cargo +nightly build
```

## Project Structure

```
kernel/
├── Cargo.toml
├── .cargo/config.toml     # Target: x86_64-unknown-none
├── linker.ld              # Kernel linker script
└── src/
    ├── lib.rs             # Entry point (_start)
    ├── boot/              # Boot info structures
    ├── mm/                # Memory management
    │   ├── frame.rs       # Physical frame allocator
    │   ├── heap.rs        # Kernel heap
    │   ├── page.rs        # Page table management
    │   └── virt.rs        # Address space
    ├── caps/              # Capability system
    ├── ipc/               # IPC endpoints & messages
    ├── sys/               # System services
    │   ├── scheduler.rs   # Thread scheduler
    │   ├── process.rs     # Process management
    │   ├── thread.rs      # Thread & context switch
    │   └── syscall.rs     # Syscall interface
    └── drivers/
        ├── serial.rs      # UART 16550
        ├── interrupts.rs  # IDT & PIC
        └── timer.rs       # PIT timer
```

## Syscall Interface

| Range | Category | Syscalls |
|-------|----------|----------|
| 1-99 | IPC | Send, Recv, Call, Reply, Wait, Signal |
| 100-199 | Capabilities | Create, Delete, Copy, Mint, Revoke |
| 200-299 | Memory | Map, Unmap, Protect, Alloc, Free |
| 300-399 | Threads | Create, Suspend, Resume, Yield, Exit |
| 400-499 | Process | Create, Kill, Wait |
| 500-599 | Time | Get, Sleep |
| 900-999 | Debug | Print, KernelInfo |

## Next Steps

- [ ] UEFI bootloader
- [ ] ACPI parsing
- [ ] SMP support
- [ ] User-space init process
- [ ] VFS server
- [ ] μ-crypto kernel integration

## License

MIT OR Apache-2.0
