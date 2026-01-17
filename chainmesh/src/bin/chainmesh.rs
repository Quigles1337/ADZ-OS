//! ChainMesh CLI
//!
//! Command-line interface for the ChainMesh blockchain node.
//!
//! # Usage
//!
//! ```bash
//! # Start a node
//! chainmesh node --network testnet
//!
//! # Generate a new keypair
//! chainmesh keygen
//!
//! # Check account balance
//! chainmesh account balance <address>
//!
//! # Send a transaction
//! chainmesh tx send --to <address> --value 100
//! ```

use chainmesh::node::{Node, NodeConfig, NodeStatus};
use chainmesh::types::{Address, MuCoin, Transaction, TransactionType};
use chainmesh::ChainConfig;

use clap::{Parser, Subcommand, Args};
use std::path::PathBuf;
use tracing::{info, error, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// ChainMesh - Blockchain for μOS
#[derive(Parser)]
#[command(name = "chainmesh")]
#[command(author = "μOS Project")]
#[command(version)]
#[command(about = "ChainMesh blockchain node and CLI", long_about = None)]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Data directory
    #[arg(short, long, global = true, env = "CHAINMESH_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Network (mainnet, testnet, devnet)
    #[arg(short, long, global = true, default_value = "testnet")]
    network: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a ChainMesh node
    Node(NodeArgs),

    /// Generate cryptographic keys
    Keygen(KeygenArgs),

    /// Account operations
    Account(AccountArgs),

    /// Transaction operations
    Tx(TxArgs),

    /// Query blockchain state
    Query(QueryArgs),

    /// Initialize a new chain
    Init(InitArgs),

    /// Export/Import data
    Export(ExportArgs),

    /// Show version and system info
    Version,
}

#[derive(Args)]
struct NodeArgs {
    /// P2P listen address
    #[arg(long, default_value = "0.0.0.0:30303")]
    p2p_addr: String,

    /// RPC listen address
    #[arg(long, default_value = "127.0.0.1:8545")]
    rpc_addr: String,

    /// Disable RPC server
    #[arg(long)]
    no_rpc: bool,

    /// Bootstrap nodes (comma-separated)
    #[arg(long)]
    bootstrap: Option<String>,

    /// Maximum peers
    #[arg(long, default_value = "50")]
    max_peers: u32,

    /// Validator private key (hex)
    #[arg(long, env = "CHAINMESH_VALIDATOR_KEY")]
    validator_key: Option<String>,

    /// Coinbase address for block rewards
    #[arg(long)]
    coinbase: Option<String>,

    /// Enable state pruning
    #[arg(long)]
    pruning: bool,

    /// Blocks to keep when pruning
    #[arg(long, default_value = "128")]
    pruning_retention: u64,

    /// Cache size in MB
    #[arg(long, default_value = "512")]
    cache_size: usize,

    /// Mempool size (max transactions)
    #[arg(long, default_value = "10000")]
    mempool_size: usize,

    /// Run in background
    #[arg(long)]
    daemon: bool,
}

#[derive(Args)]
struct KeygenArgs {
    /// Output file for private key
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Generate validator key
    #[arg(long)]
    validator: bool,

    /// Show mnemonic (BIP39)
    #[arg(long)]
    mnemonic: bool,
}

#[derive(Args)]
struct AccountArgs {
    #[command(subcommand)]
    command: AccountCommand,
}

#[derive(Subcommand)]
enum AccountCommand {
    /// Show account balance
    Balance {
        /// Account address
        address: String,
    },
    /// Show account nonce
    Nonce {
        /// Account address
        address: String,
    },
    /// Create new account
    New {
        /// Output file for private key
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Import account from private key
    Import {
        /// Private key (hex)
        key: String,
    },
    /// List known accounts
    List,
}

#[derive(Args)]
struct TxArgs {
    #[command(subcommand)]
    command: TxCommand,
}

#[derive(Subcommand)]
enum TxCommand {
    /// Send a transfer transaction
    Send {
        /// Recipient address
        #[arg(long)]
        to: String,
        /// Value to send (in MUC)
        #[arg(long)]
        value: String,
        /// Gas price
        #[arg(long, default_value = "1")]
        gas_price: u64,
        /// Gas limit
        #[arg(long, default_value = "21000")]
        gas_limit: u64,
        /// Private key (hex) or keyfile
        #[arg(long)]
        key: Option<String>,
        /// Nonce (auto if not specified)
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Show transaction details
    Get {
        /// Transaction hash
        hash: String,
    },
    /// Show pending transactions
    Pending {
        /// Account address (optional)
        address: Option<String>,
    },
}

#[derive(Args)]
struct QueryArgs {
    #[command(subcommand)]
    command: QueryCommand,
}

#[derive(Subcommand)]
enum QueryCommand {
    /// Get block by height or hash
    Block {
        /// Block height or hash
        id: String,
    },
    /// Get current chain state
    State,
    /// Get node info
    Node,
    /// Get peers
    Peers,
    /// Get mempool stats
    Mempool,
}

#[derive(Args)]
struct InitArgs {
    /// Force reinitialize (WARNING: deletes existing data)
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct ExportArgs {
    #[command(subcommand)]
    command: ExportCommand,
}

#[derive(Subcommand)]
enum ExportCommand {
    /// Export blocks to file
    Blocks {
        /// Output file
        output: PathBuf,
        /// Start block
        #[arg(long, default_value = "0")]
        from: u64,
        /// End block (latest if not specified)
        #[arg(long)]
        to: Option<u64>,
    },
    /// Export state snapshot
    State {
        /// Output file
        output: PathBuf,
        /// Block height (latest if not specified)
        #[arg(long)]
        at: Option<u64>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(log_level)))
        .init();

    // Determine data directory
    let data_dir = cli.data_dir
        .or_else(|| dirs::data_dir().map(|d| d.join("chainmesh")))
        .unwrap_or_else(|| PathBuf::from(".chainmesh"));

    // Parse network
    let network: chainmesh::node::config::Network = cli.network.parse()
        .map_err(|e: String| format!("Invalid network: {}", e))?;

    match cli.command {
        Commands::Node(args) => run_node(args, data_dir, network).await?,
        Commands::Keygen(args) => run_keygen(args)?,
        Commands::Account(args) => run_account(args, &data_dir).await?,
        Commands::Tx(args) => run_tx(args, &data_dir).await?,
        Commands::Query(args) => run_query(args, &data_dir).await?,
        Commands::Init(args) => run_init(args, data_dir, network)?,
        Commands::Export(args) => run_export(args, &data_dir).await?,
        Commands::Version => run_version(),
    }

    Ok(())
}

/// Run the node
async fn run_node(
    args: NodeArgs,
    data_dir: PathBuf,
    network: chainmesh::node::config::Network,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting ChainMesh node...");

    // Build configuration
    let mut config = match network {
        chainmesh::node::config::Network::Mainnet => NodeConfig::mainnet(data_dir),
        chainmesh::node::config::Network::Testnet => NodeConfig::testnet(data_dir),
        chainmesh::node::config::Network::Devnet => NodeConfig::devnet(data_dir),
    };

    config.p2p_addr = args.p2p_addr.parse()?;
    config.rpc_addr = args.rpc_addr.parse()?;
    config.rpc_enabled = !args.no_rpc;
    config.max_peers = args.max_peers;
    config.validator_key = args.validator_key;
    config.pruning_enabled = args.pruning;
    config.pruning_retention = args.pruning_retention;
    config.cache_size_mb = args.cache_size;
    config.mempool_size = args.mempool_size;

    if let Some(coinbase) = args.coinbase {
        config.coinbase = Some(Address::from_str(&coinbase)?);
    }

    if let Some(bootstrap) = args.bootstrap {
        config.bootstrap_nodes = bootstrap.split(',')
            .map(|s| s.trim().to_string())
            .collect();
    }

    // Validate configuration
    config.validate()?;

    // Create and start node
    let mut node = Node::new(config)?;
    node.start().await?;

    info!("Node running. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;

    info!("Shutting down...");
    node.stop().await?;

    info!("Node stopped.");
    Ok(())
}

/// Generate keys
fn run_keygen(args: KeygenArgs) -> Result<(), Box<dyn std::error::Error>> {
    use libmu_crypto::signature::MuKeyPair;
    use rand::RngCore;

    // Generate random seed
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);

    let keypair = MuKeyPair::from_seed(&seed);
    let public_key = keypair.public_key();
    let address = Address::from_public_key(&public_key);

    println!("Generated new keypair:");
    println!("  Address:     {}", address);
    println!("  Public Key:  {}", hex::encode(public_key.to_bytes()));
    println!("  Private Key: {}", hex::encode(keypair.private_key_bytes()));

    if args.validator {
        println!("\nValidator configuration:");
        println!("  --validator-key={}", hex::encode(keypair.private_key_bytes()));
        println!("  --coinbase={}", address);
    }

    if let Some(output) = args.output {
        std::fs::write(&output, hex::encode(keypair.private_key_bytes()))?;
        println!("\nPrivate key saved to: {}", output.display());
    }

    if args.mnemonic {
        println!("\nNote: BIP39 mnemonic generation not yet implemented");
    }

    Ok(())
}

/// Account operations
async fn run_account(args: AccountArgs, data_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        AccountCommand::Balance { address } => {
            let addr = Address::from_str(&address)?;
            println!("Querying balance for {} ...", addr);
            // TODO: Connect to RPC and query
            println!("Note: RPC query not yet implemented. Run a node first.");
        }
        AccountCommand::Nonce { address } => {
            let addr = Address::from_str(&address)?;
            println!("Querying nonce for {} ...", addr);
            println!("Note: RPC query not yet implemented. Run a node first.");
        }
        AccountCommand::New { output } => {
            run_keygen(KeygenArgs {
                output,
                validator: false,
                mnemonic: false,
            })?;
        }
        AccountCommand::Import { key } => {
            use libmu_crypto::signature::MuKeyPair;

            let key_bytes = hex::decode(&key)?;
            if key_bytes.len() != 32 {
                return Err("Private key must be 32 bytes".into());
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);

            let keypair = MuKeyPair::from_seed(&arr);
            let address = Address::from_public_key(&keypair.public_key());

            println!("Imported account: {}", address);
        }
        AccountCommand::List => {
            println!("Note: Account listing not yet implemented.");
        }
    }

    Ok(())
}

/// Transaction operations
async fn run_tx(args: TxArgs, data_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        TxCommand::Send { to, value, gas_price, gas_limit, key, nonce } => {
            let to_addr = Address::from_str(&to)?;
            let value_muc = MuCoin::from_muc_str(&value)?;

            println!("Preparing transaction:");
            println!("  To:        {}", to_addr);
            println!("  Value:     {}", value_muc);
            println!("  Gas Price: {}", gas_price);
            println!("  Gas Limit: {}", gas_limit);

            if key.is_none() {
                return Err("Private key required (--key)".into());
            }

            println!("\nNote: Transaction sending not yet implemented. Run a node with RPC enabled.");
        }
        TxCommand::Get { hash } => {
            println!("Querying transaction {} ...", hash);
            println!("Note: RPC query not yet implemented. Run a node first.");
        }
        TxCommand::Pending { address } => {
            if let Some(addr) = address {
                println!("Querying pending transactions for {} ...", addr);
            } else {
                println!("Querying all pending transactions...");
            }
            println!("Note: RPC query not yet implemented. Run a node first.");
        }
    }

    Ok(())
}

/// Query operations
async fn run_query(args: QueryArgs, data_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        QueryCommand::Block { id } => {
            println!("Querying block {} ...", id);
            println!("Note: RPC query not yet implemented. Run a node first.");
        }
        QueryCommand::State => {
            println!("Querying chain state...");
            println!("Note: RPC query not yet implemented. Run a node first.");
        }
        QueryCommand::Node => {
            println!("Querying node info...");
            println!("Note: RPC query not yet implemented. Run a node first.");
        }
        QueryCommand::Peers => {
            println!("Querying peers...");
            println!("Note: RPC query not yet implemented. Run a node first.");
        }
        QueryCommand::Mempool => {
            println!("Querying mempool stats...");
            println!("Note: RPC query not yet implemented. Run a node first.");
        }
    }

    Ok(())
}

/// Initialize chain
fn run_init(
    args: InitArgs,
    data_dir: PathBuf,
    network: chainmesh::node::config::Network,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Initializing ChainMesh at {}", data_dir.display());

    if data_dir.join("state").exists() {
        if args.force {
            warn!("Removing existing data...");
            std::fs::remove_dir_all(&data_dir)?;
        } else {
            return Err("Data directory already exists. Use --force to reinitialize.".into());
        }
    }

    std::fs::create_dir_all(&data_dir)?;

    let config = match network {
        chainmesh::node::config::Network::Mainnet => NodeConfig::mainnet(data_dir.clone()),
        chainmesh::node::config::Network::Testnet => NodeConfig::testnet(data_dir.clone()),
        chainmesh::node::config::Network::Devnet => NodeConfig::devnet(data_dir.clone()),
    };

    // Save default config
    config.save(&data_dir.join("config.json"))?;

    info!("Created configuration at {}", data_dir.join("config.json").display());
    info!("Initialization complete.");
    info!("Run 'chainmesh node' to start the node.");

    Ok(())
}

/// Export data
async fn run_export(args: ExportArgs, data_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        ExportCommand::Blocks { output, from, to } => {
            println!("Exporting blocks {} to {:?} to {}", from, to, output.display());
            println!("Note: Export not yet implemented.");
        }
        ExportCommand::State { output, at } => {
            println!("Exporting state at block {:?} to {}", at, output.display());
            println!("Note: Export not yet implemented.");
        }
    }

    Ok(())
}

/// Show version
fn run_version() {
    println!("ChainMesh {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  Blockchain for μOS");
    println!();
    println!("  Build info:");
    println!("    Commit:   unknown");
    println!("    Built:    unknown");
    println!();
    println!("  μ-Cryptography:");
    println!("    μ = e^(i·3π/4) = (-1 + i)/√2");
    println!("    α ≈ 1/137.036");
    println!();
    println!("  Network:");
    println!("    Mainnet chain ID: 1");
    println!("    Testnet chain ID: 137");
    println!("    Devnet chain ID:  1337");
    println!();
    println!("  Total supply: 137,036,000 MUC");
    println!("  Block time:   6 seconds");
    println!("  Epoch length: 8 blocks (μ^8 = 1)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
