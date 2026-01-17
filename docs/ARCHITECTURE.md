# μOS Architecture

*Visual documentation of the μOS system architecture using Mark Lombardi-inspired network diagrams*

---

## System Overview

The μOS ecosystem consists of four interconnected pillars, each building upon the cryptographic foundation.

```mermaid
flowchart TB
    subgraph FOUNDATION["🔐 CRYPTOGRAPHIC FOUNDATION"]
        MU["μ = e^(i·3π/4)"]
        ALPHA["α ≈ 1/137"]
        PHI["φ = Golden Ratio"]

        MU --> VZ["V_Z Quantization"]
        ALPHA --> VZ
        PHI --> GOLDEN["Golden Sequences"]
    end

    subgraph CRYPTO["📚 libmu-crypto"]
        direction TB
        CIPHER["μ-Spiral Cipher"]
        HASH["μ-Hash"]
        SIG["μ-Signatures"]
        KDF["μ-KDF"]
        RNG["μ-RNG"]

        VZ --> CIPHER
        VZ --> HASH
        VZ --> SIG
        GOLDEN --> KDF
        HASH --> RNG
    end

    subgraph CHAIN["⛓️ ChainMesh"]
        direction TB
        CONSENSUS["μ-PoS Consensus"]
        TYPES["Core Types"]
        CONTRACTS["Smart Contracts"]

        GOLDEN --> CONSENSUS
        SIG --> CONSENSUS
        HASH --> TYPES
    end

    subgraph NET["🌐 MuonNet"]
        direction TB
        ONION["Onion Routing"]
        HIDDEN["Hidden Services"]
        P2P["P2P Gossip"]
    end

    subgraph KERNEL["⚙️ μKernel"]
        direction TB
        CAPS["Capabilities"]
        IPC["Message IPC"]
        DRIVERS["Drivers"]
    end

    CRYPTO --> CHAIN
    CRYPTO --> NET
    CRYPTO --> KERNEL
    CHAIN --> NET
    NET --> KERNEL

    classDef foundation fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#fff
    classDef crypto fill:#16213e,stroke:#0f3460,stroke-width:2px,color:#fff
    classDef chain fill:#0f3460,stroke:#e94560,stroke-width:2px,color:#fff
    classDef net fill:#533483,stroke:#e94560,stroke-width:2px,color:#fff
    classDef kernel fill:#2c061f,stroke:#e94560,stroke-width:2px,color:#fff

    class MU,ALPHA,PHI,VZ,GOLDEN foundation
    class CIPHER,HASH,SIG,KDF,RNG crypto
    class CONSENSUS,TYPES,CONTRACTS chain
    class ONION,HIDDEN,P2P net
    class CAPS,IPC,DRIVERS kernel
```

---

## μ-Cryptography Internals

The cryptographic primitives form an interconnected web where each component reinforces the others.

```mermaid
flowchart LR
    subgraph PRIMITIVES["Mathematical Primitives"]
        MU["μ = (-1+i)/√2"]
        MU8["μ^8 = 1<br/>Closure"]
        BALANCE["|Re| = |Im|<br/>Balance"]
        SPIRAL["135° Spiral<br/>Geometry"]

        MU --> MU8
        MU --> BALANCE
        MU --> SPIRAL
    end

    subgraph CIPHER_ENGINE["μ-Spiral Cipher Engine"]
        direction TB
        SBOX["S-Box<br/>V_Z Sampling"]
        PERM["Permutation<br/>μ-Rotation"]
        MIX["MixColumns<br/>Balance Diffusion"]
        ROUNDS["8 Rounds<br/>μ^8 Closure"]

        SBOX --> PERM
        PERM --> MIX
        MIX --> ROUNDS
        ROUNDS -.-> SBOX
    end

    subgraph HASH_ENGINE["μ-Hash Sponge"]
        direction TB
        ABSORB["Absorb Phase"]
        SQUEEZE["Squeeze Phase"]
        SPONGE["Sponge State<br/>1600 bits"]

        ABSORB --> SPONGE
        SPONGE --> SQUEEZE
    end

    subgraph SIGNATURE["μ-Signature Scheme"]
        direction TB
        KEYPAIR["Key Generation<br/>Seed → (sk, pk)"]
        COMMIT["Commitment<br/>R = k·G"]
        CHALLENGE["Challenge<br/>e = H(R,pk,m)"]
        RESPONSE["Response<br/>s = k + e·sk"]

        KEYPAIR --> COMMIT
        COMMIT --> CHALLENGE
        CHALLENGE --> RESPONSE
    end

    SPIRAL --> SBOX
    MU8 --> ROUNDS
    BALANCE --> MIX

    MIX --> ABSORB
    ROUNDS --> SPONGE

    SQUEEZE --> CHALLENGE
    SPONGE --> KEYPAIR

    classDef prim fill:#2d132c,stroke:#ee4540,stroke-width:2px,color:#fff
    classDef cipher fill:#801336,stroke:#ee4540,stroke-width:2px,color:#fff
    classDef hash fill:#c72c41,stroke:#fff,stroke-width:2px,color:#fff
    classDef sig fill:#ee4540,stroke:#2d132c,stroke-width:2px,color:#fff

    class MU,MU8,BALANCE,SPIRAL prim
    class SBOX,PERM,MIX,ROUNDS cipher
    class ABSORB,SQUEEZE,SPONGE hash
    class KEYPAIR,COMMIT,CHALLENGE,RESPONSE sig
```

---

## ChainMesh Blockchain Architecture

The blockchain layer weaves together consensus, state management, and smart contracts.

```mermaid
flowchart TB
    subgraph GENESIS["Genesis Configuration"]
        CHAIN_ID["Chain ID: 137"]
        SUPPLY["Supply: 137,036,000 MUC"]
        EPOCH_LEN["Epoch: 8 blocks"]
    end

    subgraph CONSENSUS_LAYER["μ-Proof-of-Stake Consensus"]
        direction LR
        VALIDATORS["Validator Set"]
        GOLDEN_SEL["Golden Ratio<br/>Selection"]
        VRF["VRF-like<br/>Randomness"]
        EPOCHS["8-Block<br/>Epochs"]

        VALIDATORS --> GOLDEN_SEL
        GOLDEN_SEL --> VRF
        VRF --> EPOCHS
    end

    subgraph BLOCK_LAYER["Block Production"]
        direction LR
        PROPOSER["Block<br/>Proposer"]
        ATTESTERS["Attesters"]
        FINALITY["2/3 Quorum<br/>Finality"]

        PROPOSER --> ATTESTERS
        ATTESTERS --> FINALITY
    end

    subgraph STATE_LAYER["State Management"]
        direction TB
        ACCOUNTS["Account<br/>States"]
        BALANCES["Token<br/>Balances"]
        NFTS["NFT<br/>Ownership"]
        STAKES["Validator<br/>Stakes"]

        ACCOUNTS --> BALANCES
        ACCOUNTS --> NFTS
        ACCOUNTS --> STAKES
    end

    subgraph TX_LAYER["Transaction Types"]
        direction TB
        TRANSFER["Transfer"]
        STAKE_TX["Stake/Unstake"]
        CONTRACT["Contract Call"]
        NFT_TX["NFT Operations"]

        TRANSFER --> |"fee"| BALANCES
        STAKE_TX --> STAKES
        CONTRACT --> CONTRACTS
        NFT_TX --> NFTS
    end

    subgraph CONTRACTS["Smart Contracts"]
        direction TB
        NFT_CONTRACT["NFT Contract"]
        MARKET["Marketplace"]
        ROYALTY["Royalty<br/>Distribution"]
        LICENSE["Game<br/>Licensing"]
    end

    GENESIS --> CONSENSUS_LAYER
    CONSENSUS_LAYER --> BLOCK_LAYER
    BLOCK_LAYER --> STATE_LAYER
    TX_LAYER --> STATE_LAYER
    CONTRACTS --> STATE_LAYER

    EPOCHS --> PROPOSER
    FINALITY --> ACCOUNTS

    classDef genesis fill:#0d1b2a,stroke:#1b998b,stroke-width:2px,color:#fff
    classDef consensus fill:#1b4332,stroke:#40916c,stroke-width:2px,color:#fff
    classDef block fill:#2d6a4f,stroke:#52b788,stroke-width:2px,color:#fff
    classDef state fill:#40916c,stroke:#fff,stroke-width:2px,color:#fff
    classDef tx fill:#52b788,stroke:#0d1b2a,stroke-width:2px,color:#000
    classDef contract fill:#95d5b2,stroke:#1b4332,stroke-width:2px,color:#000

    class CHAIN_ID,SUPPLY,EPOCH_LEN genesis
    class VALIDATORS,GOLDEN_SEL,VRF,EPOCHS consensus
    class PROPOSER,ATTESTERS,FINALITY block
    class ACCOUNTS,BALANCES,NFTS,STAKES state
    class TRANSFER,STAKE_TX,CONTRACT,NFT_TX tx
    class NFT_CONTRACT,MARKET,ROYALTY,LICENSE contract
```

---

## Validator Selection Flow

The golden ratio-based validator selection creates a deterministic yet unpredictable sequence.

```mermaid
flowchart LR
    subgraph INPUT["Selection Inputs"]
        EPOCH_SEED["Epoch Seed<br/>H(prev_block)"]
        SLOT_NUM["Slot Number<br/>0-7"]
        VAL_SET["Active<br/>Validators"]
    end

    subgraph GOLDEN_ALGO["Golden Sequence Algorithm"]
        direction TB
        FRAC["Fractional Part<br/>{n · φ}"]
        SCALE["Scale to<br/>Validator Count"]
        INDEX["Validator<br/>Index"]

        FRAC --> SCALE
        SCALE --> INDEX
    end

    subgraph VZ_WEIGHT["V_Z Stake Weighting"]
        direction TB
        STAKE["Raw Stake"]
        QUANTIZE["Z = floor(stake/min)"]
        VZ_CALC["V_Z = Z · α · μ"]
        WEIGHT["|V_Z| Weight"]

        STAKE --> QUANTIZE
        QUANTIZE --> VZ_CALC
        VZ_CALC --> WEIGHT
    end

    subgraph OUTPUT["Block Production"]
        PROPOSER["Selected<br/>Proposer"]
        BACKUP["Backup<br/>Proposers"]
        ATTESTERS["Attester<br/>Committee"]
    end

    EPOCH_SEED --> FRAC
    SLOT_NUM --> FRAC
    VAL_SET --> VZ_WEIGHT

    INDEX --> PROPOSER
    WEIGHT --> INDEX

    PROPOSER --> BACKUP
    VAL_SET --> ATTESTERS

    classDef input fill:#003049,stroke:#fcbf49,stroke-width:2px,color:#fff
    classDef golden fill:#d62828,stroke:#fcbf49,stroke-width:2px,color:#fff
    classDef vz fill:#f77f00,stroke:#003049,stroke-width:2px,color:#000
    classDef output fill:#fcbf49,stroke:#003049,stroke-width:2px,color:#000

    class EPOCH_SEED,SLOT_NUM,VAL_SET input
    class FRAC,SCALE,INDEX golden
    class STAKE,QUANTIZE,VZ_CALC,WEIGHT vz
    class PROPOSER,BACKUP,ATTESTERS output
```

---

## NFT & Marketplace Ecosystem

A comprehensive digital ownership and trading network.

```mermaid
flowchart TB
    subgraph CREATOR_FLOW["Creator Flow"]
        direction LR
        ARTIST["Creator"]
        COLLECTION["Create<br/>Collection"]
        MINT["Mint<br/>NFTs"]
        ROYALTY_CFG["Configure<br/>Royalties"]

        ARTIST --> COLLECTION
        COLLECTION --> MINT
        MINT --> ROYALTY_CFG
    end

    subgraph NFT_STATE["NFT State Machine"]
        direction TB
        MINTED["Minted"]
        LISTED["Listed"]
        AUCTION["In Auction"]
        ESCROWED["Escrowed"]
        SOLD["Sold"]
        BURNED["Burned"]

        MINTED --> LISTED
        MINTED --> AUCTION
        LISTED --> SOLD
        AUCTION --> SOLD
        LISTED --> ESCROWED
        ESCROWED --> SOLD
        MINTED --> BURNED
    end

    subgraph MARKETPLACE["Marketplace Operations"]
        direction TB
        FIXED["Fixed Price<br/>Listing"]
        AUCTION_TYPE["Auction<br/>w/ Anti-Snipe"]
        DUTCH["Dutch<br/>Auction"]

        FIXED --> BUY["Direct Buy"]
        AUCTION_TYPE --> BID["Place Bid"]
        DUTCH --> DECLINING["Declining<br/>Price"]

        BID --> SETTLE["Settle<br/>Auction"]
    end

    subgraph ESCROW_FLOW["Escrow System"]
        direction TB
        FUNDED["Buyer<br/>Funds"]
        DELIVERED["Seller<br/>Delivers"]
        DISPUTE["Dispute<br/>Raised"]
        RESOLVED["Arbitration"]
        RELEASED["Funds<br/>Released"]

        FUNDED --> DELIVERED
        FUNDED --> DISPUTE
        DELIVERED --> RELEASED
        DISPUTE --> RESOLVED
        RESOLVED --> RELEASED
    end

    subgraph ROYALTY_FLOW["Royalty Distribution"]
        direction LR
        SALE_PRICE["Sale<br/>Price"]
        ROYALTY_PCT["Royalty %<br/>(max 25%)"]
        SPLITS["Multi-way<br/>Split"]
        WITHDRAW["Withdraw<br/>Accumulated"]

        SALE_PRICE --> ROYALTY_PCT
        ROYALTY_PCT --> SPLITS
        SPLITS --> WITHDRAW
    end

    CREATOR_FLOW --> NFT_STATE
    NFT_STATE --> MARKETPLACE
    MARKETPLACE --> ESCROW_FLOW

    SOLD --> ROYALTY_FLOW
    SETTLE --> ROYALTY_FLOW

    classDef creator fill:#240046,stroke:#9d4edd,stroke-width:2px,color:#fff
    classDef state fill:#3c096c,stroke:#c77dff,stroke-width:2px,color:#fff
    classDef market fill:#5a189a,stroke:#e0aaff,stroke-width:2px,color:#fff
    classDef escrow fill:#7b2cbf,stroke:#fff,stroke-width:2px,color:#fff
    classDef royalty fill:#9d4edd,stroke:#240046,stroke-width:2px,color:#fff

    class ARTIST,COLLECTION,MINT,ROYALTY_CFG creator
    class MINTED,LISTED,AUCTION,ESCROWED,SOLD,BURNED state
    class FIXED,AUCTION_TYPE,DUTCH,BUY,BID,DECLINING,SETTLE market
    class FUNDED,DELIVERED,DISPUTE,RESOLVED,RELEASED escrow
    class SALE_PRICE,ROYALTY_PCT,SPLITS,WITHDRAW royalty
```

---

## Game Licensing System

Digital game ownership with activation tracking and license types.

```mermaid
flowchart TB
    subgraph PUBLISHER["Publisher Operations"]
        direction LR
        PUB["Publisher"]
        REGISTER["Register<br/>Game"]
        SET_PRICE["Set Pricing"]
        ROYALTY_SET["Set Royalty<br/>Rate"]

        PUB --> REGISTER
        REGISTER --> SET_PRICE
        SET_PRICE --> ROYALTY_SET
    end

    subgraph LICENSE_TYPES["License Types"]
        direction TB
        STANDARD["Standard<br/>Single User"]
        FAMILY["Family<br/>Shared Access"]
        DEVELOPER["Developer<br/>Free, Non-Transfer"]
        TIMED["Time-Limited<br/>Rental"]
        SUBSCRIPTION["Subscription<br/>Recurring"]

        STANDARD --> |"3 devices"| ACTIVATE
        FAMILY --> |"5 devices"| ACTIVATE
        DEVELOPER --> |"unlimited"| ACTIVATE
        TIMED --> |"until expiry"| ACTIVATE
        SUBSCRIPTION --> |"while active"| ACTIVATE
    end

    subgraph ACTIVATION["Activation Flow"]
        direction TB
        ACTIVATE["Activate"]
        DEVICE_ID["Device<br/>Fingerprint"]
        CHECK["Check<br/>Limit"]
        ACTIVE["Active<br/>Session"]
        DEACTIVATE["Deactivate"]

        ACTIVATE --> DEVICE_ID
        DEVICE_ID --> CHECK
        CHECK --> |"OK"| ACTIVE
        CHECK --> |"limit reached"| DEACTIVATE
        ACTIVE --> DEACTIVATE
    end

    subgraph TRANSFER["License Transfer"]
        direction LR
        OWNER["Current<br/>Owner"]
        TRANSFER_REQ["Transfer<br/>Request"]
        ROYALTY_CUT["Royalty<br/>Deduction"]
        NEW_OWNER["New<br/>Owner"]

        OWNER --> TRANSFER_REQ
        TRANSFER_REQ --> ROYALTY_CUT
        ROYALTY_CUT --> NEW_OWNER
    end

    PUBLISHER --> LICENSE_TYPES
    LICENSE_TYPES --> ACTIVATION
    STANDARD --> TRANSFER
    FAMILY --> TRANSFER
    TIMED --> TRANSFER

    classDef pub fill:#023047,stroke:#ffb703,stroke-width:2px,color:#fff
    classDef license fill:#219ebc,stroke:#023047,stroke-width:2px,color:#fff
    classDef activation fill:#8ecae6,stroke:#023047,stroke-width:2px,color:#000
    classDef transfer fill:#ffb703,stroke:#023047,stroke-width:2px,color:#000

    class PUB,REGISTER,SET_PRICE,ROYALTY_SET pub
    class STANDARD,FAMILY,DEVELOPER,TIMED,SUBSCRIPTION license
    class ACTIVATE,DEVICE_ID,CHECK,ACTIVE,DEACTIVATE activation
    class OWNER,TRANSFER_REQ,ROYALTY_CUT,NEW_OWNER transfer
```

---

## Token Economics Flow

The μCoin (MUC) economic model with staking, rewards, and fee distribution.

```mermaid
flowchart TB
    subgraph SUPPLY["Token Supply"]
        direction TB
        TOTAL["Total Supply<br/>137,036,000 MUC"]
        CIRCULATING["Circulating"]
        STAKED["Staked"]
        BURNED["Burned"]

        TOTAL --> CIRCULATING
        TOTAL --> STAKED
        TOTAL --> BURNED
    end

    subgraph UNITS["Unit System"]
        direction LR
        MUC["1 MUC"]
        MUON["1 muon = 10⁻⁸ MUC"]

        MUC --> |"100,000,000"| MUON
    end

    subgraph REWARDS["Block Rewards"]
        direction TB
        BASE["Base Reward<br/>1000 MUC"]
        HALVING["Halving<br/>Every 2.1M blocks"]
        PROPOSER_BONUS["Proposer<br/>10% Bonus"]
        ATTESTER_SHARE["Attester<br/>Share"]

        BASE --> HALVING
        HALVING --> PROPOSER_BONUS
        HALVING --> ATTESTER_SHARE
    end

    subgraph STAKING["Staking Mechanics"]
        direction TB
        MIN_STAKE["Min Stake<br/>10,000 MUC"]
        DELEGATE["Delegation"]
        COMMISSION["Validator<br/>Commission"]
        UNBOND["Unbonding<br/>21 Epochs"]

        MIN_STAKE --> DELEGATE
        DELEGATE --> COMMISSION
        COMMISSION --> UNBOND
    end

    subgraph SLASHING["Slashing Penalties"]
        direction TB
        DOUBLE_SIGN["Double Sign<br/>-5%"]
        DOWNTIME["Downtime<br/>-1%"]
        JAIL["Jail Period"]

        DOUBLE_SIGN --> BURNED
        DOWNTIME --> BURNED
        DOUBLE_SIGN --> JAIL
        DOWNTIME --> JAIL
    end

    subgraph FEES["Fee Distribution"]
        direction TB
        TX_FEE["Transaction<br/>Fees"]
        PLATFORM["Platform Fee<br/>2.5%"]
        ROYALTIES["Creator<br/>Royalties"]

        TX_FEE --> PROPOSER_BONUS
        PLATFORM --> CIRCULATING
        ROYALTIES --> CIRCULATING
    end

    REWARDS --> CIRCULATING
    STAKING --> STAKED

    classDef supply fill:#582f0e,stroke:#faedcd,stroke-width:2px,color:#fff
    classDef units fill:#7f4f24,stroke:#faedcd,stroke-width:2px,color:#fff
    classDef rewards fill:#936639,stroke:#faedcd,stroke-width:2px,color:#fff
    classDef staking fill:#a68a64,stroke:#582f0e,stroke-width:2px,color:#000
    classDef slash fill:#b6ad90,stroke:#582f0e,stroke-width:2px,color:#000
    classDef fees fill:#faedcd,stroke:#582f0e,stroke-width:2px,color:#000

    class TOTAL,CIRCULATING,STAKED,BURNED supply
    class MUC,MUON units
    class BASE,HALVING,PROPOSER_BONUS,ATTESTER_SHARE rewards
    class MIN_STAKE,DELEGATE,COMMISSION,UNBOND staking
    class DOUBLE_SIGN,DOWNTIME,JAIL slash
    class TX_FEE,PLATFORM,ROYALTIES fees
```

---

## Epoch & Finality Timeline

The 8-block epoch structure with checkpoint finality.

```mermaid
sequenceDiagram
    participant V1 as Validator 1
    participant V2 as Validator 2
    participant V3 as Validator 3
    participant NET as Network
    participant STATE as State

    Note over V1,STATE: Epoch N Begins

    rect rgb(30, 60, 90)
        Note over NET: Slot 0
        V1->>NET: Propose Block
        V2->>NET: Attest ✓
        V3->>NET: Attest ✓
        NET->>STATE: Block Confirmed
    end

    rect rgb(40, 70, 100)
        Note over NET: Slot 1
        V2->>NET: Propose Block
        V1->>NET: Attest ✓
        V3->>NET: Attest ✓
        NET->>STATE: Block Confirmed
    end

    rect rgb(50, 80, 110)
        Note over NET: Slots 2-6
        Note over V1,V3: Golden Ratio Selection<br/>Continues...
    end

    rect rgb(60, 90, 120)
        Note over NET: Slot 7 (Final)
        V3->>NET: Propose Block
        V1->>NET: Attest ✓
        V2->>NET: Attest ✓
        NET->>STATE: Block Confirmed
    end

    rect rgb(100, 150, 100)
        Note over NET,STATE: Epoch Checkpoint
        STATE->>STATE: 2/3 Quorum Check
        STATE->>STATE: Finalize Epoch N
        STATE->>NET: Checkpoint Published
    end

    Note over V1,STATE: Epoch N+1 Begins
```

---

## Complete Data Flow

How data flows through the entire system from user action to finalized state.

```mermaid
flowchart TB
    subgraph USER["User Layer"]
        WALLET["User Wallet"]
        DAPP["DApp / CLI"]
    end

    subgraph CRYPTO_LAYER["Cryptographic Layer"]
        SIGN["μ-Sign<br/>Transaction"]
        HASH_TX["μ-Hash<br/>TxID"]
        VERIFY["Signature<br/>Verification"]
    end

    subgraph MEMPOOL["Transaction Mempool"]
        PENDING["Pending<br/>Transactions"]
        SORT["Priority<br/>Sorting"]
        VALIDATE["Validation"]
    end

    subgraph CONSENSUS_EXEC["Consensus Execution"]
        PROPOSER_SEL["Proposer<br/>Selection"]
        BLOCK_BUILD["Block<br/>Building"]
        ATTESTATION["Attestation<br/>Collection"]
    end

    subgraph STATE_TRANSITION["State Transition"]
        EXEC_TX["Execute<br/>Transactions"]
        UPDATE_STATE["Update<br/>Accounts"]
        MERKLE["Compute<br/>Merkle Root"]
    end

    subgraph FINALITY_LAYER["Finality"]
        QUORUM["Quorum<br/>Check"]
        CHECKPOINT["Epoch<br/>Checkpoint"]
        FINAL["Finalized<br/>State"]
    end

    WALLET --> DAPP
    DAPP --> SIGN
    SIGN --> HASH_TX
    HASH_TX --> PENDING

    PENDING --> SORT
    SORT --> VALIDATE
    VALIDATE --> VERIFY
    VERIFY --> PROPOSER_SEL

    PROPOSER_SEL --> BLOCK_BUILD
    VALIDATE --> BLOCK_BUILD
    BLOCK_BUILD --> ATTESTATION

    ATTESTATION --> EXEC_TX
    EXEC_TX --> UPDATE_STATE
    UPDATE_STATE --> MERKLE

    MERKLE --> QUORUM
    QUORUM --> CHECKPOINT
    CHECKPOINT --> FINAL
    FINAL -.-> |"confirmed"| WALLET

    classDef user fill:#1d3557,stroke:#a8dadc,stroke-width:2px,color:#fff
    classDef crypto fill:#457b9d,stroke:#a8dadc,stroke-width:2px,color:#fff
    classDef mempool fill:#a8dadc,stroke:#1d3557,stroke-width:2px,color:#000
    classDef consensus fill:#f1faee,stroke:#1d3557,stroke-width:2px,color:#000
    classDef state fill:#e63946,stroke:#fff,stroke-width:2px,color:#fff
    classDef finality fill:#2a9d8f,stroke:#fff,stroke-width:2px,color:#fff

    class WALLET,DAPP user
    class SIGN,HASH_TX,VERIFY crypto
    class PENDING,SORT,VALIDATE mempool
    class PROPOSER_SEL,BLOCK_BUILD,ATTESTATION consensus
    class EXEC_TX,UPDATE_STATE,MERKLE state
    class QUORUM,CHECKPOINT,FINAL finality
```

---

## Module Dependency Graph

The interconnections between all μOS modules.

```mermaid
graph LR
    subgraph LIBMU["libmu-crypto"]
        P[primitives]
        C[cipher]
        H[hash]
        K[kdf]
        S[signature]
        R[random]

        P --> C
        P --> H
        H --> K
        H --> S
        K --> S
        H --> R
    end

    subgraph CHAIN["chainmesh"]
        subgraph TYPES["types"]
            ADDR[address]
            TOKEN[token]
            BLOCK[block]
            TX[transaction]
            ACCT[account]
        end

        subgraph CONSENSUS["consensus"]
            MUPOS[mu_pos]
            VAL[validator]
            EPOCH[epoch]
            REWARD[reward]
        end

        subgraph CONTRACTS["contracts"]
            NFT[nft]
            COLL[collection]
            MKT[marketplace]
            ROY[royalty]
            LIC[game_license]
        end

        ADDR --> TOKEN
        TOKEN --> BLOCK
        TOKEN --> TX
        ADDR --> ACCT
        TOKEN --> ACCT

        ADDR --> MUPOS
        TOKEN --> VAL
        VAL --> EPOCH
        TOKEN --> REWARD

        ADDR --> NFT
        TOKEN --> NFT
        NFT --> COLL
        NFT --> MKT
        TOKEN --> MKT
        MKT --> ROY
        NFT --> LIC
        TOKEN --> LIC
    end

    S --> ADDR
    H --> BLOCK
    S --> TX
    H --> ACCT

    H --> MUPOS

    linkStyle default stroke:#e94560,stroke-width:2px
```

---

*"In the spiral of μ, balance emerges from chaos."*

