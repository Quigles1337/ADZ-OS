//! State Database
//!
//! High-level interface for account and contract state management.
//! Uses Merkle Patricia Trie for authenticated storage.

use super::{KeyValueStore, MerkleTrie, StateRoot, StorageError, StorageResult, KeyPrefix, WriteBatch, EMPTY_ROOT};
use crate::types::{Address, MuCoin};
use libmu_crypto::MuHash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Account state stored in the trie
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountState {
    /// Account nonce (transaction count)
    pub nonce: u64,
    /// Account balance
    pub balance: u64,
    /// Storage root (for contracts)
    pub storage_root: StateRoot,
    /// Code hash (for contracts, empty for EOAs)
    pub code_hash: [u8; 32],
    /// Staked amount
    pub staked: u64,
    /// Delegated validators
    pub delegations: Vec<(Address, u64)>,
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: 0,
            storage_root: EMPTY_ROOT,
            code_hash: EMPTY_ROOT, // Empty code hash
            staked: 0,
            delegations: Vec::new(),
        }
    }
}

impl AccountState {
    /// Create new account with balance
    pub fn new(balance: u64) -> Self {
        Self {
            balance,
            ..Default::default()
        }
    }

    /// Check if account is empty (can be pruned)
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 &&
        self.balance == 0 &&
        self.storage_root == EMPTY_ROOT &&
        self.code_hash == EMPTY_ROOT &&
        self.staked == 0 &&
        self.delegations.is_empty()
    }

    /// Check if this is a contract account
    pub fn is_contract(&self) -> bool {
        self.code_hash != EMPTY_ROOT
    }

    /// Get total balance (available + staked)
    pub fn total_balance(&self) -> u64 {
        self.balance.saturating_add(self.staked)
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> StorageResult<Self> {
        bincode::deserialize(data)
            .map_err(|e| StorageError::SerializationError(e.to_string()))
    }
}

/// Storage value for contracts
pub type StorageValue = [u8; 32];

/// State database for account management
pub struct StateDB<S: KeyValueStore> {
    /// Account state trie
    account_trie: MerkleTrie<S>,
    /// Contract storage tries (address -> trie)
    storage_tries: RwLock<HashMap<Address, MerkleTrie<S>>>,
    /// Contract code cache
    code_cache: RwLock<HashMap<[u8; 32], Vec<u8>>>,
    /// Underlying storage
    store: Arc<S>,
    /// Dirty accounts
    dirty_accounts: RwLock<HashMap<Address, AccountState>>,
    /// Dirty storage
    dirty_storage: RwLock<HashMap<Address, HashMap<[u8; 32], StorageValue>>>,
}

impl<S: KeyValueStore> StateDB<S> {
    /// Create new state database
    pub fn new(store: Arc<S>) -> Self {
        Self {
            account_trie: MerkleTrie::new(Arc::clone(&store)),
            storage_tries: RwLock::new(HashMap::new()),
            code_cache: RwLock::new(HashMap::new()),
            store,
            dirty_accounts: RwLock::new(HashMap::new()),
            dirty_storage: RwLock::new(HashMap::new()),
        }
    }

    /// Create with existing state root
    pub fn with_root(store: Arc<S>, root: StateRoot) -> Self {
        Self {
            account_trie: MerkleTrie::with_root(Arc::clone(&store), root),
            storage_tries: RwLock::new(HashMap::new()),
            code_cache: RwLock::new(HashMap::new()),
            store,
            dirty_accounts: RwLock::new(HashMap::new()),
            dirty_storage: RwLock::new(HashMap::new()),
        }
    }

    /// Get current state root
    pub fn root(&self) -> StateRoot {
        self.account_trie.root()
    }

    /// Get account state
    pub fn get_account(&self, address: &Address) -> StorageResult<AccountState> {
        // Check dirty first
        if let Some(account) = self.dirty_accounts.read().unwrap().get(address) {
            return Ok(account.clone());
        }

        // Get from trie
        let key = address.bytes.to_vec();
        match self.account_trie.get(&key)? {
            Some(data) => AccountState::decode(&data),
            None => Ok(AccountState::default()),
        }
    }

    /// Set account state
    pub fn set_account(&self, address: &Address, account: AccountState) -> StorageResult<()> {
        self.dirty_accounts.write().unwrap().insert(address.clone(), account);
        Ok(())
    }

    /// Get account balance
    pub fn get_balance(&self, address: &Address) -> StorageResult<MuCoin> {
        let account = self.get_account(address)?;
        Ok(MuCoin::from_muons(account.balance))
    }

    /// Set account balance
    pub fn set_balance(&self, address: &Address, balance: MuCoin) -> StorageResult<()> {
        let mut account = self.get_account(address)?;
        account.balance = balance.muons();
        self.set_account(address, account)
    }

    /// Add to balance
    pub fn add_balance(&self, address: &Address, amount: MuCoin) -> StorageResult<()> {
        let mut account = self.get_account(address)?;
        account.balance = account.balance.saturating_add(amount.muons());
        self.set_account(address, account)
    }

    /// Subtract from balance
    pub fn sub_balance(&self, address: &Address, amount: MuCoin) -> StorageResult<()> {
        let mut account = self.get_account(address)?;
        if account.balance < amount.muons() {
            return Err(StorageError::DatabaseError("Insufficient balance".into()));
        }
        account.balance = account.balance.saturating_sub(amount.muons());
        self.set_account(address, account)
    }

    /// Get account nonce
    pub fn get_nonce(&self, address: &Address) -> StorageResult<u64> {
        let account = self.get_account(address)?;
        Ok(account.nonce)
    }

    /// Increment account nonce
    pub fn increment_nonce(&self, address: &Address) -> StorageResult<u64> {
        let mut account = self.get_account(address)?;
        account.nonce = account.nonce.saturating_add(1);
        let new_nonce = account.nonce;
        self.set_account(address, account)?;
        Ok(new_nonce)
    }

    /// Check if account exists (non-empty)
    pub fn account_exists(&self, address: &Address) -> StorageResult<bool> {
        let account = self.get_account(address)?;
        Ok(!account.is_empty())
    }

    /// Check if address is a contract
    pub fn is_contract(&self, address: &Address) -> StorageResult<bool> {
        let account = self.get_account(address)?;
        Ok(account.is_contract())
    }

    /// Get contract code
    pub fn get_code(&self, address: &Address) -> StorageResult<Option<Vec<u8>>> {
        let account = self.get_account(address)?;
        if account.code_hash == EMPTY_ROOT {
            return Ok(None);
        }

        // Check cache
        if let Some(code) = self.code_cache.read().unwrap().get(&account.code_hash) {
            return Ok(Some(code.clone()));
        }

        // Load from storage
        let key = KeyPrefix::code_key(&account.code_hash);
        match self.store.get(&key)? {
            Some(code) => {
                self.code_cache.write().unwrap().insert(account.code_hash, code.clone());
                Ok(Some(code))
            }
            None => Ok(None),
        }
    }

    /// Set contract code
    pub fn set_code(&self, address: &Address, code: Vec<u8>) -> StorageResult<[u8; 32]> {
        let code_hash = MuHash::hash(&code);

        // Store code
        let key = KeyPrefix::code_key(&code_hash);
        self.store.put(&key, &code)?;

        // Update cache
        self.code_cache.write().unwrap().insert(code_hash, code);

        // Update account
        let mut account = self.get_account(address)?;
        account.code_hash = code_hash;
        self.set_account(address, account)?;

        Ok(code_hash)
    }

    /// Get code hash
    pub fn get_code_hash(&self, address: &Address) -> StorageResult<[u8; 32]> {
        let account = self.get_account(address)?;
        Ok(account.code_hash)
    }

    /// Get contract storage value
    pub fn get_storage(&self, address: &Address, slot: &[u8; 32]) -> StorageResult<StorageValue> {
        // Check dirty first
        if let Some(storage) = self.dirty_storage.read().unwrap().get(address) {
            if let Some(value) = storage.get(slot) {
                return Ok(*value);
            }
        }

        // Get account to find storage root
        let account = self.get_account(address)?;
        if account.storage_root == EMPTY_ROOT {
            return Ok([0u8; 32]);
        }

        // Get or create storage trie
        let storage_trie = self.get_or_create_storage_trie(address, account.storage_root)?;

        match storage_trie.get(slot)? {
            Some(data) if data.len() == 32 => {
                let mut value = [0u8; 32];
                value.copy_from_slice(&data);
                Ok(value)
            }
            _ => Ok([0u8; 32]),
        }
    }

    /// Set contract storage value
    pub fn set_storage(&self, address: &Address, slot: [u8; 32], value: StorageValue) -> StorageResult<()> {
        self.dirty_storage
            .write()
            .unwrap()
            .entry(address.clone())
            .or_insert_with(HashMap::new)
            .insert(slot, value);
        Ok(())
    }

    /// Get or create storage trie for an address
    fn get_or_create_storage_trie(&self, address: &Address, root: StateRoot) -> StorageResult<MerkleTrie<S>> {
        let mut tries = self.storage_tries.write().unwrap();

        if let Some(trie) = tries.get(address) {
            // Check if root matches
            if trie.root() == root {
                return Ok(MerkleTrie::with_root(Arc::clone(&self.store), root));
            }
        }

        let trie = MerkleTrie::with_root(Arc::clone(&self.store), root);
        tries.insert(address.clone(), MerkleTrie::with_root(Arc::clone(&self.store), root));
        Ok(trie)
    }

    /// Commit all changes and return new state root
    pub fn commit(&self) -> StorageResult<StateRoot> {
        // First, commit dirty storage to get new storage roots
        let mut storage_roots: HashMap<Address, StateRoot> = HashMap::new();
        {
            let dirty_storage = self.dirty_storage.read().unwrap();
            for (address, storage) in dirty_storage.iter() {
                let account = self.get_account(address)?;
                let mut trie = MerkleTrie::with_root(Arc::clone(&self.store), account.storage_root);

                for (slot, value) in storage {
                    if *value == [0u8; 32] {
                        trie.delete(slot)?;
                    } else {
                        trie.put(slot, value.to_vec())?;
                    }
                }

                trie.commit()?;
                storage_roots.insert(address.clone(), trie.root());
            }
        }

        // Now commit dirty accounts with updated storage roots
        {
            let dirty_accounts = self.dirty_accounts.read().unwrap();
            for (address, mut account) in dirty_accounts.iter().map(|(a, acc)| (a.clone(), acc.clone())) {
                // Update storage root if changed
                if let Some(new_root) = storage_roots.get(&address) {
                    account.storage_root = *new_root;
                }

                let key = address.bytes.to_vec();
                if account.is_empty() {
                    self.account_trie.delete(&key)?;
                } else {
                    self.account_trie.put(&key, account.encode())?;
                }
            }
        }

        // Commit account trie
        self.account_trie.commit()?;

        // Clear dirty state
        self.dirty_accounts.write().unwrap().clear();
        self.dirty_storage.write().unwrap().clear();

        Ok(self.account_trie.root())
    }

    /// Rollback uncommitted changes
    pub fn rollback(&self) {
        self.dirty_accounts.write().unwrap().clear();
        self.dirty_storage.write().unwrap().clear();
    }

    /// Get pending changes count
    pub fn pending_changes(&self) -> usize {
        let accounts = self.dirty_accounts.read().unwrap().len();
        let storage: usize = self.dirty_storage.read().unwrap()
            .values()
            .map(|s| s.len())
            .sum();
        accounts + storage
    }

    /// Create snapshot of current state
    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            root: self.root(),
            dirty_accounts: self.dirty_accounts.read().unwrap().clone(),
            dirty_storage: self.dirty_storage.read().unwrap().clone(),
        }
    }

    /// Restore from snapshot
    pub fn restore(&self, snapshot: StateSnapshot) {
        *self.dirty_accounts.write().unwrap() = snapshot.dirty_accounts;
        *self.dirty_storage.write().unwrap() = snapshot.dirty_storage;
    }

    /// Transfer balance between accounts
    pub fn transfer(&self, from: &Address, to: &Address, amount: MuCoin) -> StorageResult<()> {
        // Check balance
        let from_account = self.get_account(from)?;
        if from_account.balance < amount.muons() {
            return Err(StorageError::DatabaseError("Insufficient balance for transfer".into()));
        }

        // Perform transfer
        self.sub_balance(from, amount)?;
        self.add_balance(to, amount)?;

        Ok(())
    }

    /// Get staked amount for address
    pub fn get_staked(&self, address: &Address) -> StorageResult<MuCoin> {
        let account = self.get_account(address)?;
        Ok(MuCoin::from_muons(account.staked))
    }

    /// Add stake
    pub fn add_stake(&self, address: &Address, amount: MuCoin) -> StorageResult<()> {
        let mut account = self.get_account(address)?;
        if account.balance < amount.muons() {
            return Err(StorageError::DatabaseError("Insufficient balance for staking".into()));
        }
        account.balance = account.balance.saturating_sub(amount.muons());
        account.staked = account.staked.saturating_add(amount.muons());
        self.set_account(address, account)
    }

    /// Remove stake
    pub fn remove_stake(&self, address: &Address, amount: MuCoin) -> StorageResult<()> {
        let mut account = self.get_account(address)?;
        if account.staked < amount.muons() {
            return Err(StorageError::DatabaseError("Insufficient staked amount".into()));
        }
        account.staked = account.staked.saturating_sub(amount.muons());
        account.balance = account.balance.saturating_add(amount.muons());
        self.set_account(address, account)
    }

    /// Clear all caches
    pub fn clear_caches(&self) {
        self.account_trie.clear_cache();
        self.storage_tries.write().unwrap().clear();
        self.code_cache.write().unwrap().clear();
    }
}

/// Snapshot of dirty state for rollback
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    /// State root at snapshot time
    pub root: StateRoot,
    /// Dirty accounts
    dirty_accounts: HashMap<Address, AccountState>,
    /// Dirty storage
    dirty_storage: HashMap<Address, HashMap<[u8; 32], StorageValue>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryKV;
    use crate::types::AddressType;

    fn test_address(n: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = n;
        Address::new(AddressType::User, bytes)
    }

    fn create_test_state() -> StateDB<MemoryKV> {
        let store = Arc::new(MemoryKV::new());
        StateDB::new(store)
    }

    #[test]
    fn test_empty_state() {
        let state = create_test_state();
        assert_eq!(state.root(), EMPTY_ROOT);

        let account = state.get_account(&test_address(1)).unwrap();
        assert!(account.is_empty());
    }

    #[test]
    fn test_set_get_balance() {
        let state = create_test_state();
        let addr = test_address(1);

        state.set_balance(&addr, MuCoin::from_muc(100)).unwrap();
        let balance = state.get_balance(&addr).unwrap();
        assert_eq!(balance.muc(), 100);
    }

    #[test]
    fn test_transfer() {
        let state = create_test_state();
        let addr1 = test_address(1);
        let addr2 = test_address(2);

        state.set_balance(&addr1, MuCoin::from_muc(100)).unwrap();
        state.transfer(&addr1, &addr2, MuCoin::from_muc(30)).unwrap();

        assert_eq!(state.get_balance(&addr1).unwrap().muc(), 70);
        assert_eq!(state.get_balance(&addr2).unwrap().muc(), 30);
    }

    #[test]
    fn test_transfer_insufficient() {
        let state = create_test_state();
        let addr1 = test_address(1);
        let addr2 = test_address(2);

        state.set_balance(&addr1, MuCoin::from_muc(100)).unwrap();
        let result = state.transfer(&addr1, &addr2, MuCoin::from_muc(200));
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce() {
        let state = create_test_state();
        let addr = test_address(1);

        assert_eq!(state.get_nonce(&addr).unwrap(), 0);
        assert_eq!(state.increment_nonce(&addr).unwrap(), 1);
        assert_eq!(state.increment_nonce(&addr).unwrap(), 2);
        assert_eq!(state.get_nonce(&addr).unwrap(), 2);
    }

    #[test]
    fn test_storage() {
        let state = create_test_state();
        let addr = test_address(1);
        let slot = [1u8; 32];
        let value = [2u8; 32];

        // Initial storage is zero
        assert_eq!(state.get_storage(&addr, &slot).unwrap(), [0u8; 32]);

        // Set storage
        state.set_storage(&addr, slot, value).unwrap();
        assert_eq!(state.get_storage(&addr, &slot).unwrap(), value);
    }

    #[test]
    fn test_commit() {
        let state = create_test_state();
        let addr = test_address(1);

        state.set_balance(&addr, MuCoin::from_muc(100)).unwrap();
        let root1 = state.commit().unwrap();
        assert_ne!(root1, EMPTY_ROOT);

        // State should persist after commit
        assert_eq!(state.get_balance(&addr).unwrap().muc(), 100);

        // Another change should produce different root
        state.set_balance(&addr, MuCoin::from_muc(200)).unwrap();
        let root2 = state.commit().unwrap();
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_rollback() {
        let state = create_test_state();
        let addr = test_address(1);

        state.set_balance(&addr, MuCoin::from_muc(100)).unwrap();
        state.commit().unwrap();

        // Make uncommitted change
        state.set_balance(&addr, MuCoin::from_muc(200)).unwrap();
        assert_eq!(state.pending_changes(), 1);

        // Rollback
        state.rollback();
        assert_eq!(state.pending_changes(), 0);

        // Original value should be preserved (from trie)
        assert_eq!(state.get_balance(&addr).unwrap().muc(), 100);
    }

    #[test]
    fn test_snapshot_restore() {
        let state = create_test_state();
        let addr = test_address(1);

        state.set_balance(&addr, MuCoin::from_muc(100)).unwrap();
        let snap = state.snapshot();

        state.set_balance(&addr, MuCoin::from_muc(200)).unwrap();
        assert_eq!(state.get_balance(&addr).unwrap().muc(), 200);

        state.restore(snap);
        assert_eq!(state.get_balance(&addr).unwrap().muc(), 100);
    }

    #[test]
    fn test_staking() {
        let state = create_test_state();
        let addr = test_address(1);

        state.set_balance(&addr, MuCoin::from_muc(100)).unwrap();
        state.add_stake(&addr, MuCoin::from_muc(30)).unwrap();

        assert_eq!(state.get_balance(&addr).unwrap().muc(), 70);
        assert_eq!(state.get_staked(&addr).unwrap().muc(), 30);

        state.remove_stake(&addr, MuCoin::from_muc(20)).unwrap();
        assert_eq!(state.get_balance(&addr).unwrap().muc(), 90);
        assert_eq!(state.get_staked(&addr).unwrap().muc(), 10);
    }

    #[test]
    fn test_code_storage() {
        let state = create_test_state();
        let addr = test_address(1);
        let code = b"contract bytecode here".to_vec();

        assert!(!state.is_contract(&addr).unwrap());

        let code_hash = state.set_code(&addr, code.clone()).unwrap();
        assert!(state.is_contract(&addr).unwrap());
        assert_eq!(state.get_code(&addr).unwrap(), Some(code));
        assert_eq!(state.get_code_hash(&addr).unwrap(), code_hash);
    }

    #[test]
    fn test_deterministic_root() {
        let store1 = Arc::new(MemoryKV::new());
        let store2 = Arc::new(MemoryKV::new());

        let state1 = StateDB::new(store1);
        let state2 = StateDB::new(store2);

        let addr1 = test_address(1);
        let addr2 = test_address(2);

        // Same operations should produce same root
        state1.set_balance(&addr1, MuCoin::from_muc(100)).unwrap();
        state1.set_balance(&addr2, MuCoin::from_muc(200)).unwrap();
        let root1 = state1.commit().unwrap();

        state2.set_balance(&addr1, MuCoin::from_muc(100)).unwrap();
        state2.set_balance(&addr2, MuCoin::from_muc(200)).unwrap();
        let root2 = state2.commit().unwrap();

        assert_eq!(root1, root2);
    }
}
