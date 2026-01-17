//! Game License Contract
//!
//! Digital game ownership through NFTs with licensing features:
//! - Single-use and multi-use licenses
//! - Family sharing
//! - Time-limited licenses
//! - Resale with royalties
//! - Activation tracking

use crate::types::{Address, MuCoin};
use super::{ContractError, ContractResult, ContractEvent, generate_id};
use std::collections::{HashMap, HashSet};

/// License types for games
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseType {
    /// Standard single-user license
    Standard,
    /// Family license (multiple users)
    Family { max_users: u8 },
    /// Developer/review copy (non-transferable)
    Developer,
    /// Time-limited license (rental)
    TimeLimited { expires_at: u64 },
    /// Subscription-based (requires renewal)
    Subscription { renewal_period: u64 },
}

impl LicenseType {
    /// Check if this license can be resold
    pub fn is_resellable(&self) -> bool {
        match self {
            LicenseType::Developer => false,
            LicenseType::Subscription { .. } => false,
            _ => true,
        }
    }

    /// Get maximum activations for this license type
    pub fn max_activations(&self) -> u32 {
        match self {
            LicenseType::Standard => 3,
            LicenseType::Family { max_users } => *max_users as u32 * 2,
            LicenseType::Developer => 5,
            LicenseType::TimeLimited { .. } => 2,
            LicenseType::Subscription { .. } => 3,
        }
    }
}

/// State of a game license
#[derive(Debug, Clone)]
pub struct LicenseState {
    /// License ID
    pub license_id: [u8; 32],
    /// Game ID this license is for
    pub game_id: [u8; 32],
    /// Current owner
    pub owner: Address,
    /// Original purchaser
    pub original_owner: Address,
    /// License type
    pub license_type: LicenseType,
    /// Current activations
    pub activations: Vec<Activation>,
    /// Is license revoked
    pub revoked: bool,
    /// Purchase price (for royalty calculation on resale)
    pub purchase_price: MuCoin,
    /// Royalty percentage (basis points)
    pub royalty_bps: u16,
    /// Created timestamp
    pub created_at: u64,
    /// Last transfer timestamp
    pub last_transfer: u64,
    /// Number of times transferred
    pub transfer_count: u32,
}

impl LicenseState {
    /// Check if license is valid
    pub fn is_valid(&self) -> bool {
        if self.revoked {
            return false;
        }

        let now = super::current_timestamp();
        match self.license_type {
            LicenseType::TimeLimited { expires_at } => now < expires_at,
            LicenseType::Subscription { .. } => {
                // Check if any activation is still valid
                self.activations.iter().any(|a| a.is_active(now))
            }
            _ => true,
        }
    }

    /// Check if can add activation
    pub fn can_activate(&self) -> bool {
        if !self.is_valid() {
            return false;
        }
        self.active_count() < self.license_type.max_activations()
    }

    /// Get count of active activations
    pub fn active_count(&self) -> u32 {
        let now = super::current_timestamp();
        self.activations.iter().filter(|a| a.is_active(now)).count() as u32
    }

    /// Calculate royalty for resale
    pub fn calculate_royalty(&self, sale_price: MuCoin) -> MuCoin {
        sale_price.percentage(self.royalty_bps as u64)
    }
}

/// An activation of a license on a device/user
#[derive(Debug, Clone)]
pub struct Activation {
    /// User address (for family sharing)
    pub user: Address,
    /// Device ID hash
    pub device_id: [u8; 32],
    /// Activation timestamp
    pub activated_at: u64,
    /// Deactivation timestamp (0 if active)
    pub deactivated_at: u64,
    /// For subscription: when this activation expires
    pub expires_at: Option<u64>,
}

impl Activation {
    /// Check if activation is currently active
    pub fn is_active(&self, now: u64) -> bool {
        if self.deactivated_at > 0 {
            return false;
        }
        match self.expires_at {
            Some(exp) => now < exp,
            None => true,
        }
    }
}

/// Game metadata
#[derive(Debug, Clone)]
pub struct GameInfo {
    /// Game ID
    pub game_id: [u8; 32],
    /// Game title
    pub title: String,
    /// Developer/publisher address
    pub publisher: Address,
    /// Default royalty for resales
    pub royalty_bps: u16,
    /// Is game active for new licenses
    pub active: bool,
    /// Game metadata URI
    pub metadata_uri: String,
    /// Standard license price
    pub standard_price: MuCoin,
    /// Family license price
    pub family_price: MuCoin,
}

/// Game License Contract
#[derive(Debug)]
pub struct GameLicenseContract {
    /// Contract address
    pub address: Address,
    /// Platform operator
    pub operator: Address,
    /// Registered games
    games: HashMap<[u8; 32], GameInfo>,
    /// All licenses
    licenses: HashMap<[u8; 32], LicenseState>,
    /// Licenses by owner
    licenses_by_owner: HashMap<Address, HashSet<[u8; 32]>>,
    /// Licenses by game
    licenses_by_game: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    /// Platform fee (basis points)
    pub platform_fee_bps: u16,
    /// Accumulated platform fees
    pub platform_fees: MuCoin,
    /// Events
    events: Vec<ContractEvent>,
}

impl GameLicenseContract {
    /// Create new game license contract
    pub fn new(address: Address, operator: Address) -> Self {
        Self {
            address,
            operator,
            games: HashMap::new(),
            licenses: HashMap::new(),
            licenses_by_owner: HashMap::new(),
            licenses_by_game: HashMap::new(),
            platform_fee_bps: 250, // 2.5% platform fee
            platform_fees: MuCoin::ZERO,
            events: Vec::new(),
        }
    }

    /// Register a new game
    pub fn register_game(
        &mut self,
        title: String,
        publisher: Address,
        royalty_bps: u16,
        metadata_uri: String,
        standard_price: MuCoin,
        family_price: MuCoin,
        caller: &Address,
    ) -> ContractResult<[u8; 32]> {
        // Only operator or publisher can register
        if caller != &self.operator && caller != &publisher {
            return Err(ContractError::Unauthorized("Not authorized to register game".into()));
        }

        if royalty_bps > 2500 {
            return Err(ContractError::RoyaltyTooHigh(royalty_bps));
        }

        let game_id = generate_id(&[
            &self.address.bytes,
            title.as_bytes(),
            &publisher.bytes,
        ]);

        if self.games.contains_key(&game_id) {
            return Err(ContractError::AlreadyExists("Game already registered".into()));
        }

        self.games.insert(game_id, GameInfo {
            game_id,
            title,
            publisher,
            royalty_bps,
            active: true,
            metadata_uri,
            standard_price,
            family_price,
        });

        self.licenses_by_game.insert(game_id, HashSet::new());

        Ok(game_id)
    }

    /// Purchase a license
    pub fn purchase_license(
        &mut self,
        game_id: &[u8; 32],
        license_type: LicenseType,
        buyer: Address,
        payment: MuCoin,
    ) -> ContractResult<[u8; 32]> {
        let game = self.games.get(game_id)
            .ok_or_else(|| ContractError::LicenseError("Game not found".into()))?;

        if !game.active {
            return Err(ContractError::LicenseError("Game not available".into()));
        }

        // Determine price
        let price = match license_type {
            LicenseType::Family { .. } => game.family_price,
            LicenseType::Developer => MuCoin::ZERO, // Developer licenses are free
            _ => game.standard_price,
        };

        if payment < price {
            return Err(ContractError::InsufficientFunds {
                have: payment,
                need: price,
            });
        }

        // Calculate fees
        let platform_fee = price.percentage(self.platform_fee_bps as u64);
        self.platform_fees = self.platform_fees + platform_fee;

        // Generate license ID
        let license_id = generate_id(&[
            game_id,
            &buyer.bytes,
            &super::current_timestamp().to_le_bytes(),
        ]);

        let now = super::current_timestamp();

        let license = LicenseState {
            license_id,
            game_id: *game_id,
            owner: buyer.clone(),
            original_owner: buyer.clone(),
            license_type,
            activations: Vec::new(),
            revoked: false,
            purchase_price: price,
            royalty_bps: game.royalty_bps,
            created_at: now,
            last_transfer: now,
            transfer_count: 0,
        };

        // Update indices
        self.licenses.insert(license_id, license);
        self.licenses_by_owner
            .entry(buyer.clone())
            .or_insert_with(HashSet::new)
            .insert(license_id);
        self.licenses_by_game
            .get_mut(game_id)
            .map(|set| set.insert(license_id));

        self.events.push(ContractEvent::LicenseActivated {
            license_id,
            user: buyer,
            game_id: *game_id,
        });

        Ok(license_id)
    }

    /// Activate a license on a device
    pub fn activate(
        &mut self,
        license_id: &[u8; 32],
        user: Address,
        device_id: [u8; 32],
        caller: &Address,
    ) -> ContractResult<()> {
        let license = self.licenses.get_mut(license_id)
            .ok_or_else(|| ContractError::LicenseError("License not found".into()))?;

        // Check ownership
        if &license.owner != caller {
            // For family licenses, owner can activate for family members
            if !matches!(license.license_type, LicenseType::Family { .. }) {
                return Err(ContractError::Unauthorized("Not license owner".into()));
            }
        }

        if !license.can_activate() {
            return Err(ContractError::LicenseError("Cannot activate - max reached or invalid".into()));
        }

        // Check if device already activated
        let now = super::current_timestamp();
        if license.activations.iter().any(|a| a.device_id == device_id && a.is_active(now)) {
            return Err(ContractError::AlreadyExists("Device already activated".into()));
        }

        // Calculate expiration for subscription
        let expires_at = match license.license_type {
            LicenseType::Subscription { renewal_period } => Some(now + renewal_period),
            LicenseType::TimeLimited { expires_at } => Some(expires_at),
            _ => None,
        };

        license.activations.push(Activation {
            user: user.clone(),
            device_id,
            activated_at: now,
            deactivated_at: 0,
            expires_at,
        });

        self.events.push(ContractEvent::LicenseActivated {
            license_id: *license_id,
            user,
            game_id: license.game_id,
        });

        Ok(())
    }

    /// Deactivate a license on a device
    pub fn deactivate(
        &mut self,
        license_id: &[u8; 32],
        device_id: [u8; 32],
        caller: &Address,
    ) -> ContractResult<()> {
        let license = self.licenses.get_mut(license_id)
            .ok_or_else(|| ContractError::LicenseError("License not found".into()))?;

        if &license.owner != caller {
            return Err(ContractError::Unauthorized("Not license owner".into()));
        }

        let now = super::current_timestamp();
        let activation = license.activations.iter_mut()
            .find(|a| a.device_id == device_id && a.is_active(now))
            .ok_or_else(|| ContractError::LicenseError("Activation not found".into()))?;

        activation.deactivated_at = now;

        Ok(())
    }

    /// Transfer license to new owner
    pub fn transfer_license(
        &mut self,
        license_id: &[u8; 32],
        to: Address,
        sale_price: MuCoin,
        caller: &Address,
    ) -> ContractResult<MuCoin> {
        let license = self.licenses.get(license_id)
            .ok_or_else(|| ContractError::LicenseError("License not found".into()))?;

        if &license.owner != caller {
            return Err(ContractError::Unauthorized("Not license owner".into()));
        }

        if !license.license_type.is_resellable() {
            return Err(ContractError::LicenseError("License is not resellable".into()));
        }

        if !license.is_valid() {
            return Err(ContractError::LicenseError("License is not valid".into()));
        }

        let from = license.owner.clone();
        let game_id = license.game_id;

        // Calculate royalty
        let royalty = license.calculate_royalty(sale_price);
        let platform_fee = sale_price.percentage(self.platform_fee_bps as u64);
        self.platform_fees = self.platform_fees + platform_fee;

        // Emit royalty event
        if !royalty.is_zero() {
            if let Some(game) = self.games.get(&game_id) {
                self.events.push(ContractEvent::RoyaltyPaid {
                    token_id: *license_id,
                    creator: game.publisher.clone(),
                    amount: royalty,
                });
            }
        }

        // Update license
        let license = self.licenses.get_mut(license_id).unwrap();
        license.owner = to.clone();
        license.last_transfer = super::current_timestamp();
        license.transfer_count += 1;

        // Clear all activations on transfer
        for activation in &mut license.activations {
            if activation.deactivated_at == 0 {
                activation.deactivated_at = super::current_timestamp();
            }
        }

        // Update indices
        self.licenses_by_owner
            .get_mut(&from)
            .map(|set| set.remove(license_id));
        self.licenses_by_owner
            .entry(to.clone())
            .or_insert_with(HashSet::new)
            .insert(*license_id);

        self.events.push(ContractEvent::NFTTransferred {
            collection: self.address.clone(),
            token_id: *license_id,
            from,
            to,
        });

        Ok(royalty)
    }

    /// Revoke a license (publisher/operator only)
    pub fn revoke_license(
        &mut self,
        license_id: &[u8; 32],
        reason: String,
        caller: &Address,
    ) -> ContractResult<()> {
        let license = self.licenses.get(license_id)
            .ok_or_else(|| ContractError::LicenseError("License not found".into()))?;

        let game = self.games.get(&license.game_id)
            .ok_or_else(|| ContractError::LicenseError("Game not found".into()))?;

        // Only operator or publisher can revoke
        if caller != &self.operator && caller != &game.publisher {
            return Err(ContractError::Unauthorized("Not authorized to revoke".into()));
        }

        let license = self.licenses.get_mut(license_id).unwrap();
        license.revoked = true;

        // Deactivate all activations
        let now = super::current_timestamp();
        for activation in &mut license.activations {
            if activation.deactivated_at == 0 {
                activation.deactivated_at = now;
            }
        }

        Ok(())
    }

    /// Get license by ID
    pub fn get_license(&self, license_id: &[u8; 32]) -> Option<&LicenseState> {
        self.licenses.get(license_id)
    }

    /// Get all licenses for an owner
    pub fn licenses_of(&self, owner: &Address) -> Vec<&LicenseState> {
        self.licenses_by_owner
            .get(owner)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.licenses.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get game info
    pub fn get_game(&self, game_id: &[u8; 32]) -> Option<&GameInfo> {
        self.games.get(game_id)
    }

    /// Check if user has valid license for a game
    pub fn has_valid_license(&self, user: &Address, game_id: &[u8; 32]) -> bool {
        self.licenses_by_owner
            .get(user)
            .map(|license_ids| {
                license_ids.iter().any(|id| {
                    self.licenses.get(id)
                        .map(|l| l.game_id == *game_id && l.is_valid())
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    /// Withdraw platform fees
    pub fn withdraw_fees(&mut self, caller: &Address) -> ContractResult<MuCoin> {
        if caller != &self.operator {
            return Err(ContractError::Unauthorized("Only operator can withdraw".into()));
        }

        let amount = self.platform_fees;
        self.platform_fees = MuCoin::ZERO;
        Ok(amount)
    }

    /// Get and clear events
    pub fn take_events(&mut self) -> Vec<ContractEvent> {
        std::mem::take(&mut self.events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libmu_crypto::MuKeyPair;

    fn test_address(seed: &[u8]) -> Address {
        let keypair = MuKeyPair::from_seed(seed);
        Address::from_public_key(keypair.public_key())
    }

    #[test]
    fn test_register_game() {
        let operator = test_address(b"operator");
        let publisher = test_address(b"publisher");
        let contract_addr = test_address(b"contract");

        let mut contract = GameLicenseContract::new(contract_addr, operator.clone());

        let game_id = contract.register_game(
            "Test Game".into(),
            publisher.clone(),
            500, // 5% royalty
            "ipfs://metadata".into(),
            MuCoin::from_muc(50), // Standard price
            MuCoin::from_muc(80), // Family price
            &publisher,
        ).unwrap();

        let game = contract.get_game(&game_id).unwrap();
        assert_eq!(game.title, "Test Game");
        assert_eq!(game.standard_price.muc(), 50);
    }

    #[test]
    fn test_purchase_license() {
        let operator = test_address(b"operator");
        let publisher = test_address(b"publisher");
        let buyer = test_address(b"buyer");
        let contract_addr = test_address(b"contract");

        let mut contract = GameLicenseContract::new(contract_addr, operator);

        let game_id = contract.register_game(
            "Test Game".into(),
            publisher.clone(),
            500,
            "ipfs://metadata".into(),
            MuCoin::from_muc(50),
            MuCoin::from_muc(80),
            &publisher,
        ).unwrap();

        let license_id = contract.purchase_license(
            &game_id,
            LicenseType::Standard,
            buyer.clone(),
            MuCoin::from_muc(50),
        ).unwrap();

        let license = contract.get_license(&license_id).unwrap();
        assert_eq!(license.owner, buyer);
        assert!(license.is_valid());
    }

    #[test]
    fn test_activation() {
        let operator = test_address(b"operator");
        let publisher = test_address(b"publisher");
        let buyer = test_address(b"buyer");
        let contract_addr = test_address(b"contract");

        let mut contract = GameLicenseContract::new(contract_addr, operator);

        let game_id = contract.register_game(
            "Test Game".into(),
            publisher.clone(),
            500,
            "ipfs://metadata".into(),
            MuCoin::from_muc(50),
            MuCoin::from_muc(80),
            &publisher,
        ).unwrap();

        let license_id = contract.purchase_license(
            &game_id,
            LicenseType::Standard,
            buyer.clone(),
            MuCoin::from_muc(50),
        ).unwrap();

        // Activate
        let device_id = [1u8; 32];
        contract.activate(&license_id, buyer.clone(), device_id, &buyer).unwrap();

        let license = contract.get_license(&license_id).unwrap();
        assert_eq!(license.active_count(), 1);

        // Deactivate
        contract.deactivate(&license_id, device_id, &buyer).unwrap();
        let license = contract.get_license(&license_id).unwrap();
        assert_eq!(license.active_count(), 0);
    }

    #[test]
    fn test_license_transfer() {
        let operator = test_address(b"operator");
        let publisher = test_address(b"publisher");
        let buyer = test_address(b"buyer");
        let new_owner = test_address(b"new_owner");
        let contract_addr = test_address(b"contract");

        let mut contract = GameLicenseContract::new(contract_addr, operator);

        let game_id = contract.register_game(
            "Test Game".into(),
            publisher.clone(),
            500, // 5% royalty
            "ipfs://metadata".into(),
            MuCoin::from_muc(50),
            MuCoin::from_muc(80),
            &publisher,
        ).unwrap();

        let license_id = contract.purchase_license(
            &game_id,
            LicenseType::Standard,
            buyer.clone(),
            MuCoin::from_muc(50),
        ).unwrap();

        // Activate before transfer
        contract.activate(&license_id, buyer.clone(), [1u8; 32], &buyer).unwrap();

        // Transfer
        let royalty = contract.transfer_license(
            &license_id,
            new_owner.clone(),
            MuCoin::from_muc(40), // Resale price
            &buyer,
        ).unwrap();

        // 5% of 40 = 2 MUC royalty
        assert_eq!(royalty.muc(), 2);

        let license = contract.get_license(&license_id).unwrap();
        assert_eq!(license.owner, new_owner);
        assert_eq!(license.transfer_count, 1);
        // Activations should be cleared
        assert_eq!(license.active_count(), 0);
    }

    #[test]
    fn test_family_license() {
        let operator = test_address(b"operator");
        let publisher = test_address(b"publisher");
        let buyer = test_address(b"buyer");
        let family_member = test_address(b"family");
        let contract_addr = test_address(b"contract");

        let mut contract = GameLicenseContract::new(contract_addr, operator);

        let game_id = contract.register_game(
            "Test Game".into(),
            publisher.clone(),
            500,
            "ipfs://metadata".into(),
            MuCoin::from_muc(50),
            MuCoin::from_muc(80),
            &publisher,
        ).unwrap();

        let license_id = contract.purchase_license(
            &game_id,
            LicenseType::Family { max_users: 5 },
            buyer.clone(),
            MuCoin::from_muc(80),
        ).unwrap();

        // Owner can activate for family members
        contract.activate(&license_id, family_member.clone(), [1u8; 32], &buyer).unwrap();
        contract.activate(&license_id, buyer.clone(), [2u8; 32], &buyer).unwrap();

        let license = contract.get_license(&license_id).unwrap();
        assert_eq!(license.active_count(), 2);
        // Family with 5 users = 10 max activations
        assert_eq!(license.license_type.max_activations(), 10);
    }

    #[test]
    fn test_developer_license_non_transferable() {
        let operator = test_address(b"operator");
        let publisher = test_address(b"publisher");
        let developer = test_address(b"developer");
        let other = test_address(b"other");
        let contract_addr = test_address(b"contract");

        let mut contract = GameLicenseContract::new(contract_addr, operator);

        let game_id = contract.register_game(
            "Test Game".into(),
            publisher.clone(),
            500,
            "ipfs://metadata".into(),
            MuCoin::from_muc(50),
            MuCoin::from_muc(80),
            &publisher,
        ).unwrap();

        let license_id = contract.purchase_license(
            &game_id,
            LicenseType::Developer,
            developer.clone(),
            MuCoin::ZERO, // Free for developer
        ).unwrap();

        // Cannot transfer developer license
        let result = contract.transfer_license(
            &license_id,
            other,
            MuCoin::from_muc(10),
            &developer,
        );
        assert!(matches!(result, Err(ContractError::LicenseError(_))));
    }
}
