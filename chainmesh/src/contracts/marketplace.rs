//! NFT Marketplace with Escrow
//!
//! P2P trading platform for NFTs with:
//! - Listing management (fixed price, auction)
//! - Secure escrow for trades
//! - Automatic royalty distribution
//! - Offer system

use crate::types::{Address, MuCoin};
use super::{ContractError, ContractResult, ContractEvent, generate_id};
use std::collections::HashMap;

/// Listing status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingStatus {
    /// Listing is active
    Active,
    /// Listing has been sold
    Sold,
    /// Listing was cancelled by seller
    Cancelled,
    /// Listing has expired
    Expired,
}

/// Listing type
#[derive(Debug, Clone)]
pub enum ListingType {
    /// Fixed price listing
    FixedPrice {
        price: MuCoin,
    },
    /// Auction listing
    Auction {
        starting_price: MuCoin,
        reserve_price: Option<MuCoin>,
        current_bid: Option<Bid>,
        end_time: u64,
    },
    /// Dutch auction (declining price)
    DutchAuction {
        starting_price: MuCoin,
        ending_price: MuCoin,
        start_time: u64,
        end_time: u64,
    },
}

/// A bid on an auction
#[derive(Debug, Clone)]
pub struct Bid {
    /// Bidder address
    pub bidder: Address,
    /// Bid amount
    pub amount: MuCoin,
    /// Bid timestamp
    pub timestamp: u64,
}

/// A marketplace listing
#[derive(Debug, Clone)]
pub struct Listing {
    /// Listing ID
    pub listing_id: [u8; 32],
    /// NFT collection address
    pub collection: Address,
    /// NFT token ID
    pub token_id: [u8; 32],
    /// Seller address
    pub seller: Address,
    /// Listing type and price info
    pub listing_type: ListingType,
    /// Current status
    pub status: ListingStatus,
    /// Royalty recipient
    pub royalty_recipient: Address,
    /// Royalty percentage (basis points)
    pub royalty_bps: u16,
    /// Created timestamp
    pub created_at: u64,
    /// Expiration timestamp (0 = no expiration)
    pub expires_at: u64,
}

impl Listing {
    /// Get current price for fixed or dutch auction
    pub fn current_price(&self) -> Option<MuCoin> {
        match &self.listing_type {
            ListingType::FixedPrice { price } => Some(*price),
            ListingType::DutchAuction {
                starting_price,
                ending_price,
                start_time,
                end_time,
            } => {
                let now = super::current_timestamp();
                if now <= *start_time {
                    return Some(*starting_price);
                }
                if now >= *end_time {
                    return Some(*ending_price);
                }

                // Linear interpolation
                let elapsed = now - start_time;
                let duration = end_time - start_time;
                let price_drop = starting_price.muons().saturating_sub(ending_price.muons());
                let current_drop = (price_drop as u128 * elapsed as u128 / duration as u128) as u64;
                Some(MuCoin::from_muons(starting_price.muons().saturating_sub(current_drop)))
            }
            ListingType::Auction { current_bid, .. } => {
                current_bid.as_ref().map(|b| b.amount)
            }
        }
    }

    /// Check if listing is active
    pub fn is_active(&self) -> bool {
        if self.status != ListingStatus::Active {
            return false;
        }
        if self.expires_at > 0 && super::current_timestamp() >= self.expires_at {
            return false;
        }
        true
    }

    /// Calculate royalty
    pub fn calculate_royalty(&self, sale_price: MuCoin) -> MuCoin {
        sale_price.percentage(self.royalty_bps as u64)
    }
}

/// Escrow state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowState {
    /// Escrow is funded and waiting
    Funded,
    /// Trade completed, funds released
    Released,
    /// Trade cancelled, funds refunded
    Refunded,
    /// Dispute raised
    Disputed,
    /// Dispute resolved
    Resolved,
}

/// Escrow for secure trades
#[derive(Debug, Clone)]
pub struct Escrow {
    /// Escrow ID
    pub escrow_id: [u8; 32],
    /// Buyer address
    pub buyer: Address,
    /// Seller address
    pub seller: Address,
    /// Escrowed amount
    pub amount: MuCoin,
    /// State
    pub state: EscrowState,
    /// Associated listing ID (if any)
    pub listing_id: Option<[u8; 32]>,
    /// Created timestamp
    pub created_at: u64,
    /// Completed timestamp
    pub completed_at: Option<u64>,
    /// Release deadline (auto-release if not disputed)
    pub release_deadline: u64,
    /// Dispute reason (if disputed)
    pub dispute_reason: Option<String>,
}

impl Escrow {
    /// Check if escrow can be released
    pub fn can_release(&self) -> bool {
        self.state == EscrowState::Funded
    }

    /// Check if escrow can be refunded
    pub fn can_refund(&self) -> bool {
        matches!(self.state, EscrowState::Funded | EscrowState::Disputed)
    }

    /// Check if auto-release is available
    pub fn can_auto_release(&self) -> bool {
        self.state == EscrowState::Funded &&
            super::current_timestamp() >= self.release_deadline
    }
}

/// An offer on an NFT
#[derive(Debug, Clone)]
pub struct Offer {
    /// Offer ID
    pub offer_id: [u8; 32],
    /// Collection address
    pub collection: Address,
    /// Token ID
    pub token_id: [u8; 32],
    /// Offerer address
    pub offerer: Address,
    /// Offer amount
    pub amount: MuCoin,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Is offer still active
    pub active: bool,
}

/// NFT Marketplace contract
#[derive(Debug)]
pub struct Marketplace {
    /// Contract address
    pub address: Address,
    /// Platform operator
    pub operator: Address,
    /// All listings
    listings: HashMap<[u8; 32], Listing>,
    /// Listings by seller
    listings_by_seller: HashMap<Address, Vec<[u8; 32]>>,
    /// Listings by collection
    listings_by_collection: HashMap<Address, Vec<[u8; 32]>>,
    /// Escrows
    escrows: HashMap<[u8; 32], Escrow>,
    /// Offers by token
    offers: HashMap<([u8; 32], Address), Vec<Offer>>, // (token_id, collection) -> offers
    /// Platform fee (basis points)
    pub platform_fee_bps: u16,
    /// Accumulated fees
    pub accumulated_fees: MuCoin,
    /// Auto-release period (seconds)
    pub auto_release_period: u64,
    /// Events
    events: Vec<ContractEvent>,
}

impl Marketplace {
    /// Create new marketplace
    pub fn new(address: Address, operator: Address) -> Self {
        Self {
            address,
            operator,
            listings: HashMap::new(),
            listings_by_seller: HashMap::new(),
            listings_by_collection: HashMap::new(),
            escrows: HashMap::new(),
            offers: HashMap::new(),
            platform_fee_bps: 250, // 2.5%
            accumulated_fees: MuCoin::ZERO,
            auto_release_period: 3 * 24 * 60 * 60, // 3 days
            events: Vec::new(),
        }
    }

    /// Create a fixed price listing
    pub fn create_listing(
        &mut self,
        collection: Address,
        token_id: [u8; 32],
        price: MuCoin,
        royalty_recipient: Address,
        royalty_bps: u16,
        expires_at: u64,
        seller: &Address,
    ) -> ContractResult<[u8; 32]> {
        if royalty_bps > 2500 {
            return Err(ContractError::RoyaltyTooHigh(royalty_bps));
        }

        let listing_id = generate_id(&[
            &collection.bytes,
            &token_id,
            &seller.bytes,
            &super::current_timestamp().to_le_bytes(),
        ]);

        let listing = Listing {
            listing_id,
            collection: collection.clone(),
            token_id,
            seller: seller.clone(),
            listing_type: ListingType::FixedPrice { price },
            status: ListingStatus::Active,
            royalty_recipient,
            royalty_bps,
            created_at: super::current_timestamp(),
            expires_at,
        };

        self.listings.insert(listing_id, listing);
        self.listings_by_seller
            .entry(seller.clone())
            .or_insert_with(Vec::new)
            .push(listing_id);
        self.listings_by_collection
            .entry(collection.clone())
            .or_insert_with(Vec::new)
            .push(listing_id);

        self.events.push(ContractEvent::ListingCreated {
            listing_id,
            token_id,
            seller: seller.clone(),
            price,
        });

        Ok(listing_id)
    }

    /// Create an auction listing
    pub fn create_auction(
        &mut self,
        collection: Address,
        token_id: [u8; 32],
        starting_price: MuCoin,
        reserve_price: Option<MuCoin>,
        duration: u64,
        royalty_recipient: Address,
        royalty_bps: u16,
        seller: &Address,
    ) -> ContractResult<[u8; 32]> {
        if royalty_bps > 2500 {
            return Err(ContractError::RoyaltyTooHigh(royalty_bps));
        }

        let listing_id = generate_id(&[
            &collection.bytes,
            &token_id,
            &seller.bytes,
            b"auction",
            &super::current_timestamp().to_le_bytes(),
        ]);

        let now = super::current_timestamp();
        let listing = Listing {
            listing_id,
            collection: collection.clone(),
            token_id,
            seller: seller.clone(),
            listing_type: ListingType::Auction {
                starting_price,
                reserve_price,
                current_bid: None,
                end_time: now + duration,
            },
            status: ListingStatus::Active,
            royalty_recipient,
            royalty_bps,
            created_at: now,
            expires_at: now + duration,
        };

        self.listings.insert(listing_id, listing);
        self.listings_by_seller
            .entry(seller.clone())
            .or_insert_with(Vec::new)
            .push(listing_id);
        self.listings_by_collection
            .entry(collection.clone())
            .or_insert_with(Vec::new)
            .push(listing_id);

        self.events.push(ContractEvent::ListingCreated {
            listing_id,
            token_id,
            seller: seller.clone(),
            price: starting_price,
        });

        Ok(listing_id)
    }

    /// Buy a fixed price listing
    pub fn buy(
        &mut self,
        listing_id: &[u8; 32],
        payment: MuCoin,
        buyer: &Address,
    ) -> ContractResult<(MuCoin, MuCoin, MuCoin)> { // (seller_amount, royalty, platform_fee)
        let listing = self.listings.get(listing_id)
            .ok_or(ContractError::ListingNotFound)?;

        if !listing.is_active() {
            return Err(ContractError::ListingExpired);
        }

        if buyer == &listing.seller {
            return Err(ContractError::InvalidOperation("Cannot buy own listing".into()));
        }

        let price = match &listing.listing_type {
            ListingType::FixedPrice { price } => *price,
            ListingType::DutchAuction { .. } => {
                listing.current_price().ok_or(ContractError::ListingExpired)?
            }
            _ => return Err(ContractError::InvalidOperation("Use bid for auctions".into())),
        };

        if payment < price {
            return Err(ContractError::InsufficientFunds {
                have: payment,
                need: price,
            });
        }

        // Calculate fees
        let royalty = listing.calculate_royalty(price);
        let platform_fee = price.percentage(self.platform_fee_bps as u64);
        let seller_amount = price - royalty - platform_fee;

        self.accumulated_fees = self.accumulated_fees + platform_fee;

        // Update listing
        let listing = self.listings.get_mut(listing_id).unwrap();
        listing.status = ListingStatus::Sold;

        self.events.push(ContractEvent::ListingSold {
            listing_id: *listing_id,
            buyer: buyer.clone(),
            price,
        });

        // Emit royalty event if applicable
        if !royalty.is_zero() {
            self.events.push(ContractEvent::RoyaltyPaid {
                token_id: listing.token_id,
                creator: listing.royalty_recipient.clone(),
                amount: royalty,
            });
        }

        Ok((seller_amount, royalty, platform_fee))
    }

    /// Place a bid on an auction
    pub fn place_bid(
        &mut self,
        listing_id: &[u8; 32],
        amount: MuCoin,
        bidder: &Address,
    ) -> ContractResult<Option<Bid>> { // Returns previous bid to refund
        let listing = self.listings.get_mut(listing_id)
            .ok_or(ContractError::ListingNotFound)?;

        if !listing.is_active() {
            return Err(ContractError::ListingExpired);
        }

        if bidder == &listing.seller {
            return Err(ContractError::InvalidOperation("Cannot bid on own listing".into()));
        }

        // Capture original duration for anti-sniping logic
        let original_duration = listing.expires_at.saturating_sub(listing.created_at);

        match &mut listing.listing_type {
            ListingType::Auction {
                starting_price,
                current_bid,
                end_time,
                ..
            } => {
                let now = super::current_timestamp();
                if now >= *end_time {
                    return Err(ContractError::ListingExpired);
                }

                // Check minimum bid
                let min_bid = current_bid
                    .as_ref()
                    .map(|b| MuCoin::from_muons(b.amount.muons() + b.amount.muons() / 20)) // 5% higher
                    .unwrap_or(*starting_price);

                if amount < min_bid {
                    return Err(ContractError::InsufficientFunds {
                        have: amount,
                        need: min_bid,
                    });
                }

                // Get previous bid for refund
                let previous = current_bid.take();

                // Set new bid
                *current_bid = Some(Bid {
                    bidder: bidder.clone(),
                    amount,
                    timestamp: now,
                });

                // Anti-sniping: extend auction if bid in last 10 minutes
                // Only applies to auctions with original duration >= 5 minutes
                if original_duration >= 300 && *end_time - now < 600 {
                    *end_time = now + 600;
                }

                Ok(previous)
            }
            _ => Err(ContractError::InvalidOperation("Not an auction".into())),
        }
    }

    /// Settle an auction
    pub fn settle_auction(
        &mut self,
        listing_id: &[u8; 32],
    ) -> ContractResult<Option<(Address, MuCoin, MuCoin, MuCoin)>> { // (winner, seller_amount, royalty, fee)
        let listing = self.listings.get(listing_id)
            .ok_or(ContractError::ListingNotFound)?;

        if listing.status != ListingStatus::Active {
            return Err(ContractError::InvalidOperation("Auction not active".into()));
        }

        match &listing.listing_type {
            ListingType::Auction {
                current_bid,
                reserve_price,
                end_time,
                ..
            } => {
                let now = super::current_timestamp();
                if now < *end_time {
                    return Err(ContractError::InvalidOperation("Auction not ended".into()));
                }

                match current_bid {
                    Some(bid) => {
                        // Check reserve price
                        if let Some(reserve) = reserve_price {
                            if bid.amount < *reserve {
                                // Reserve not met, cancel
                                let listing = self.listings.get_mut(listing_id).unwrap();
                                listing.status = ListingStatus::Cancelled;
                                return Ok(None);
                            }
                        }

                        let price = bid.amount;
                        let winner = bid.bidder.clone();

                        // Calculate fees
                        let royalty = listing.calculate_royalty(price);
                        let platform_fee = price.percentage(self.platform_fee_bps as u64);
                        let seller_amount = price - royalty - platform_fee;

                        self.accumulated_fees = self.accumulated_fees + platform_fee;

                        let royalty_recipient = listing.royalty_recipient.clone();
                        let token_id = listing.token_id;

                        // Update listing
                        let listing = self.listings.get_mut(listing_id).unwrap();
                        listing.status = ListingStatus::Sold;

                        self.events.push(ContractEvent::ListingSold {
                            listing_id: *listing_id,
                            buyer: winner.clone(),
                            price,
                        });

                        if !royalty.is_zero() {
                            self.events.push(ContractEvent::RoyaltyPaid {
                                token_id,
                                creator: royalty_recipient,
                                amount: royalty,
                            });
                        }

                        Ok(Some((winner, seller_amount, royalty, platform_fee)))
                    }
                    None => {
                        // No bids, cancel
                        let listing = self.listings.get_mut(listing_id).unwrap();
                        listing.status = ListingStatus::Cancelled;
                        Ok(None)
                    }
                }
            }
            _ => Err(ContractError::InvalidOperation("Not an auction".into())),
        }
    }

    /// Cancel a listing
    pub fn cancel_listing(
        &mut self,
        listing_id: &[u8; 32],
        caller: &Address,
    ) -> ContractResult<Option<Bid>> { // Returns bid to refund for auctions
        let listing = self.listings.get(listing_id)
            .ok_or(ContractError::ListingNotFound)?;

        if &listing.seller != caller && caller != &self.operator {
            return Err(ContractError::Unauthorized("Not authorized to cancel".into()));
        }

        if listing.status != ListingStatus::Active {
            return Err(ContractError::InvalidOperation("Listing not active".into()));
        }

        // Get bid to refund for auctions
        let refund_bid = match &listing.listing_type {
            ListingType::Auction { current_bid, .. } => current_bid.clone(),
            _ => None,
        };

        let listing = self.listings.get_mut(listing_id).unwrap();
        listing.status = ListingStatus::Cancelled;

        self.events.push(ContractEvent::ListingCancelled {
            listing_id: *listing_id,
        });

        Ok(refund_bid)
    }

    /// Create escrow for P2P trade
    pub fn create_escrow(
        &mut self,
        buyer: Address,
        seller: Address,
        amount: MuCoin,
        listing_id: Option<[u8; 32]>,
    ) -> ContractResult<[u8; 32]> {
        let escrow_id = generate_id(&[
            &buyer.bytes,
            &seller.bytes,
            &amount.muons().to_le_bytes(),
            &super::current_timestamp().to_le_bytes(),
        ]);

        let now = super::current_timestamp();
        let escrow = Escrow {
            escrow_id,
            buyer: buyer.clone(),
            seller: seller.clone(),
            amount,
            state: EscrowState::Funded,
            listing_id,
            created_at: now,
            completed_at: None,
            release_deadline: now + self.auto_release_period,
            dispute_reason: None,
        };

        self.escrows.insert(escrow_id, escrow);

        self.events.push(ContractEvent::EscrowCreated {
            escrow_id,
            buyer,
            seller,
            amount,
        });

        Ok(escrow_id)
    }

    /// Release escrow to seller
    pub fn release_escrow(
        &mut self,
        escrow_id: &[u8; 32],
        caller: &Address,
    ) -> ContractResult<(Address, MuCoin)> { // (recipient, amount)
        let escrow = self.escrows.get(escrow_id)
            .ok_or_else(|| ContractError::EscrowError("Escrow not found".into()))?;

        // Buyer can release, or auto-release after deadline
        let is_auto_release = escrow.can_auto_release();
        if caller != &escrow.buyer && caller != &self.operator && !is_auto_release {
            return Err(ContractError::Unauthorized("Not authorized to release".into()));
        }

        if !escrow.can_release() {
            return Err(ContractError::EscrowError("Cannot release escrow".into()));
        }

        let seller = escrow.seller.clone();
        let amount = escrow.amount;

        let escrow = self.escrows.get_mut(escrow_id).unwrap();
        escrow.state = EscrowState::Released;
        escrow.completed_at = Some(super::current_timestamp());

        self.events.push(ContractEvent::EscrowReleased {
            escrow_id: *escrow_id,
            to: seller.clone(),
            amount,
        });

        Ok((seller, amount))
    }

    /// Refund escrow to buyer
    pub fn refund_escrow(
        &mut self,
        escrow_id: &[u8; 32],
        caller: &Address,
    ) -> ContractResult<(Address, MuCoin)> {
        let escrow = self.escrows.get(escrow_id)
            .ok_or_else(|| ContractError::EscrowError("Escrow not found".into()))?;

        // Seller can refund, or operator for disputes
        if caller != &escrow.seller && caller != &self.operator {
            return Err(ContractError::Unauthorized("Not authorized to refund".into()));
        }

        if !escrow.can_refund() {
            return Err(ContractError::EscrowError("Cannot refund escrow".into()));
        }

        let buyer = escrow.buyer.clone();
        let amount = escrow.amount;

        let escrow = self.escrows.get_mut(escrow_id).unwrap();
        escrow.state = EscrowState::Refunded;
        escrow.completed_at = Some(super::current_timestamp());

        self.events.push(ContractEvent::EscrowReleased {
            escrow_id: *escrow_id,
            to: buyer.clone(),
            amount,
        });

        Ok((buyer, amount))
    }

    /// Raise dispute on escrow
    pub fn dispute_escrow(
        &mut self,
        escrow_id: &[u8; 32],
        reason: String,
        caller: &Address,
    ) -> ContractResult<()> {
        let escrow = self.escrows.get(escrow_id)
            .ok_or_else(|| ContractError::EscrowError("Escrow not found".into()))?;

        if caller != &escrow.buyer && caller != &escrow.seller {
            return Err(ContractError::Unauthorized("Not a party to escrow".into()));
        }

        if escrow.state != EscrowState::Funded {
            return Err(ContractError::EscrowError("Escrow not in fundedstate".into()));
        }

        let escrow = self.escrows.get_mut(escrow_id).unwrap();
        escrow.state = EscrowState::Disputed;
        escrow.dispute_reason = Some(reason);

        Ok(())
    }

    /// Resolve dispute (operator only)
    pub fn resolve_dispute(
        &mut self,
        escrow_id: &[u8; 32],
        release_to_seller: bool,
        caller: &Address,
    ) -> ContractResult<(Address, MuCoin)> {
        if caller != &self.operator {
            return Err(ContractError::Unauthorized("Only operator can resolve".into()));
        }

        let escrow = self.escrows.get(escrow_id)
            .ok_or_else(|| ContractError::EscrowError("Escrow not found".into()))?;

        if escrow.state != EscrowState::Disputed {
            return Err(ContractError::EscrowError("Escrow not disputed".into()));
        }

        let (recipient, amount) = if release_to_seller {
            (escrow.seller.clone(), escrow.amount)
        } else {
            (escrow.buyer.clone(), escrow.amount)
        };

        let escrow = self.escrows.get_mut(escrow_id).unwrap();
        escrow.state = EscrowState::Resolved;
        escrow.completed_at = Some(super::current_timestamp());

        self.events.push(ContractEvent::EscrowReleased {
            escrow_id: *escrow_id,
            to: recipient.clone(),
            amount,
        });

        Ok((recipient, amount))
    }

    /// Get listing by ID
    pub fn get_listing(&self, listing_id: &[u8; 32]) -> Option<&Listing> {
        self.listings.get(listing_id)
    }

    /// Get all listings for a seller
    pub fn listings_by_seller(&self, seller: &Address) -> Vec<&Listing> {
        self.listings_by_seller
            .get(seller)
            .map(|ids| ids.iter().filter_map(|id| self.listings.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all active listings for a collection
    pub fn active_listings_for_collection(&self, collection: &Address) -> Vec<&Listing> {
        self.listings_by_collection
            .get(collection)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.listings.get(id))
                    .filter(|l| l.is_active())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get escrow by ID
    pub fn get_escrow(&self, escrow_id: &[u8; 32]) -> Option<&Escrow> {
        self.escrows.get(escrow_id)
    }

    /// Withdraw accumulated fees
    pub fn withdraw_fees(&mut self, caller: &Address) -> ContractResult<MuCoin> {
        if caller != &self.operator {
            return Err(ContractError::Unauthorized("Only operator can withdraw".into()));
        }

        let amount = self.accumulated_fees;
        self.accumulated_fees = MuCoin::ZERO;
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
    fn test_create_and_buy_listing() {
        let operator = test_address(b"operator");
        let seller = test_address(b"seller");
        let buyer = test_address(b"buyer");
        let royalty_recipient = test_address(b"creator");
        let collection = test_address(b"collection");
        let marketplace_addr = test_address(b"marketplace");

        let mut marketplace = Marketplace::new(marketplace_addr, operator);

        let listing_id = marketplace.create_listing(
            collection,
            [1u8; 32], // token_id
            MuCoin::from_muc(100),
            royalty_recipient,
            500, // 5% royalty
            0, // no expiration
            &seller,
        ).unwrap();

        // Buy
        let (seller_amount, royalty, platform_fee) = marketplace.buy(
            &listing_id,
            MuCoin::from_muc(100),
            &buyer,
        ).unwrap();

        // 5% royalty = 5 MUC
        assert_eq!(royalty.muc(), 5);
        // 2.5% platform fee = 2.5 MUC (2 due to integer division)
        assert_eq!(platform_fee.muons(), MuCoin::from_muc(100).percentage(250).muons());
        // Seller gets rest
        assert!(seller_amount.muc() > 90);

        let listing = marketplace.get_listing(&listing_id).unwrap();
        assert_eq!(listing.status, ListingStatus::Sold);
    }

    #[test]
    fn test_auction() {
        let operator = test_address(b"operator");
        let seller = test_address(b"seller");
        let bidder1 = test_address(b"bidder1");
        let bidder2 = test_address(b"bidder2");
        let royalty_recipient = test_address(b"creator");
        let collection = test_address(b"collection");
        let marketplace_addr = test_address(b"marketplace");

        let mut marketplace = Marketplace::new(marketplace_addr, operator);

        let listing_id = marketplace.create_auction(
            collection,
            [1u8; 32],
            MuCoin::from_muc(10), // starting price
            Some(MuCoin::from_muc(50)), // reserve price
            1, // 1 second duration
            royalty_recipient,
            500,
            &seller,
        ).unwrap();

        // Place bids
        marketplace.place_bid(&listing_id, MuCoin::from_muc(15), &bidder1).unwrap();
        let prev_bid = marketplace.place_bid(&listing_id, MuCoin::from_muc(60), &bidder2).unwrap();

        // Previous bidder should get refund
        assert!(prev_bid.is_some());
        assert_eq!(prev_bid.unwrap().bidder, bidder1);

        // Wait for auction to end - need to wait >1 second for the auction to expire
        // Using 1100ms to ensure we cross the second boundary
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Settle
        let result = marketplace.settle_auction(&listing_id).unwrap();
        assert!(result.is_some());
        let (winner, _, _, _) = result.unwrap();
        assert_eq!(winner, bidder2);
    }

    #[test]
    fn test_escrow() {
        let operator = test_address(b"operator");
        let buyer = test_address(b"buyer");
        let seller = test_address(b"seller");
        let marketplace_addr = test_address(b"marketplace");

        let mut marketplace = Marketplace::new(marketplace_addr, operator);

        let escrow_id = marketplace.create_escrow(
            buyer.clone(),
            seller.clone(),
            MuCoin::from_muc(100),
            None,
        ).unwrap();

        let escrow = marketplace.get_escrow(&escrow_id).unwrap();
        assert_eq!(escrow.state, EscrowState::Funded);

        // Release
        let (recipient, amount) = marketplace.release_escrow(&escrow_id, &buyer).unwrap();
        assert_eq!(recipient, seller);
        assert_eq!(amount.muc(), 100);

        let escrow = marketplace.get_escrow(&escrow_id).unwrap();
        assert_eq!(escrow.state, EscrowState::Released);
    }

    #[test]
    fn test_escrow_dispute() {
        let operator = test_address(b"operator");
        let buyer = test_address(b"buyer");
        let seller = test_address(b"seller");
        let marketplace_addr = test_address(b"marketplace");

        let mut marketplace = Marketplace::new(marketplace_addr, operator.clone());

        let escrow_id = marketplace.create_escrow(
            buyer.clone(),
            seller.clone(),
            MuCoin::from_muc(100),
            None,
        ).unwrap();

        // Buyer raises dispute
        marketplace.dispute_escrow(&escrow_id, "Item not as described".into(), &buyer).unwrap();

        let escrow = marketplace.get_escrow(&escrow_id).unwrap();
        assert_eq!(escrow.state, EscrowState::Disputed);

        // Operator resolves in favor of buyer
        let (recipient, amount) = marketplace.resolve_dispute(&escrow_id, false, &operator).unwrap();
        assert_eq!(recipient, buyer);
        assert_eq!(amount.muc(), 100);
    }

    #[test]
    fn test_cancel_listing() {
        let operator = test_address(b"operator");
        let seller = test_address(b"seller");
        let royalty_recipient = test_address(b"creator");
        let collection = test_address(b"collection");
        let marketplace_addr = test_address(b"marketplace");

        let mut marketplace = Marketplace::new(marketplace_addr, operator);

        let listing_id = marketplace.create_listing(
            collection,
            [1u8; 32],
            MuCoin::from_muc(100),
            royalty_recipient,
            500,
            0,
            &seller,
        ).unwrap();

        marketplace.cancel_listing(&listing_id, &seller).unwrap();

        let listing = marketplace.get_listing(&listing_id).unwrap();
        assert_eq!(listing.status, ListingStatus::Cancelled);
    }
}
