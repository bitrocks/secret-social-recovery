//! # Secret Social Recovery Pallet
//!
//! ## Overview
//! The Recovery Pallet shipped with official Substrate Frame provides a nice M-of-N social recovery
//! mechanism. However, it exposed the friends' accounts in plaintext and may introduces several attack
//! vectors, such as collusions or targetet attacks.
//!
//! Through this pallet, we only store the merkle root of friends' accounts, and commit a merkle proof
//! to blockchain during the recovery period. It's both space effecient and privacy-preserving.
//!

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{
	decl_error, decl_event, decl_module, decl_storage, ensure,
	weights::{FunctionOf, GetDispatchInfo, SimpleDispatchInfo},
	Parameter, RuntimeDebug,
};
use sp_runtime::{
	traits::{CheckedAdd, Dispatchable},
	DispatchResult,
};
use sp_std::convert::TryInto;
use system::{self as system, ensure_root, ensure_signed};

use merkle::Proof;
use sp_core::{sr25519, Pair};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub type Signature = sr25519::Signature;

// #[derive(Encode, Decode)]
// pub type MerkleProof = Proof<Vec<u8>>;

// pub type MerkleProof = Vec<u8>;
/// The pallet's configuration trait.
pub trait Trait: system::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

	/// The overarching call type.
	type Call: Parameter + Dispatchable<Origin = Self::Origin> + GetDispatchInfo;
}

/// Modified version of RecoveryConfig
#[derive(Clone, Eq, PartialEq, Encode, Decode, Default, RuntimeDebug)]
pub struct RecoveryConfig<BlockNumber> {
	/// The minimum number of blocks since the start of the recovery process before the account
	/// can be recovered.
	delay_period: BlockNumber,
	/// The list of friends which can help recover an account. Always sorted.
	friends_merkle_root: Vec<u8>,
	/// The number of approving friends needed to recover an account.
	threshold: u16,
}

/// Modified version of ActiveRecovery
#[derive(Clone, Eq, PartialEq, Encode, Decode, Default, RuntimeDebug)]
pub struct ActiveRecovery<BlockNumber, AccountId> {
	/// The block number when the recovery process started.
	created: BlockNumber,
	/// The friends which have vouched so far. Always sorted.
	approved_friends: Vec<AccountId>,
}

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Trait> as SecretSocialRecovery {
		/// The set of recoverable accounts and their recovery configuration.
		pub Recoverable get(fn recovery_config):
		map hasher(twox_64_concat) T::AccountId => Option<RecoveryConfig<T::BlockNumber>>;


		/// Active recovery attempts.
		///
		/// First account is the account to be recovered, and the second account
		/// is the user trying to recover the account.
		pub ActiveRecoveries get(fn active_recovery):
			double_map hasher(twox_64_concat) T::AccountId, hasher(twox_64_concat) T::AccountId =>
			Option<ActiveRecovery<T::BlockNumber, T::AccountId>>;


		/// The list of allowed proxy accounts.
		///
		/// Map from the user who can access it to the recovered account.
		pub Proxy get(fn proxy):
			map hasher(blake2_128_concat) T::AccountId => Option<T::AccountId>;

	}
}

// The pallet's events
decl_event!(
	pub enum Event<T>
	where
		AccountId = <T as system::Trait>::AccountId,
	{
		/// A recovery process has been set up for an account
		RecoveryCreated(AccountId),
		/// A recovery process has been initiated for account_1 by account_2
		RecoveryInitiated(AccountId, AccountId),
		AccountRecovered(AccountId, AccountId),
		ApprovedRecovery(AccountId, AccountId, AccountId),
	}
);

// The pallet's errors
decl_error! {
	pub enum Error for Module<T: Trait> {
		/// Value was None
		NoneValue,
		/// Value reached maximum and cannot be incremented further
		StorageOverflow,
		/// User is not allowed to make a call on behalf of this account
		NotAllowed,
		/// Threshold must be greater than zero
		ZeroThreshold,
		/// This account is already set up for recovery
		AlreadyRecoverable,
		/// A recovery process has already started for this account
		AlreadyStarted,
		/// This account is not set up for recovery
		NotRecoverable,
		/// the proof's signature is invalid
		SignatureInvalid,
		/// the merkle inclusion proof is invalid
		MerkleProofInvalid,
		/// A recovery process has not started for this account
		NotStarted,
		AlreadyApproved,
		InconsistentProofValue,
		AlreadyProxied,
		Overflow,
		DelayPeriod,
		UnderThreshold
	}
}

// The pallet's dispatchable functions.
decl_module! {
	/// The module declaration.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		// Initializing errors
		// this includes information about your errors in the node's metadata.
		// it is needed only if you are using errors in your pallet
		type Error = Error<T>;

		// Initializing events
		// this is needed only if you are using events in your pallet
		fn deposit_event() = default;


		#[weight = SimpleDispatchInfo::FixedNormal(10_000)]
		fn set_recovered(origin, lost: T::AccountId, rescuer: T::AccountId) {
			ensure_root(origin)?;
			// Create the recovery storage item.
			<Proxy<T>>::insert(&rescuer, &lost);
			Self::deposit_event(RawEvent::AccountRecovered(lost, rescuer));
		}

		#[weight = FunctionOf(
			|args: (&T::AccountId, &Box<<T as Trait>::Call>)| args.1.get_dispatch_info().weight + 10_000,
			|args: (&T::AccountId, &Box<<T as Trait>::Call>)| args.1.get_dispatch_info().class,
			true
		)]
		fn as_recovered(origin,
			lost: T::AccountId,
			call: Box<<T as Trait>::Call>
		) -> DispatchResult {
			let rescuer= ensure_signed(origin)?;
			// Check `who` is allowed to make a call on behalf of `account`
			let target = Self::proxy(&rescuer).ok_or(Error::<T>::NotAllowed)?;
			ensure!(&target == &lost, Error::<T>::NotAllowed);
			call.dispatch(system::RawOrigin::Signed(lost).into())
		}


		#[weight = SimpleDispatchInfo::FixedNormal(100_000)]
		fn create_recovery(origin,
			friends_merkle_root: Vec<u8>,
			threshold: u16,
			delay_period: T::BlockNumber
		) {
			let who = ensure_signed(origin)?;
			// Check account is not already set up for recovery
			ensure!(!<Recoverable<T>>::contains_key(&who), Error::<T>::AlreadyRecoverable);
			// Check user input is valid
			ensure!(threshold >= 1, Error::<T>::ZeroThreshold);

			// Create the recovery configuration
			let recovery_config = RecoveryConfig {
				delay_period,
				friends_merkle_root,
				threshold,
			};

			// Create the recovery configuration storage item
			<Recoverable<T>>::insert(&who, recovery_config);

			Self::deposit_event(RawEvent::RecoveryCreated(who));
		}

		#[weight = SimpleDispatchInfo::FixedNormal(100_000)]
		fn initiate_recovery(origin, lost: T::AccountId) {
			let rescuer = ensure_signed(origin)?;
			// Check that the account is recoverable
			ensure!(<Recoverable<T>>::contains_key(&lost), Error::<T>::NotRecoverable);
			// Check that the recovery process has not already been started
			ensure!(!<ActiveRecoveries<T>>::contains_key(&lost, &rescuer), Error::<T>::AlreadyStarted);
			// Create an active recovery status
			let recovery_status = ActiveRecovery {
				created: <system::Module<T>>::block_number(),
				approved_friends: vec![]
			};
			// Create the active recovery storage item
			<ActiveRecoveries<T>>::insert(&lost, &rescuer, recovery_status);
			Self::deposit_event(RawEvent::RecoveryInitiated(lost, rescuer));
		}

		// fn approve_recovery(origin, lost: T::AccountId, rescuer: T::AccountId, approver: T::AccountId, signature: Signature, proof: Proof<Vec<u8>>) {
		fn approve_recovery(origin, lost: T::AccountId, rescuer: T::AccountId, signature: Signature, proof: Proof<T::AccountId>) {
			let _ = ensure_signed(origin);
			// Check that the lost account is recoverable
			ensure!(<Recoverable<T>>::contains_key(&lost), Error::<T>::NotRecoverable);
			// todo better Error
			let approver = proof.clone().value;
			let approver_public: [u8;32] = approver.as_ref().try_into().expect("");
			// Check that the friend's signature on resuer account is valid
			ensure!(sr25519::Pair::verify(&signature, rescuer.clone(), &sr25519::Public(approver_public)), Error::<T>::SignatureInvalid);
			// ensure!(sr25519::Pair::verify(&signature, rescuer.clone(), &sr25519::Public(public)), Error::<T>::SignatureInvalid);
			let recovery_config = Self::recovery_config(&lost).unwrap();
			// Check that the merkle proof is valid so the friend's account is in recovery group
			ensure!(proof.validate(&recovery_config.friends_merkle_root), Error::<T>::MerkleProofInvalid);
			let mut active_recovery = Self::active_recovery(&lost, &rescuer).ok_or(Error::<T>::NotStarted)?;
			match active_recovery.approved_friends.binary_search(&approver) {
				Ok(_pos) => Err(Error::<T>::AlreadyApproved)?,
				Err(pos) => active_recovery.approved_friends.insert(pos, approver.clone()),
			}
			<ActiveRecoveries<T>>::insert(&lost, &rescuer, active_recovery);
			Self::deposit_event(RawEvent::ApprovedRecovery(lost, rescuer, approver));
		}

		fn claim_recovery(origin, lost: T::AccountId) {
			let rescuer = ensure_signed(origin)?;
			let recovery_config = Self::recovery_config(&lost).ok_or(Error::<T>::NotRecoverable)?;
			let active_recovery = Self::active_recovery(&lost, &rescuer).ok_or(Error::<T>::NotStarted)?;
			ensure!(!<Proxy<T>>::contains_key(&rescuer), Error::<T>::AlreadyProxied);
			// Check delay period
			let current_block_number = <system::Module<T>>::block_number();
			let recoverable_block_number = active_recovery.created.checked_add(&recovery_config.delay_period).ok_or(Error::<T>::Overflow)?;
			ensure!(recoverable_block_number <= current_block_number, Error::<T>::DelayPeriod);
			// Check threshold
			ensure!(active_recovery.approved_friends.len() >= recovery_config.threshold as usize, Error::<T>::UnderThreshold);
			<Proxy<T>>::insert(&rescuer, &lost);
			system::Module::<T>::inc_ref(&rescuer);
			Self::deposit_event(RawEvent::AccountRecovered(lost, rescuer));
		}

	}
}
