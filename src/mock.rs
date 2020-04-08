// Creating mock runtime here

use super::*;
use crate::{Module, Trait};
use frame_support::{
	impl_outer_dispatch, impl_outer_event, impl_outer_origin, parameter_types, weights::Weight,
};
use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup, OnFinalize, OnInitialize},
	Perbill,
};

use crate as recovery;
use system as frame_system;

impl_outer_origin! {
	pub enum Origin for Test where system = frame_system {}
}

impl_outer_event! {
	pub enum TestEvent for Test {
		system<T>,
		pallet_balances<T>,
		recovery<T>,
	}
}

impl_outer_dispatch! {
	pub enum Call for Test where origin: Origin {
		pallet_balances::Balances,
		recovery::Recovery,
	}
}

// For testing the pallet, we construct most of a mock runtime. This means
// first constructing a configuration type (`Test`) which `impl`s each of the
// configuration traits of pallets we want to use.
#[derive(Clone, Eq, PartialEq)]
pub struct Test;
parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const MaximumBlockWeight: Weight = 1024;
	pub const MaximumBlockLength: u32 = 2 * 1024;
	pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
}
impl frame_system::Trait for Test {
	type Origin = Origin;
	type Call = Call;
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = sr25519::Public;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = TestEvent;
	type BlockHashCount = BlockHashCount;
	type MaximumBlockWeight = MaximumBlockWeight;
	type MaximumBlockLength = MaximumBlockLength;
	type AvailableBlockRatio = AvailableBlockRatio;
	type Version = ();
	type ModuleToIndex = ();
	type AccountData = pallet_balances::AccountData<u128>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
}

impl Trait for Test {
	type Event = TestEvent;
	type Call = Call;
}

parameter_types! {
	pub const ExistentialDeposit: u64 = 1;
}

impl pallet_balances::Trait for Test {
	type Balance = u128;
	type DustRemoval = ();
	type Event = TestEvent;
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
}

pub type Recovery = Module<Test>;
pub type System = system::Module<Test>;
pub type Balances = pallet_balances::Module<Test>;
pub type BalancesCall = pallet_balances::Call<Test>;

// This function basically just builds a genesis storage key/value store according to
// our desired mockup.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::default()
		.build_storage::<Test>()
		.unwrap();

	// let alice = get_from_seed::<sr25519::Public>("alice");
	// let bob = get_from_seed::<sr25519::Public>("bob");
	// let eve = get_from_seed::<sr25519::Public>("eve");
	let alice = get_from_seed("alice");
	let bob = get_from_seed("bob");
	let charlie = get_from_seed("charlie");
	let dave = get_from_seed("dave");
	let eve = get_from_seed("eve");
	pallet_balances::GenesisConfig::<Test> {
		balances: vec![
			(alice, 100),
			(bob, 100),
			(charlie, 100),
			(dave, 100),
			(eve, 100),
		],
	}
	.assimilate_storage(&mut t)
	.unwrap();
	t.into()
}

pub fn get_from_seed(seed: &str) -> sr25519::Public {
	<sr25519::Pair>::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

pub fn sign_by_seed(seed: &str, message: &[u8]) -> Signature {
	<sr25519::Pair>::from_string(&format!("//{}", seed), None)
		.expect("static values are valid;qed")
		.sign(message)
}

pub fn run_to_block(n: u64) {
	while System::block_number() < n {
		if System::block_number() > 1 {
			System::on_finalize(System::block_number());
		}
		System::set_block_number(System::block_number() + 1);
		System::on_initialize(System::block_number());
	}
}
