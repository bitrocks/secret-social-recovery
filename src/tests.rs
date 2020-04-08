// Tests to be written here
use super::*;
use crate::mock::Call;
use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok};
use merkle::MerkleTree;
use ring::digest::SHA256;
use sp_core::{sr25519, Pair};
use sp_runtime::traits::BadOrigin;

#[test]
fn basic_setup_works() {
	new_test_ext().execute_with(|| {
		// Nothing in storage to start
		let alice = get_from_seed("alice");
		let bob = get_from_seed("bob");
		assert_eq!(Recovery::proxy(bob), None);
		assert_eq!(Recovery::active_recovery(&alice, &bob), None);
		assert_eq!(Recovery::recovery_config(&alice), None);
		// Everyone should have starting balance of 100
		assert_eq!(Balances::free_balance(alice), 100);
	});
}

#[test]
fn set_recovered_works() {
	new_test_ext().execute_with(|| {
		// Not accessible by a normal user
		let alice = get_from_seed("alice");
		let bob = get_from_seed("bob");
		let charlie = get_from_seed("charlie");
		assert_noop!(
			Recovery::set_recovered(Origin::signed(charlie), alice, bob),
			BadOrigin
		);
		// Root can set a recovered account though
		assert_ok!(Recovery::set_recovered(Origin::ROOT, alice, bob));
		// Account 1 should now be able to make a call through account 5
		let call = Box::new(Call::Balances(BalancesCall::transfer(charlie, 10)));
		assert_ok!(Recovery::as_recovered(Origin::signed(bob), alice, call));
		// Account 1 has successfully drained the funds from account 5
		assert_eq!(Balances::free_balance(charlie), 110);
		assert_eq!(Balances::free_balance(alice), 90);
	});
}

#[test]
fn create_recovery_works() {
	new_test_ext().execute_with(|| {
		let alice = get_from_seed("alice");
		// let bob = get_from_seed("bob");
		let charlie = get_from_seed("charlie");
		let dave = get_from_seed("dave");
		let eve = get_from_seed("eve");

		let merkle_tree = MerkleTree::from_vec(&SHA256, vec![charlie, dave, eve]);
		let friends_merkle_root = merkle_tree.root_hash();
		let threshold = 2;
		let delay_period = 5;
		assert_ok!(Recovery::create_recovery(
			Origin::signed(alice),
			friends_merkle_root.to_vec(),
			threshold,
			delay_period,
		));
		let recovery_config = RecoveryConfig {
			friends_merkle_root: friends_merkle_root.to_vec(),
			threshold: threshold,
			delay_period: delay_period,
		};
		assert_eq!(Recovery::recovery_config(alice), Some(recovery_config));
	});
}

#[test]
fn initiate_recovery_works() {
	new_test_ext().execute_with(|| {
		let alice = get_from_seed("alice");
		let bob = get_from_seed("bob");
		let charlie = get_from_seed("charlie");
		let dave = get_from_seed("dave");
		let eve = get_from_seed("eve");

		let merkle_tree = MerkleTree::from_vec(&SHA256, vec![charlie, dave, eve]);

		let friends_merkle_tree = merkle_tree.root_hash();
		assert_noop!(
			Recovery::initiate_recovery(Origin::signed(bob), alice),
			Error::<Test>::NotRecoverable
		);
		assert_ok!(Recovery::create_recovery(
			Origin::signed(alice),
			friends_merkle_tree.to_vec(),
			2,
			5,
		));
		assert_ok!(Recovery::initiate_recovery(Origin::signed(bob), alice));
		assert_noop!(
			Recovery::initiate_recovery(Origin::signed(bob), alice),
			Error::<Test>::AlreadyStarted
		);
		assert_eq!(
			Recovery::active_recovery(alice, bob),
			Some(ActiveRecovery {
				created: 1,
				approved_friends: vec![]
			})
		);
	});
}

#[test]
fn approve_recovery_works() {
	new_test_ext().execute_with(|| {
		let alice = get_from_seed("alice");
		let bob = get_from_seed("bob");
		let charlie = get_from_seed("charlie");
		let dave = get_from_seed("dave");
		let eve = get_from_seed("eve");

		let merkle_tree = MerkleTree::from_vec(&SHA256, vec![charlie, dave, eve]);
		let merkle_tree2 = MerkleTree::from_vec(&SHA256, vec![charlie, dave]);

		let friends_merkle_tree = merkle_tree.root_hash();
		assert_ok!(Recovery::create_recovery(
			Origin::signed(alice),
			friends_merkle_tree.to_vec(),
			2,
			10,
		));
		assert_ok!(Recovery::initiate_recovery(Origin::signed(bob), alice));

		let charlie_proof = merkle_tree.gen_proof(charlie).unwrap();
		let charlie_signature = sign_by_seed("charlie", &bob);
		// charlie is not recoverable
		assert_noop!(
			Recovery::approve_recovery(
				Origin::signed(bob),
				charlie,
				bob,
				charlie_signature.clone(),
				charlie_proof.clone()
			),
			Error::<Test>::NotRecoverable
		);
		let malicious_signature = sign_by_seed("malicious", &bob);
		// malicious signature is invalid, even with charlie's valid proof
		assert_noop!(
			Recovery::approve_recovery(
				Origin::signed(bob),
				alice,
				bob,
				malicious_signature,
				charlie_proof.clone()
			),
			Error::<Test>::SignatureInvalid
		);

		// malicious proof is invalid, even with charlie's valid signature
		let malicious_proof = merkle_tree2.gen_proof(charlie).unwrap();
		// assert_eq!(charlie_proof.clone(), malicious_proof.clone());
		assert_eq!(false, malicious_proof.validate(friends_merkle_tree));
		assert_noop!(
			Recovery::approve_recovery(
				Origin::signed(bob),
				alice,
				bob,
				charlie_signature.clone(),
				malicious_proof
			),
			Error::<Test>::MerkleProofInvalid
		);

		// a valid approve by charlie
		assert_ok!(Recovery::approve_recovery(
			Origin::signed(bob),
			alice,
			bob,
			charlie_signature.clone(),
			charlie_proof.clone()
		));
		assert_eq!(
			Recovery::active_recovery(alice, bob),
			Some(ActiveRecovery {
				created: 1,
				approved_friends: vec![charlie]
			})
		);
		// charlie can't approve twice on the same recovery process
		assert_noop!(
			Recovery::approve_recovery(
				Origin::signed(bob),
				alice,
				bob,
				charlie_signature.clone(),
				charlie_proof.clone()
			),
			Error::<Test>::AlreadyApproved
		);
	});
}

#[test]
fn claim_recovery_works() {
	new_test_ext().execute_with(|| {
		let alice = get_from_seed("alice");
		let bob = get_from_seed("bob");
		let charlie = get_from_seed("charlie");
		let dave = get_from_seed("dave");
		let eve = get_from_seed("eve");
		let merkle_tree = MerkleTree::from_vec(&SHA256, vec![charlie, dave, eve]);

		let friends_merkle_tree = merkle_tree.root_hash();
		assert_ok!(Recovery::create_recovery(
			Origin::signed(alice),
			friends_merkle_tree.to_vec(),
			2,
			10,
		));
		assert_ok!(Recovery::initiate_recovery(Origin::signed(bob), alice));

		let charlie_proof = merkle_tree.gen_proof(charlie).unwrap();
		let charlie_signature = sign_by_seed("charlie", &bob);

		// a valid approve by charlie
		assert_ok!(Recovery::approve_recovery(
			Origin::signed(bob),
			alice,
			bob,
			charlie_signature.clone(),
			charlie_proof.clone()
		));

		assert_eq!(
			Recovery::active_recovery(alice, bob),
			Some(ActiveRecovery {
				created: 1,
				approved_friends: vec![charlie]
			})
		);

		assert_noop!(
			Recovery::claim_recovery(Origin::signed(bob), alice),
			Error::<Test>::DelayPeriod
		);
		run_to_block(11);
		assert_noop!(
			Recovery::claim_recovery(Origin::signed(bob), alice),
			Error::<Test>::UnderThreshold
		);
		let dave_proof = merkle_tree.gen_proof(dave).unwrap();
		let dave_signature = sign_by_seed("dave", &bob);

		// a valid approve by dave
		assert_ok!(Recovery::approve_recovery(
			Origin::signed(bob),
			alice,
			bob,
			dave_signature.clone(),
			dave_proof.clone()
		));

		let mut approved_friends = vec![charlie, dave];
		approved_friends.sort_unstable();
		assert_eq!(
			Recovery::active_recovery(alice, bob),
			Some(ActiveRecovery {
				created: 1,
				approved_friends: approved_friends
			})
		);

		assert_ok!(Recovery::claim_recovery(Origin::signed(bob), alice));

		let call = Box::new(Call::Balances(BalancesCall::transfer(charlie, 10)));
		assert_ok!(Recovery::as_recovered(Origin::signed(bob), alice, call));
		// Account 1 has successfully drained the funds from account 5
		assert_eq!(Balances::free_balance(charlie), 110);
		assert_eq!(Balances::free_balance(alice), 90);
	});
}

#[test]
fn merkle_tree_proof() {
	new_test_ext().execute_with(|| {
		let alice = get_from_seed("alice");
		let bob = get_from_seed("bob");
		let eve = get_from_seed("eve");
		let tree = MerkleTree::from_vec(&SHA256, vec![alice.clone(), bob.clone(), eve.clone()]);

		let proof = tree.gen_proof(alice.clone()).unwrap();
		assert_eq!(true, proof.validate(tree.root_hash()));
		assert_eq!(alice, proof.value);
	});
}

#[test]
fn sr25519_sign_and_verify() {
	new_test_ext().execute_with(|| {
		let pair = <sr25519::Pair>::from_string(&format!("//{}", "alice"), None)
			.expect("static values are valid;qed");
		assert_eq!(get_from_seed("alice"), pair.public());
		let bob = get_from_seed("bob");
		assert!(sr25519::Pair::verify(&pair.sign(&bob), bob, &pair.public()));
	})
}
