use assert_matches::assert_matches;
use miden_lib::account::components::rpo_falcon_512_multisig_library;
use miden_lib::account::interface::AccountInterface;
use miden_lib::account::wallets::BasicWallet;
use miden_lib::errors::tx_kernel_errors::ERR_TX_ALREADY_EXECUTED;
use miden_lib::note::create_p2id_note;
use miden_lib::testing::account_interface::get_public_keys_from_account;
use miden_lib::utils::ScriptBuilder;
use miden_objects::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountStorageMode,
    AccountType,
    AuthSecretKey,
};
use miden_objects::asset::FungibleAsset;
use miden_objects::crypto::dsa::rpo_falcon512::{PublicKey, SecretKey};
use miden_objects::note::NoteType;
use miden_objects::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_objects::transaction::OutputNote;
use miden_objects::vm::AdviceMap;
use miden_objects::{Felt, Hasher, Word};
use miden_processor::AdviceInputs;
use miden_processor::crypto::RpoRandomCoin;
use miden_testing::utils::create_spawn_note;
use miden_testing::{Auth, MockChainBuilder, assert_transaction_executor_error};
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use miden_tx::{
    NoteConsumptionChecker,
    NoteConsumptionStatus,
    TransactionExecutor,
    TransactionExecutorError,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// ================================================================================================
// HELPER FUNCTIONS
// ================================================================================================

type MultisigTestSetup = (Vec<SecretKey>, Vec<PublicKey>, Vec<BasicAuthenticator<ChaCha20Rng>>);

/// Sets up secret keys, public keys, and authenticators for multisig testing
fn setup_keys_and_authenticators(
    num_approvers: usize,
    threshold: usize,
) -> anyhow::Result<MultisigTestSetup> {
    let seed: [u8; 32] = rand::random();
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    let mut authenticators = Vec::new();

    for _ in 0..num_approvers {
        let sec_key = SecretKey::with_rng(&mut rng);
        let pub_key = sec_key.public_key();

        secret_keys.push(sec_key);
        public_keys.push(pub_key);
    }

    // Create authenticators for required signers
    for i in 0..threshold {
        let authenticator = BasicAuthenticator::<ChaCha20Rng>::new_with_rng(
            &[(
                public_keys[i].to_commitment(),
                AuthSecretKey::RpoFalcon512(secret_keys[i].clone()),
            )],
            rng.clone(),
        );
        authenticators.push(authenticator);
    }

    Ok((secret_keys, public_keys, authenticators))
}

/// Creates a multisig account with the specified configuration
fn create_multisig_account(
    threshold: u32,
    public_keys: &[PublicKey],
    asset_amount: u64,
    proc_threshold_map: Vec<(Word, u32)>,
) -> anyhow::Result<Account> {
    let approvers: Vec<_> = public_keys.iter().map(|pk| pk.to_commitment()).collect();

    let multisig_account = AccountBuilder::new([0; 32])
        .with_auth_component(Auth::Multisig { threshold, approvers, proc_threshold_map })
        .with_component(BasicWallet)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_assets(vec![FungibleAsset::mock(asset_amount)])
        .build_existing()?;

    Ok(multisig_account)
}

// ================================================================================================
// TESTS
// ================================================================================================

/// Tests basic 2-of-2 multisig functionality with note creation.
///
/// This test verifies that a multisig account with 2 approvers and threshold 2
/// can successfully execute a transaction that creates an output note when both
/// required signatures are provided.
///
/// **Roles:**
/// - 2 Approvers (multisig signers)
/// - 1 Multisig Contract
#[tokio::test]
async fn test_multisig_2_of_2_with_note_creation() -> anyhow::Result<()> {
    // Setup keys and authenticators
    let (_secret_keys, public_keys, authenticators) = setup_keys_and_authenticators(2, 2)?;

    // Create multisig account
    let multisig_starting_balance = 10u64;
    let mut multisig_account =
        create_multisig_account(2, &public_keys, multisig_starting_balance, vec![])?;

    let output_note_asset = FungibleAsset::mock(0);

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    // Create output note for spawn note
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[output_note_asset],
        NoteType::Public,
    )?;

    // Create spawn note to generate the output note
    let input_note = mock_chain_builder.add_spawn_note([&output_note])?;

    let mut mock_chain = mock_chain_builder.build().unwrap();

    let salt = Word::from([Felt::new(1); 4]);

    // Execute transaction without signatures - should fail
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[input_note.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from both approvers
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment().into(), &tx_summary)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment().into(), &tx_summary)
        .await?;

    // Execute transaction with signatures - should succeed
    let tx_context_execute = mock_chain
        .build_tx_context(multisig_account.id(), &[input_note.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .add_signature(public_keys[0].clone().into(), msg, sig_1)
        .add_signature(public_keys[1].clone().into(), msg, sig_2)
        .auth_args(salt)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_delta(tx_context_execute.account_delta())?;

    mock_chain.add_pending_executed_transaction(&tx_context_execute)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        multisig_account
            .vault()
            .get_balance(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?)?,
        multisig_starting_balance - output_note_asset.unwrap_fungible().amount()
    );

    Ok(())
}

/// Tests 2-of-4 multisig with all possible signer combinations.
///
/// This test verifies that a multisig account with 4 approvers and threshold 2
/// can successfully execute transactions when signed by any 2 of the 4 approvers.
/// It tests all 6 possible combinations of 2 signers to ensure the multisig
/// implementation correctly validates signatures from any valid subset.
///
/// **Tested combinations:** (0,1), (0,2), (0,3), (1,2), (1,3), (2,3)
#[tokio::test]
async fn test_multisig_2_of_4_all_signer_combinations() -> anyhow::Result<()> {
    // Setup keys and authenticators (4 approvers, all 4 can sign)
    let (_secret_keys, public_keys, authenticators) = setup_keys_and_authenticators(4, 4)?;

    // Create multisig account with 4 approvers but threshold of 2
    let multisig_account = create_multisig_account(2, &public_keys, 10, vec![])?;

    let mut mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    // Test different combinations of 2 signers out of 4
    let signer_combinations = [
        (0, 1), // First two
        (0, 2), // First and third
        (0, 3), // First and fourth
        (1, 2), // Second and third
        (1, 3), // Second and fourth
        (2, 3), // Last two
    ];

    for (i, (signer1_idx, signer2_idx)) in signer_combinations.iter().enumerate() {
        let salt = Word::from([Felt::new(10 + i as u64); 4]);

        // Execute transaction without signatures first to get tx summary
        let tx_context_init = mock_chain
            .build_tx_context(multisig_account.id(), &[], &[])?
            .auth_args(salt)
            .build()?;

        let tx_summary = match tx_context_init.execute().await.unwrap_err() {
            TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
            error => panic!("expected abort with tx effects: {error:?}"),
        };

        // Get signatures from the specific combination of signers
        let msg = tx_summary.as_ref().to_commitment();
        let tx_summary = SigningInputs::TransactionSummary(tx_summary);

        let sig_1 = authenticators[*signer1_idx]
            .get_signature(public_keys[*signer1_idx].to_commitment().into(), &tx_summary)
            .await?;
        let sig_2 = authenticators[*signer2_idx]
            .get_signature(public_keys[*signer2_idx].to_commitment().into(), &tx_summary)
            .await?;

        // Execute transaction with signatures - should succeed for any combination
        let tx_context_execute = mock_chain
            .build_tx_context(multisig_account.id(), &[], &[])?
            .auth_args(salt)
            .add_signature(public_keys[*signer1_idx].clone().into(), msg, sig_1)
            .add_signature(public_keys[*signer2_idx].clone().into(), msg, sig_2)
            .build()?;

        let executed_tx = tx_context_execute.execute().await.unwrap_or_else(|_| {
            panic!("Transaction should succeed with signers {signer1_idx} and {signer2_idx}")
        });

        // Apply the transaction to the mock chain for the next iteration
        mock_chain.add_pending_executed_transaction(&executed_tx)?;
        mock_chain.prove_next_block()?;
    }

    Ok(())
}

/// Tests multisig replay protection to prevent transaction re-execution.
///
/// This test verifies that a 2-of-3 multisig account properly prevents replay attacks
/// by rejecting attempts to execute the same transaction twice. The first execution
/// should succeed with valid signatures, but the second attempt with identical
/// parameters should fail with ERR_TX_ALREADY_EXECUTED.
///
/// **Roles:**
/// - 3 Approvers (2 signers required)
/// - 1 Multisig Contract
#[tokio::test]
async fn test_multisig_replay_protection() -> anyhow::Result<()> {
    // Setup keys and authenticators (3 approvers, but only 2 signers)
    let (_secret_keys, public_keys, authenticators) = setup_keys_and_authenticators(3, 2)?;

    // Create 2/3 multisig account
    let multisig_account = create_multisig_account(2, &public_keys, 20, vec![])?;

    let mut mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let salt = Word::from([Felt::new(3); 4]);

    // Execute transaction without signatures first to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from 2 of the 3 approvers
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment().into(), &tx_summary)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment().into(), &tx_summary)
        .await?;

    // Execute transaction with signatures - should succeed (first execution)
    let tx_context_execute = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .add_signature(public_keys[0].clone().into(), msg, sig_1.clone())
        .add_signature(public_keys[1].clone().into(), msg, sig_2.clone())
        .auth_args(salt)
        .build()?;

    let executed_tx = tx_context_execute.execute().await.expect("First transaction should succeed");

    // Apply the transaction to the mock chain
    mock_chain.add_pending_executed_transaction(&executed_tx)?;
    mock_chain.prove_next_block()?;

    // Attempt to execute the same transaction again - should fail due to replay protection
    let tx_context_replay = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .add_signature(public_keys[0].clone().into(), msg, sig_1)
        .add_signature(public_keys[1].clone().into(), msg, sig_2)
        .auth_args(salt)
        .build()?;

    // This should fail due to replay protection
    let result = tx_context_replay.execute().await;
    assert_transaction_executor_error!(result, ERR_TX_ALREADY_EXECUTED);

    Ok(())
}

/// Tests multisig signer update functionality.
///
/// This test verifies that a multisig account can:
/// 1. Execute a transaction script to update signers and threshold
/// 2. Create a second transaction signed by the new owners
/// 3. Properly handle multisig authentication with the updated signers
///
/// **Roles:**
/// - 2 Original Approvers (multisig signers)
/// - 4 New Approvers (updated multisig signers)
/// - 1 Multisig Contract
/// - 1 Transaction Script calling multisig procedures
#[tokio::test]
async fn test_multisig_update_signers() -> anyhow::Result<()> {
    let (_secret_keys, public_keys, authenticators) = setup_keys_and_authenticators(2, 2)?;

    let multisig_account = create_multisig_account(2, &public_keys, 10, vec![])?;

    // SECTION 1: Execute a transaction script to update signers and threshold
    // ================================================================================

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    let output_note_asset = FungibleAsset::mock(0);

    // Create output note for spawn note
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[output_note_asset],
        NoteType::Public,
    )?;

    let mut mock_chain = mock_chain_builder.clone().build().unwrap();

    let salt = Word::from([Felt::new(3); 4]);

    // Setup new signers
    let mut advice_map = AdviceMap::default();
    let (_new_secret_keys, new_public_keys, _new_authenticators) =
        setup_keys_and_authenticators(4, 4)?;

    let threshold = 3u64;
    let num_of_approvers = 4u64;

    // Create vector with threshold config and public keys (4 field elements each)
    let mut config_and_pubkeys_vector = Vec::new();
    config_and_pubkeys_vector.extend_from_slice(&[
        Felt::new(threshold),
        Felt::new(num_of_approvers),
        Felt::new(0),
        Felt::new(0),
    ]);

    // Add each public key to the vector
    for public_key in new_public_keys.iter().rev() {
        let key_word: Word = public_key.to_commitment();
        config_and_pubkeys_vector.extend_from_slice(key_word.as_elements());
    }

    // Hash the vector to create config hash
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);

    // Insert config and public keys into advice map
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);

    // Create a transaction script that calls the update_signers procedure
    let tx_script_code = "
        begin
            call.::update_signers_and_threshold
        end
    ";

    let tx_script = ScriptBuilder::new(true)
        .with_dynamically_linked_library(&rpo_falcon_512_multisig_library())?
        .compile_tx_script(tx_script_code)?;

    let advice_inputs = AdviceInputs {
        map: advice_map.clone(),
        ..Default::default()
    };

    // Pass the MULTISIG_CONFIG_HASH as the tx_script_args
    let tx_script_args: Word = multisig_config_hash;

    // Execute transaction without signatures first to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script.clone())
        .tx_script_args(tx_script_args)
        .extend_advice_inputs(advice_inputs.clone())
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from both approvers
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment().into(), &tx_summary)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment().into(), &tx_summary)
        .await?;

    // Execute transaction with signatures - should succeed
    let update_approvers_tx = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(multisig_config_hash)
        .add_signature(public_keys[0].clone().into(), msg, sig_1)
        .add_signature(public_keys[1].clone().into(), msg, sig_2)
        .auth_args(salt)
        .extend_advice_inputs(advice_inputs)
        .build()?
        .execute()
        .await
        .unwrap();

    // Verify the transaction executed successfully
    assert_eq!(update_approvers_tx.account_delta().nonce_delta(), Felt::new(1));

    mock_chain.add_pending_executed_transaction(&update_approvers_tx)?;
    mock_chain.prove_next_block()?;

    // Apply the delta to get the updated account with new signers
    let mut updated_multisig_account = multisig_account.clone();
    updated_multisig_account.apply_delta(update_approvers_tx.account_delta())?;

    // Verify that the public keys were actually updated in storage
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let storage_key = [Felt::new(i as u64), Felt::new(0), Felt::new(0), Felt::new(0)].into();
        let storage_item = updated_multisig_account.storage().get_map_item(1, storage_key).unwrap();

        let expected_word: Word = expected_key.to_commitment();

        assert_eq!(storage_item, expected_word, "Public key {} doesn't match expected value", i);
    }

    // Verify the threshold was updated by checking storage slot 0
    let threshold_config_storage = updated_multisig_account.storage().get_item(0).unwrap();

    assert_eq!(
        threshold_config_storage[0],
        Felt::new(threshold),
        "Threshold was not updated correctly"
    );
    assert_eq!(
        threshold_config_storage[1],
        Felt::new(num_of_approvers),
        "Num approvers was not updated correctly"
    );

    // Extract public keys using the interface function
    let extracted_pub_keys = get_public_keys_from_account(&updated_multisig_account);

    // Verify that we have the expected number of public keys (4 new ones)
    assert_eq!(
        extracted_pub_keys.len(),
        4,
        "get_public_keys_from_account should return 4 public keys after update"
    );

    // Verify that the extracted public keys match the new ones we set
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let expected_word: Word = expected_key.to_commitment();

        // Find the matching key in extracted keys (order might be different)
        let found_key = extracted_pub_keys.iter().find(|&key| *key == expected_word);

        assert!(
            found_key.is_some(),
            "Public key {} not found in extracted keys: expected {:?}, got {:?}",
            i,
            expected_word,
            extracted_pub_keys
        );
    }

    // SECTION 2: Create a second transaction signed by the new owners
    // ================================================================================

    // Now test creating a note with the new signers
    // Setup authenticators for the new signers (we need 3 out of 4 for threshold 3)
    let mut new_authenticators = Vec::new();
    for i in 0..3 {
        let authenticator = BasicAuthenticator::<ChaCha20Rng>::new_with_rng(
            &[(
                new_public_keys[i].to_commitment(),
                AuthSecretKey::RpoFalcon512(_new_secret_keys[i].clone()),
            )],
            ChaCha20Rng::from_seed([0u8; 32]),
        );
        new_authenticators.push(authenticator);
    }

    // Create a new output note for the second transaction with new signers
    let output_note_new = create_p2id_note(
        updated_multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        vec![output_note_asset],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::empty()),
    )?;

    // Create a new spawn note for the second transaction
    let input_note_new = create_spawn_note([&output_note_new])?;

    let salt_new = Word::from([Felt::new(4); 4]);

    // Build the new mock chain with the updated account and notes
    let mut new_mock_chain_builder =
        MockChainBuilder::with_accounts([updated_multisig_account.clone()]).unwrap();
    new_mock_chain_builder.add_output_note(OutputNote::Full(input_note_new.clone()));
    let new_mock_chain = new_mock_chain_builder.build().unwrap();

    // Execute transaction without signatures first to get tx summary
    let tx_context_init_new = new_mock_chain
        .build_tx_context(updated_multisig_account.id(), &[input_note_new.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .auth_args(salt_new)
        .build()?;

    let tx_summary_new = match tx_context_init_new.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from 3 of the 4 new approvers (threshold is 3)
    let msg_new = tx_summary_new.as_ref().to_commitment();
    let tx_summary_new = SigningInputs::TransactionSummary(tx_summary_new);

    let sig_1_new = new_authenticators[0]
        .get_signature(new_public_keys[0].to_commitment().into(), &tx_summary_new)
        .await?;
    let sig_2_new = new_authenticators[1]
        .get_signature(new_public_keys[1].to_commitment().into(), &tx_summary_new)
        .await?;
    let sig_3_new = new_authenticators[2]
        .get_signature(new_public_keys[2].to_commitment().into(), &tx_summary_new)
        .await?;

    // SECTION 3: Properly handle multisig authentication with the updated signers
    // ================================================================================

    // Execute transaction with new signatures - should succeed
    let tx_context_execute_new = new_mock_chain
        .build_tx_context(updated_multisig_account.id(), &[input_note_new.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_new)])
        .add_signature(new_public_keys[0].clone().into(), msg_new, sig_1_new)
        .add_signature(new_public_keys[1].clone().into(), msg_new, sig_2_new)
        .add_signature(new_public_keys[2].clone().into(), msg_new, sig_3_new)
        .auth_args(salt_new)
        .build()?
        .execute()
        .await?;

    // Verify the transaction executed successfully with new signers
    assert_eq!(tx_context_execute_new.account_delta().nonce_delta(), Felt::new(1));

    Ok(())
}

/// Tests multisig signer update functionality with owner removal.
///
/// This test verifies that a multisig account can:
/// 1. Start with 5 owners and threshold 4
/// 2. Execute a transaction to remove 3 owners (updating to 2 owners)
/// 3. Verify that all removed owners' storage slots are properly cleared
///
/// **Roles:**
/// - 5 Original Approvers (multisig signers, threshold 4)
/// - 2 Updated Approvers (after removing 3 owners)
/// - 1 Multisig Contract
/// - 1 Transaction Script calling multisig procedures
#[tokio::test]
async fn test_multisig_update_signers_remove_owner() -> anyhow::Result<()> {
    // Setup 5 original owners with threshold 4
    let (_secret_keys, public_keys, authenticators) = setup_keys_and_authenticators(5, 5)?;
    let multisig_account = create_multisig_account(4, &public_keys, 10, vec![])?;

    // Build mock chain
    let mock_chain_builder = MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();
    let mut mock_chain = mock_chain_builder.build().unwrap();

    // Setup new signers (remove the last 3 owners, keeping first 2)
    let new_public_keys = &public_keys[0..2];
    let threshold = 1u64;
    let num_of_approvers = 2u64;

    // Create multisig config vector
    let mut config_and_pubkeys_vector =
        vec![Felt::new(threshold), Felt::new(num_of_approvers), Felt::new(0), Felt::new(0)];

    // Add public keys in reverse order
    for public_key in new_public_keys.iter().rev() {
        let key_word: Word = public_key.to_commitment();
        config_and_pubkeys_vector.extend_from_slice(key_word.as_elements());
    }

    // Create config hash and advice map
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);
    let mut advice_map = AdviceMap::default();
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);

    // Create transaction script
    let tx_script = ScriptBuilder::new(true)
        .with_dynamically_linked_library(&rpo_falcon_512_multisig_library())?
        .compile_tx_script("begin\n    call.::update_signers_and_threshold\nend")?;

    let advice_inputs = AdviceInputs { map: advice_map, ..Default::default() };

    let salt = Word::from([Felt::new(3); 4]);

    // Execute without signatures to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script.clone())
        .tx_script_args(multisig_config_hash)
        .extend_advice_inputs(advice_inputs.clone())
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from 4 of the 5 original approvers (threshold is 4)
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment().into(), &tx_summary)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment().into(), &tx_summary)
        .await?;
    let sig_3 = authenticators[2]
        .get_signature(public_keys[2].to_commitment().into(), &tx_summary)
        .await?;
    let sig_4 = authenticators[3]
        .get_signature(public_keys[3].to_commitment().into(), &tx_summary)
        .await?;

    // Execute with signatures
    let update_approvers_tx = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(multisig_config_hash)
        .add_signature(public_keys[0].clone().into(), msg, sig_1)
        .add_signature(public_keys[1].clone().into(), msg, sig_2)
        .add_signature(public_keys[2].clone().into(), msg, sig_3)
        .add_signature(public_keys[3].clone().into(), msg, sig_4)
        .auth_args(salt)
        .extend_advice_inputs(advice_inputs)
        .build()?
        .execute()
        .await
        .unwrap();

    // Verify transaction success
    assert_eq!(update_approvers_tx.account_delta().nonce_delta(), Felt::new(1));

    mock_chain.add_pending_executed_transaction(&update_approvers_tx)?;
    mock_chain.prove_next_block()?;

    // Apply delta to get updated account
    let mut updated_multisig_account = multisig_account.clone();
    updated_multisig_account.apply_delta(update_approvers_tx.account_delta())?;

    // Verify public keys were updated
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let storage_key = [Felt::new(i as u64), Felt::new(0), Felt::new(0), Felt::new(0)].into();
        let storage_item = updated_multisig_account.storage().get_map_item(1, storage_key).unwrap();
        let expected_word: Word = expected_key.to_commitment();
        assert_eq!(storage_item, expected_word, "Public key {} doesn't match", i);
    }

    // Verify threshold and num_approvers
    let threshold_config = updated_multisig_account.storage().get_item(0).unwrap();
    assert_eq!(threshold_config[0], Felt::new(threshold), "Threshold not updated");
    assert_eq!(threshold_config[1], Felt::new(num_of_approvers), "Num approvers not updated");

    // Verify extracted public keys
    let extracted_pub_keys = get_public_keys_from_account(&updated_multisig_account);
    assert_eq!(extracted_pub_keys.len(), 2, "Should have 2 public keys after update");

    for expected_key in new_public_keys.iter() {
        let expected_word: Word = expected_key.to_commitment();
        assert!(
            extracted_pub_keys.contains(&expected_word),
            "Public key not found in extracted keys"
        );
    }

    // Verify removed owners' slots are empty (indices 2, 3, and 4 should be cleared)
    for removed_idx in 2..5 {
        let removed_owner_key =
            [Felt::new(removed_idx), Felt::new(0), Felt::new(0), Felt::new(0)].into();
        let removed_owner_slot =
            updated_multisig_account.storage().get_map_item(1, removed_owner_key).unwrap();
        assert_eq!(
            removed_owner_slot,
            Word::empty(),
            "Removed owner's slot at index {} should be empty",
            removed_idx
        );
    }

    // Verify only 2 non-empty keys remain (at indices 0 and 1)
    let mut non_empty_count = 0;
    for i in 0..5 {
        let storage_key = [Felt::new(i as u64), Felt::new(0), Felt::new(0), Felt::new(0)].into();
        let storage_item = updated_multisig_account.storage().get_map_item(1, storage_key).unwrap();

        if storage_item != Word::empty() {
            non_empty_count += 1;
            assert!(i < 2, "Found non-empty key at index {} which should be removed", i);

            let expected_word: Word = new_public_keys.get(i).unwrap().to_commitment();
            assert_eq!(storage_item, expected_word, "Key at index {} doesn't match", i);
        }
    }
    assert_eq!(
        non_empty_count, 2,
        "Should have exactly 2 non-empty keys after removing 3 owners"
    );

    Ok(())
}

/// Tests that newly added approvers cannot sign transactions before the signer update is executed.
///
/// This is a regression test to ensure that unauthorized parties cannot add their own public keys
/// to the multisig configuration and immediately use them to sign transactions before
/// the current approvers have validated and executed the signer update.
///
/// **Test Flow:**
/// 1. Create a multisig account with 2 original approvers
/// 2. Prepare a signer update transaction with new approvers
/// 3. Try to sign the transaction with the NEW approvers (should fail)
/// 4. Verify that only the CURRENT approvers can sign the update transaction
#[tokio::test]
async fn test_multisig_new_approvers_cannot_sign_before_update() -> anyhow::Result<()> {
    // SECTION 1: Create a multisig account with 2 original approvers
    // ================================================================================

    let (_secret_keys, public_keys, _authenticators) = setup_keys_and_authenticators(2, 2)?;

    let multisig_account = create_multisig_account(2, &public_keys, 10, vec![])?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let salt = Word::from([Felt::new(5); 4]);

    // SECTION 2: Prepare a signer update transaction with new approvers
    // ================================================================================

    // Get the multisig library

    // Setup new signers (these should NOT be able to sign the update transaction)
    let mut advice_map = AdviceMap::default();
    let (_new_secret_keys, new_public_keys, new_authenticators) =
        setup_keys_and_authenticators(4, 4)?;

    let threshold = 3u64;
    let num_of_approvers = 4u64;

    // Create vector with threshold config and public keys (4 field elements each)
    let mut config_and_pubkeys_vector = Vec::new();
    config_and_pubkeys_vector.extend_from_slice(&[
        Felt::new(threshold),
        Felt::new(num_of_approvers),
        Felt::new(0),
        Felt::new(0),
    ]);

    // Add each public key to the vector
    for public_key in new_public_keys.iter().rev() {
        let key_word: Word = public_key.to_commitment();
        config_and_pubkeys_vector.extend_from_slice(key_word.as_elements());
    }

    // Hash the vector to create config hash
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);

    // Insert config and public keys into advice map
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);

    // Create a transaction script that calls the update_signers procedure
    let tx_script_code = "
        begin
            call.::update_signers_and_threshold
        end
    ";

    let tx_script = ScriptBuilder::new(true)
        .with_dynamically_linked_library(&rpo_falcon_512_multisig_library())?
        .compile_tx_script(tx_script_code)?;

    let advice_inputs = AdviceInputs {
        map: advice_map.clone(),
        ..Default::default()
    };

    // Pass the MULTISIG_CONFIG_HASH as the tx_script_args
    let tx_script_args: Word = multisig_config_hash;

    // Execute transaction without signatures first to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script.clone())
        .tx_script_args(tx_script_args)
        .extend_advice_inputs(advice_inputs.clone())
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // SECTION 3: Try to sign the transaction with the NEW approvers (should fail)
    // ================================================================================

    // Get signatures from the NEW approvers (these should NOT work)
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary.clone());

    let new_sig_1 = new_authenticators[0]
        .get_signature(new_public_keys[0].to_commitment().into(), &tx_summary_signing)
        .await?;
    let new_sig_2 = new_authenticators[1]
        .get_signature(new_public_keys[1].to_commitment().into(), &tx_summary_signing)
        .await?;

    // Try to execute transaction with NEW signatures - should FAIL
    let tx_context_with_new_sigs = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script.clone())
        .tx_script_args(multisig_config_hash)
        .add_signature(new_public_keys[0].clone().into(), msg, new_sig_1)
        .add_signature(new_public_keys[1].clone().into(), msg, new_sig_2)
        .auth_args(salt)
        .extend_advice_inputs(advice_inputs.clone())
        .build()?;

    // SECTION 4: Verify that only the CURRENT approvers can sign the update transaction
    // ================================================================================

    // Should fail - new approvers not yet authorized
    let result = tx_context_with_new_sigs.execute().await;

    // Assert that the transaction fails as expected
    assert!(
        result.is_err(),
        "Transaction should fail when signed by unauthorized new approvers"
    );

    Ok(())
}

#[tokio::test]
async fn test_check_note_consumability_multisig() -> anyhow::Result<()> {
    // Setup keys and authenticators
    let (_secret_keys, public_keys, authenticators) = setup_keys_and_authenticators(2, 2)?;

    // Create multisig account
    let multisig_account = create_multisig_account(2, &public_keys, 10, vec![])?;

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    let p2id_note = mock_chain_builder.add_p2id_note(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        multisig_account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;
    let mock_chain = mock_chain_builder.build().unwrap();

    let salt = Word::from([Felt::new(1); 4]);

    // get the transaction context without signatures
    let tx_context_without_signatures = mock_chain
        .build_tx_context(multisig_account.id(), &[p2id_note.id()], &[])?
        .auth_args(salt)
        .build()?;

    let block_ref = tx_context_without_signatures.tx_inputs().block_header().block_num();
    let tx_args = tx_context_without_signatures.tx_args();
    let tx_executor = TransactionExecutor::<'_, '_, _, BasicAuthenticator<ChaCha20Rng>>::new(
        &tx_context_without_signatures,
    );

    let notes_checker = NoteConsumptionChecker::new(&tx_executor);

    // this check should return `ConsumableWithAuthorization` variant: the note is consumable, but
    // authentication is failing
    let consumable_with_authorization = notes_checker
        .can_consume(
            multisig_account.id(),
            block_ref,
            miden_objects::transaction::InputNote::Unauthenticated { note: p2id_note.clone() },
            tx_args.clone(),
        )
        .await?;
    assert_matches!(
        consumable_with_authorization,
        NoteConsumptionStatus::ConsumableWithAuthorization
    );

    // execute the transaction to get the summary
    let tx_summary = match tx_context_without_signatures.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };
    // Get signatures from both approvers
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment().into(), &tx_summary)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment().into(), &tx_summary)
        .await?;

    // get the transaction context with signatures
    let tx_context_with_signatures = mock_chain
        .build_tx_context(multisig_account.id(), &[p2id_note.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(p2id_note)])
        .add_signature(public_keys[0].clone().into(), msg, sig_1)
        .add_signature(public_keys[1].clone().into(), msg, sig_2)
        .auth_args(salt)
        .build()?;

    let block_num = tx_context_with_signatures.tx_inputs().block_header().block_num();
    let notes = tx_context_with_signatures.tx_inputs().input_notes().clone();
    let tx_args = tx_context_with_signatures.tx_args().clone();

    let mut tx_executor = TransactionExecutor::new(&tx_context_with_signatures)
        .with_source_manager(tx_context_with_signatures.source_manager());
    if let Some(authenticator) = tx_context_with_signatures.authenticator() {
        tx_executor = tx_executor.with_authenticator(authenticator);
    }

    let notes_checker = NoteConsumptionChecker::new(&tx_executor);

    // this check should return `Consumable` variant: we provided the signatures, so the transaction
    // should execute successfully.
    let consumable_with_authorization = notes_checker
        .can_consume(multisig_account.id(), block_num, notes.get_note(0).clone(), tx_args)
        .await?;
    assert_matches!(consumable_with_authorization, NoteConsumptionStatus::Consumable);

    Ok(())
}

/// Tests that 1-of-2 approvers can consume a note but 2-of-2 are required to send a note.
///
/// This test verifies that a multisig account with 2 approvers and threshold 2, but a procedure
/// threshold of 1 for note consumption, can:
/// 1. Consume a note when only one approver signs the transaction
/// 2. Send a note only when both approvers sign the transaction (default threshold)
#[tokio::test]
async fn test_multisig_proc_threshold_overrides() -> anyhow::Result<()> {
    // Setup keys and authenticators
    let (_secret_keys, public_keys, authenticators) = setup_keys_and_authenticators(2, 2)?;

    let proc_threshold_map = vec![(BasicWallet::receive_asset_digest(), 1)];

    // Create multisig account
    let multisig_starting_balance = 10u64;
    let mut multisig_account =
        create_multisig_account(2, &public_keys, multisig_starting_balance, proc_threshold_map)?;

    // SECTION 1: Test note consumption with 1 signature
    // ================================================================================

    // 1. create a mock note from some random account
    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    let note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        multisig_account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;

    let mut mock_chain = mock_chain_builder.build()?;

    // 2. consume without signatures
    let salt = Word::from([Felt::new(1); 4]);
    let tx_context = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_summary) => tx_summary,
        error => panic!("expected abort with tx summary: {error:?}"),
    };

    // 3. get signature from one approver
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary.clone());
    let sig = authenticators[0]
        .get_signature(public_keys[0].to_commitment().into(), &tx_summary_signing)
        .await?;

    // 4. execute with signature
    let tx_result = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .add_signature(public_keys[0].clone().into(), msg, sig)
        .auth_args(salt)
        .build()?
        .execute()
        .await;

    assert!(tx_result.is_ok(), "Note consumption with 1 signature should succeed");

    // Apply the transaction to the account
    multisig_account.apply_delta(tx_result.as_ref().unwrap().account_delta())?;
    mock_chain.add_pending_executed_transaction(&tx_result.unwrap())?;
    mock_chain.prove_next_block()?;

    // SECTION 2: Test note sending requires 2 signatures
    // ================================================================================

    let salt2 = Word::from([Felt::new(2); 4]);

    // Create output note to send 5 units from the account
    let output_note = create_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        vec![FungibleAsset::mock(5)],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([Felt::new(42); 4])),
    )?;
    let multisig_account_interface = AccountInterface::from(&multisig_account);
    let send_note_transaction_script = multisig_account_interface.build_send_notes_script(
        &[output_note.clone().into()],
        None,
        false,
    )?;

    // Execute transaction without signatures to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .tx_script(send_note_transaction_script.clone())
        .auth_args(salt2)
        .build()?;

    let tx_summary2 = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };
    // Get signature from only ONE approver
    let msg2 = tx_summary2.as_ref().to_commitment();
    let tx_summary2_signing = SigningInputs::TransactionSummary(tx_summary2.clone());

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment().into(), &tx_summary2_signing)
        .await?;

    // Try to execute with only 1 signature - should FAIL
    let tx_context_one_sig = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .add_signature(public_keys[0].clone().into(), msg2, sig_1)
        .tx_script(send_note_transaction_script.clone())
        .auth_args(salt2)
        .build()?;

    let result = tx_context_one_sig.execute().await;
    match result {
        Err(TransactionExecutorError::Unauthorized(_)) => {
            // Expected: transaction should fail with insufficient signatures
        },
        _ => panic!(
            "Transaction should fail with Unauthorized error when only 1 signature provided for note sending"
        ),
    }

    // Now get signatures from BOTH approvers
    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment().into(), &tx_summary2_signing)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment().into(), &tx_summary2_signing)
        .await?;

    // Execute with 2 signatures - should SUCCEED
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .add_signature(public_keys[0].clone().into(), msg2, sig_1)
        .add_signature(public_keys[1].clone().into(), msg2, sig_2)
        .auth_args(salt2)
        .tx_script(send_note_transaction_script)
        .build()?
        .execute()
        .await;

    assert!(result.is_ok(), "Transaction should succeed with 2 signatures for note sending");

    // Apply the transaction to the account
    multisig_account.apply_delta(result.as_ref().unwrap().account_delta())?;
    mock_chain.add_pending_executed_transaction(&result.unwrap())?;
    mock_chain.prove_next_block()?;

    assert_eq!(multisig_account.vault().get_balance(FungibleAsset::mock_issuer())?, 6);

    Ok(())
}
