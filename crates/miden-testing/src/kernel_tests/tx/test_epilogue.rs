use alloc::string::ToString;
use alloc::vec::Vec;

use miden_lib::errors::tx_kernel_errors::{
    ERR_ACCOUNT_DELTA_NONCE_MUST_BE_INCREMENTED_IF_VAULT_OR_STORAGE_CHANGED,
    ERR_EPILOGUE_EXECUTED_TRANSACTION_IS_EMPTY,
    ERR_EPILOGUE_TOTAL_NUMBER_OF_ASSETS_MUST_STAY_THE_SAME,
    ERR_TX_INVALID_EXPIRATION_DELTA,
};
use miden_lib::testing::mock_account::MockAccountExt;
use miden_lib::testing::note::NoteBuilder;
use miden_lib::transaction::EXPIRATION_BLOCK_ELEMENT_IDX;
use miden_lib::transaction::memory::{
    NOTE_MEM_SIZE,
    OUTPUT_NOTE_ASSET_COMMITMENT_OFFSET,
    OUTPUT_NOTE_SECTION_OFFSET,
};
use miden_lib::utils::ScriptBuilder;
use miden_objects::Word;
use miden_objects::account::{Account, AccountDelta, AccountStorageDelta, AccountVaultDelta};
use miden_objects::asset::{Asset, FungibleAsset};
use miden_objects::note::{NoteTag, NoteType};
use miden_objects::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_objects::transaction::{OutputNote, OutputNotes};
use miden_processor::{Felt, ONE};

use super::{ZERO, create_mock_notes_procedure};
use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::utils::{create_public_p2any_note, create_spawn_note};
use crate::{
    Auth,
    MockChain,
    TransactionContextBuilder,
    TxContextInput,
    assert_execution_error,
    assert_transaction_executor_error,
};

#[test]
fn test_epilogue() -> anyhow::Result<()> {
    let account = Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
    let tx_context = {
        let output_note_1 = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::mock(100)],
        );

        // input_note_1 is needed for maintaining cohesion of involved assets
        let input_note_1 = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::mock(100)],
        );
        let input_note_2 = create_spawn_note([&output_note_1])?;
        TransactionContextBuilder::new(account.clone())
            .extend_input_notes(vec![input_note_1, input_note_2])
            .extend_expected_output_notes(vec![OutputNote::Full(output_note_1)])
            .build()?
    };

    let output_notes_data_procedure =
        create_mock_notes_procedure(tx_context.expected_output_notes());

    let code = format!(
        "
        use.$kernel::prologue
        use.$kernel::account
        use.$kernel::epilogue

        {output_notes_data_procedure}

        begin
            exec.prologue::prepare_transaction

            exec.create_mock_notes

            exec.epilogue::finalize_transaction

            # truncate the stack
            repeat.13 movup.13 drop end
        end
        "
    );

    let exec_output = tx_context.execute_code_blocking(&code)?;

    // The final account is the initial account with the nonce incremented by one.
    let mut final_account = account.clone();
    final_account.increment_nonce(ONE)?;

    let output_notes = OutputNotes::new(
        tx_context
            .expected_output_notes()
            .iter()
            .cloned()
            .map(OutputNote::Full)
            .collect(),
    )?;

    let account_delta_commitment = AccountDelta::new(
        tx_context.account().id(),
        AccountStorageDelta::default(),
        AccountVaultDelta::default(),
        ONE,
    )?
    .to_commitment();

    let account_update_commitment =
        miden_objects::Hasher::merge(&[final_account.commitment(), account_delta_commitment]);

    let mut expected_stack = Vec::with_capacity(16);
    expected_stack.extend(output_notes.commitment().as_elements().iter().rev());
    expected_stack.extend(account_update_commitment.as_elements().iter().rev());
    expected_stack.extend(
        Word::from(
            FungibleAsset::new(
                tx_context.tx_inputs().block_header().fee_parameters().native_asset_id(),
                0,
            )
            .unwrap(),
        )
        .iter()
        .rev(),
    );
    expected_stack.push(Felt::from(u32::MAX)); // Value for tx expiration block number
    expected_stack.extend((13..16).map(|_| ZERO));

    assert_eq!(
        exec_output.stack.as_slice(),
        expected_stack.as_slice(),
        "Stack state after finalize_transaction does not contain the expected values"
    );

    assert_eq!(
        exec_output.stack.len(),
        16,
        "The stack must be truncated to 16 elements after finalize_transaction"
    );
    Ok(())
}

#[test]
fn test_compute_output_note_id() -> anyhow::Result<()> {
    let tx_context = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let output_note_1 =
            create_public_p2any_note(ACCOUNT_ID_SENDER.try_into()?, [FungibleAsset::mock(100)]);

        // input_note_1 is needed for maintaining cohesion of involved assets
        let input_note_1 =
            create_public_p2any_note(ACCOUNT_ID_SENDER.try_into()?, [FungibleAsset::mock(100)]);
        let input_note_2 = create_spawn_note([&output_note_1])?;
        TransactionContextBuilder::new(account)
            .extend_input_notes(vec![input_note_1, input_note_2])
            .extend_expected_output_notes(vec![OutputNote::Full(output_note_1)])
            .build()?
    };

    let output_notes_data_procedure =
        create_mock_notes_procedure(tx_context.expected_output_notes());

    for (note, i) in tx_context.expected_output_notes().iter().zip(0u32..) {
        let code = format!(
            "
            use.$kernel::prologue
            use.$kernel::epilogue

            {output_notes_data_procedure}

            begin
                exec.prologue::prepare_transaction
                exec.create_mock_notes
                exec.epilogue::finalize_transaction

                # truncate the stack
                repeat.13 movup.13 drop end
            end
            "
        );

        let exec_output = &tx_context.execute_code_blocking(&code)?;

        assert_eq!(
            note.assets().commitment(),
            exec_output.get_kernel_mem_word(
                OUTPUT_NOTE_SECTION_OFFSET
                    + i * NOTE_MEM_SIZE
                    + OUTPUT_NOTE_ASSET_COMMITMENT_OFFSET
            ),
            "ASSET_COMMITMENT didn't match expected value",
        );

        assert_eq!(
            Word::from(note.id()),
            exec_output.get_kernel_mem_word(OUTPUT_NOTE_SECTION_OFFSET + i * NOTE_MEM_SIZE),
            "NOTE_ID didn't match expected value",
        );
    }
    Ok(())
}

/// Tests that a transaction fails due to the asset preservation rules when the input note has an
/// asset with amount 100 and the output note has the same asset with amount 200.
#[tokio::test]
async fn epilogue_fails_when_num_output_assets_exceed_num_input_assets() -> anyhow::Result<()> {
    // Create an input asset with amount 100 and an output asset with amount 200.
    let input_asset = FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?, 100)?;
    let output_asset = input_asset.add(input_asset)?;

    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    // Add an input note that (automatically) adds its assets to the transaction's input vault, but
    // _does not_ add the asset to the account. This is just to keep the test conceptually simple -
    // there is no account involved.
    let input_note = NoteBuilder::new(account.id(), *builder.rng_mut())
        .add_assets([Asset::from(input_asset)])
        .build()?;
    builder.add_output_note(OutputNote::Full(input_note.clone()));
    let mock_chain = builder.build()?;

    let code = format!(
        "
      use.mock::account
      use.mock::util

      begin
          # create a note with the output asset
          push.{OUTPUT_ASSET}
          exec.util::create_random_note_with_asset drop
          # => []
      end
      ",
        OUTPUT_ASSET = Word::from(output_asset),
    );

    let builder = ScriptBuilder::with_mock_libraries()?;
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;

    let tx_context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[input_note])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    let exec_output = tx_context.execute().await;
    assert_transaction_executor_error!(
        exec_output,
        ERR_EPILOGUE_TOTAL_NUMBER_OF_ASSETS_MUST_STAY_THE_SAME
    );

    Ok(())
}

/// Tests that a transaction fails due to the asset preservation rules when the input note has an
/// asset with amount 200 and the output note has the same asset with amount 100.
#[tokio::test]
async fn epilogue_fails_when_num_input_assets_exceed_num_output_assets() -> anyhow::Result<()> {
    // Create an input asset with amount 200 and an output asset with amount 100.
    let output_asset = FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?, 100)?;
    let input_asset = output_asset.add(output_asset)?;

    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    // Add an input note that (automatically) adds its assets to the transaction's input vault, but
    // _does not_ add the asset to the account. This is just to keep the test conceptually simple -
    // there is no account involved.
    let input_note = NoteBuilder::new(account.id(), *builder.rng_mut())
        .add_assets([Asset::from(output_asset)])
        .build()?;
    builder.add_output_note(OutputNote::Full(input_note.clone()));
    let mock_chain = builder.build()?;

    let code = format!(
        "
      use.mock::account
      use.mock::util

      begin
          # create a note with the output asset
          push.{OUTPUT_ASSET}
          exec.util::create_random_note_with_asset drop
          # => []
      end
      ",
        OUTPUT_ASSET = Word::from(input_asset),
    );

    let builder = ScriptBuilder::with_mock_libraries()?;
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;

    let tx_context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[input_note])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    let exec_output = tx_context.execute().await;
    assert_transaction_executor_error!(
        exec_output,
        ERR_EPILOGUE_TOTAL_NUMBER_OF_ASSETS_MUST_STAY_THE_SAME
    );

    Ok(())
}

#[test]
fn test_block_expiration_height_monotonically_decreases() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let test_pairs: [(u64, u64); 3] = [(9, 12), (18, 3), (20, 20)];
    let code_template = "
        use.$kernel::prologue
        use.$kernel::tx
        use.$kernel::epilogue
        use.$kernel::account

        begin
            exec.prologue::prepare_transaction
            push.{value_1}
            exec.tx::update_expiration_block_delta
            push.{value_2}
            exec.tx::update_expiration_block_delta

            push.{min_value} exec.tx::get_expiration_delta assert_eq

            exec.epilogue::finalize_transaction

            # truncate the stack
            repeat.13 movup.13 drop end
        end
        ";

    for (v1, v2) in test_pairs {
        let code = &code_template
            .replace("{value_1}", &v1.to_string())
            .replace("{value_2}", &v2.to_string())
            .replace("{min_value}", &v2.min(v1).to_string());

        let exec_output = &tx_context.execute_code_blocking(code)?;

        // Expiry block should be set to transaction's block + the stored expiration delta
        // (which can only decrease, not increase)
        let expected_expiry =
            v1.min(v2) + tx_context.tx_inputs().block_header().block_num().as_u64();
        assert_eq!(
            exec_output.get_stack_element(EXPIRATION_BLOCK_ELEMENT_IDX).as_int(),
            expected_expiry
        );
    }

    Ok(())
}

#[test]
fn test_invalid_expiration_deltas() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let test_values = [0u64, u16::MAX as u64 + 1, u32::MAX as u64];
    let code_template = "
        use.$kernel::tx

        begin
            push.{value_1}
            exec.tx::update_expiration_block_delta
        end
        ";

    for value in test_values {
        let code = &code_template.replace("{value_1}", &value.to_string());
        let exec_output = tx_context.execute_code_blocking(code);

        assert_execution_error!(exec_output, ERR_TX_INVALID_EXPIRATION_DELTA);
    }

    Ok(())
}

#[test]
fn test_no_expiration_delta_set() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let code_template = "
    use.$kernel::prologue
    use.$kernel::epilogue
    use.$kernel::tx
    use.$kernel::account

    begin
        exec.prologue::prepare_transaction

        exec.tx::get_expiration_delta assertz

        exec.epilogue::finalize_transaction

        # truncate the stack
        repeat.13 movup.13 drop end
    end
    ";

    let exec_output = &tx_context.execute_code_blocking(code_template)?;

    // Default value should be equal to u32::MAX, set in the prologue
    assert_eq!(
        exec_output.get_stack_element(EXPIRATION_BLOCK_ELEMENT_IDX).as_int() as u32,
        u32::MAX
    );

    Ok(())
}

#[test]
fn test_epilogue_increment_nonce_success() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let expected_nonce = ONE + ONE;

    let code = format!(
        "
        use.$kernel::prologue
        use.mock::account
        use.$kernel::epilogue
        use.$kernel::memory

        begin
            exec.prologue::prepare_transaction

            push.1.2.3.4
            push.0
            call.account::set_item
            dropw

            exec.epilogue::finalize_transaction

            # clean the stack
            dropw dropw dropw dropw

            exec.memory::get_account_nonce
            push.{expected_nonce} assert_eq
        end
        "
    );

    tx_context.execute_code_blocking(code.as_str())?;
    Ok(())
}

/// Tests that changing the account state without incrementing the nonce results in an error.
#[tokio::test]
async fn epilogue_fails_on_account_state_change_without_nonce_increment() -> anyhow::Result<()> {
    let code = "
        use.mock::account

        begin
            push.91.92.93.94
            push.0
            repeat.5 movup.5 drop end
            # => [index, VALUE]
            call.account::set_item
            # => [PREV_VALUE]
            dropw
        end
        ";

    let tx_script = ScriptBuilder::with_mock_libraries()?.compile_tx_script(code)?;

    let result = TransactionContextBuilder::with_noop_auth_account()
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_ACCOUNT_DELTA_NONCE_MUST_BE_INCREMENTED_IF_VAULT_OR_STORAGE_CHANGED
    );

    Ok(())
}

#[tokio::test]
async fn test_epilogue_execute_empty_transaction() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_noop_auth_account().build()?;

    let result = tx_context.execute().await;

    assert_transaction_executor_error!(result, ERR_EPILOGUE_EXECUTED_TRANSACTION_IS_EMPTY);

    Ok(())
}

#[test]
fn test_epilogue_empty_transaction_with_empty_output_note() -> anyhow::Result<()> {
    let tag =
        NoteTag::from_account_id(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?);
    let aux = Felt::new(26);
    let note_type = NoteType::Private;

    // create an empty output note in the transaction script
    let tx_script_source = format!(
        r#"
        use.std::word
        use.miden::output_note
        use.$kernel::prologue
        use.$kernel::epilogue
        use.$kernel::note

        begin
            exec.prologue::prepare_transaction

            # prepare the values for note creation
            push.1.2.3.4      # recipient
            push.1            # note_execution_hint (NoteExecutionHint::Always)
            push.{note_type}  # note_type
            push.{aux}        # aux
            push.{tag}        # tag
            # => [tag, aux, note_type, note_execution_hint, RECIPIENT]

            # pad the stack with zeros before calling the `create_note`.
            padw padw swapdw
            # => [tag, aux, execution_hint, note_type, RECIPIENT, pad(8)]

            # create the note
            call.output_note::create
            # => [note_idx, GARBAGE(15)]

            # make sure that output note was created: compare the output note hash with an empty
            # word
            exec.note::compute_output_notes_commitment
            exec.word::eqz assertz.err="output note was created, but the output notes hash remains to be zeros"
            # => [note_idx, GARBAGE(15)]

            # clean the stack
            dropw dropw dropw dropw
            # => []

            exec.epilogue::finalize_transaction
        end
    "#,
        note_type = note_type as u8,
    );

    let tx_context = TransactionContextBuilder::with_noop_auth_account().build()?;

    let result = tx_context.execute_code_blocking(&tx_script_source).map(|_| ());

    // assert that even if the output note was created, the transaction is considered empty
    assert_execution_error!(result, ERR_EPILOGUE_EXECUTED_TRANSACTION_IS_EMPTY);

    Ok(())
}
