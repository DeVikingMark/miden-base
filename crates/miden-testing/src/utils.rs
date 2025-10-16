use alloc::string::String;
use alloc::vec::Vec;

use miden_lib::testing::note::NoteBuilder;
use miden_lib::transaction::TransactionKernel;
use miden_objects::account::AccountId;
use miden_objects::asset::Asset;
use miden_objects::crypto::rand::FeltRng;
use miden_objects::note::{Note, NoteType};
use miden_objects::testing::storage::prepare_assets;
use miden_processor::Felt;
use miden_processor::crypto::RpoRandomCoin;
use rand::SeedableRng;
use rand::rngs::SmallRng;

// HELPER MACROS
// ================================================================================================

#[macro_export]
macro_rules! assert_execution_error {
    ($execution_result:expr, $expected_err:expr) => {
        match $execution_result {
            Err(miden_processor::ExecutionError::FailedAssertion { label: _, source_file: _, clk: _, err_code, err_msg }) => {
                if let Some(ref msg) = err_msg {
                  assert_eq!(msg.as_ref(), $expected_err.message(), "error messages did not match");
                }

                assert_eq!(
                    err_code, $expected_err.code(),
                    "Execution failed on assertion with an unexpected error (Actual code: {}, msg: {}, Expected code: {}).",
                    err_code, err_msg.as_ref().map(|string| string.as_ref()).unwrap_or("<no message>"), $expected_err,
                );
            },
            Ok(_) => panic!("Execution was unexpectedly successful"),
            Err(err) => panic!("Execution error was not as expected: {err}"),
        }
    };
}

#[macro_export]
macro_rules! assert_transaction_executor_error {
    ($execution_result:expr, $expected_err:expr) => {
        match $execution_result {
            Err(miden_tx::TransactionExecutorError::TransactionProgramExecutionFailed(
                miden_processor::ExecutionError::FailedAssertion {
                    label: _,
                    source_file: _,
                    clk: _,
                    err_code,
                    err_msg,
                },
            )) => {
                if let Some(ref msg) = err_msg {
                  assert_eq!(msg.as_ref(), $expected_err.message(), "error messages did not match");
                }

                assert_eq!(
                  err_code, $expected_err.code(),
                  "Execution failed on assertion with an unexpected error (Actual code: {}, msg: {}, Expected: {}).",
                  err_code, err_msg.as_ref().map(|string| string.as_ref()).unwrap_or("<no message>"), $expected_err);
            },
            Ok(_) => panic!("Execution was unexpectedly successful"),
            Err(err) => panic!("Execution error was not as expected: {err}"),
        }
    };
}

// HELPER NOTES
// ================================================================================================

/// Creates a public `P2ANY` note.
///
/// A `P2ANY` note carries `assets` and a script that moves the assets into the executing account's
/// vault.
///
/// The created note does not require authentication and can be consumed by any account.
pub fn create_public_p2any_note(
    sender: AccountId,
    assets: impl IntoIterator<Item = Asset>,
) -> Note {
    let mut rng = RpoRandomCoin::new(Default::default());
    create_p2any_note(sender, NoteType::Public, assets, &mut rng)
}

/// Creates a `P2ANY` note.
///
/// A `P2ANY` note carries `assets` and a script that moves the assets into the executing account's
/// vault.
///
/// The created note does not require authentication and can be consumed by any account.
pub fn create_p2any_note(
    sender: AccountId,
    note_type: NoteType,
    assets: impl IntoIterator<Item = Asset>,
    rng: &mut RpoRandomCoin,
) -> Note {
    let serial_number = rng.draw_word();
    let assets: Vec<_> = assets.into_iter().collect();
    let mut code_body = String::new();
    for i in 0..assets.len() {
        if i == 0 {
            // first asset (dest_ptr is already on stack)
            code_body.push_str(
                "
                # add first asset

                padw dup.4 mem_loadw
                padw swapw padw padw swapdw
                call.wallet::receive_asset
                dropw movup.12
                # => [dest_ptr, pad(12)]
                ",
            );
        } else {
            code_body.push_str(
                "
                # add next asset

                add.4 dup movdn.13
                padw movup.4 mem_loadw
                call.wallet::receive_asset
                dropw movup.12
                # => [dest_ptr, pad(12)]",
            );
        }
    }
    code_body.push_str("dropw dropw dropw dropw");

    let code = format!(
        "
        use.mock::account
        use.miden::active_note
        use.miden::contracts::wallets::basic->wallet

        begin
            # fetch pointer & number of assets
            push.0 exec.active_note::get_assets     # [num_assets, dest_ptr]

            # runtime-check we got the expected count
            push.{num_assets} assert_eq             # [dest_ptr]

            {code_body}
            dropw dropw dropw dropw
        end
        ",
        num_assets = assets.len(),
    );

    NoteBuilder::new(sender, SmallRng::from_seed([0; 32]))
        .add_assets(assets.iter().copied())
        .note_type(note_type)
        .serial_number(serial_number)
        .code(code)
        .dynamically_linked_libraries(TransactionKernel::mock_libraries())
        .build()
        .expect("generated note script should compile")
}

/// Creates a `SPAWN` note.
///
///  A `SPAWN` note contains a note script that creates all `output_notes` that get passed as a
///  parameter.
///
/// # Errors
///
/// Returns an error if:
/// - the sender account ID of the provided output notes is not consistent or does not match the
///   transaction's sender.
pub fn create_spawn_note<'note, I>(
    output_notes: impl IntoIterator<Item = &'note Note, IntoIter = I>,
) -> anyhow::Result<Note>
where
    I: ExactSizeIterator<Item = &'note Note>,
{
    let mut output_notes = output_notes.into_iter().peekable();
    if output_notes.len() == 0 {
        anyhow::bail!("at least one output note is needed to create a SPAWN note");
    }

    let sender_id = output_notes
        .peek()
        .expect("at least one output note should be present")
        .metadata()
        .sender();

    let note_code = note_script_that_creates_notes(sender_id, output_notes)?;

    let note = NoteBuilder::new(sender_id, SmallRng::from_os_rng())
        .code(note_code)
        .dynamically_linked_libraries(TransactionKernel::mock_libraries())
        .build()?;

    Ok(note)
}

/// Returns the code for a note that creates all notes in `output_notes`
fn note_script_that_creates_notes<'note>(
    sender_id: AccountId,
    output_notes: impl Iterator<Item = &'note Note>,
) -> anyhow::Result<String> {
    let mut out = String::from("use.miden::output_note\n\nbegin\n");

    for (idx, note) in output_notes.into_iter().enumerate() {
        anyhow::ensure!(
            note.metadata().sender() == sender_id,
            "sender IDs of output notes passed to SPAWN note are inconsistent"
        );

        // Make sure that the transaction's native account matches the note sender.
        out.push_str(&format!(
            r#"exec.::miden::account::get_native_id
             # => [native_account_id_prefix, native_account_id_suffix]
             push.{sender_prefix} assert_eq.err="sender ID prefix does not match native account ID's prefix"
             # => [native_account_id_suffix]
             push.{sender_suffix} assert_eq.err="sender ID suffix does not match native account ID's suffix"
             # => []
        "#,
          sender_prefix = sender_id.prefix().as_felt(),
          sender_suffix = sender_id.suffix()
        ));

        if idx == 0 {
            out.push_str("padw padw\n");
        } else {
            out.push_str("dropw dropw dropw\n");
        }
        out.push_str(&format!(
            "
            push.{recipient}
            push.{hint}
            push.{note_type}
            push.{aux}
            push.{tag}
            call.output_note::create\n",
            recipient = note.recipient().digest(),
            hint = Felt::from(note.metadata().execution_hint()),
            note_type = note.metadata().note_type() as u8,
            aux = note.metadata().aux(),
            tag = note.metadata().tag(),
        ));

        let assets_str = prepare_assets(note.assets());
        for asset in assets_str {
            out.push_str(&format!(
                " push.{asset}
                  call.::miden::contracts::wallets::basic::move_asset_to_note\n",
            ));
        }
    }

    out.push_str("repeat.5 dropw end\nend");

    Ok(out)
}
