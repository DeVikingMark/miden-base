use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use assert_matches::assert_matches;
use miden_objects::account::{
    AccountBuilder,
    AccountComponent,
    AccountType,
    PublicKeyCommitment,
    StorageSlot,
};
use miden_objects::assembly::diagnostics::NamedSource;
use miden_objects::assembly::{Assembler, DefaultSourceManager};
use miden_objects::asset::{FungibleAsset, NonFungibleAsset, TokenSymbol};
use miden_objects::crypto::rand::{FeltRng, RpoRandomCoin};
use miden_objects::note::{
    Note,
    NoteAssets,
    NoteExecutionHint,
    NoteInputs,
    NoteMetadata,
    NoteRecipient,
    NoteTag,
    NoteType,
};
use miden_objects::testing::account_id::{
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
};
use miden_objects::{AccountError, Felt, NoteError, Word, ZERO};

use crate::AuthScheme;
use crate::account::auth::{
    AuthRpoFalcon512,
    AuthRpoFalcon512Multisig,
    AuthRpoFalcon512MultisigConfig,
    NoAuth,
};
use crate::account::faucets::BasicFungibleFaucet;
use crate::account::interface::{
    AccountComponentInterface,
    AccountInterface,
    NoteAccountCompatibility,
};
use crate::account::wallets::BasicWallet;
use crate::note::{create_p2id_note, create_p2ide_note, create_swap_note};
use crate::testing::account_interface::get_public_keys_from_account;
use crate::transaction::TransactionKernel;
use crate::utils::ScriptBuilder;

// DEFAULT NOTES
// ================================================================================================

#[test]
fn test_basic_wallet_default_notes() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .with_assets(vec![FungibleAsset::mock(20)])
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from(&wallet_account);

    let mock_seed = Word::from([Felt::new(4), Felt::new(5), Felt::new(6), Felt::new(7)]).as_bytes();
    let faucet_account = AccountBuilder::new(mock_seed)
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(get_mock_auth_component())
        .with_component(
            BasicFungibleFaucet::new(
                TokenSymbol::new("POL").expect("invalid token symbol"),
                10,
                Felt::new(100),
            )
            .expect("failed to create a fungible faucet component"),
        )
        .build_existing()
        .expect("failed to create wallet account");
    let faucet_account_interface = AccountInterface::from(&faucet_account);

    let p2id_note = create_p2id_note(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap(),
        vec![FungibleAsset::mock(10)],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .unwrap();

    let p2ide_note = create_p2ide_note(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap(),
        vec![FungibleAsset::mock(10)],
        None,
        None,
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .unwrap();

    let offered_asset = NonFungibleAsset::mock(&[5, 6, 7, 8]);
    let requested_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);

    let (swap_note, _) = create_swap_note(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        offered_asset,
        requested_asset,
        NoteType::Public,
        ZERO,
        NoteType::Public,
        ZERO,
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .unwrap();

    // Basic wallet
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        wallet_account_interface.is_compatible_with(&p2id_note)
    );
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        wallet_account_interface.is_compatible_with(&p2ide_note)
    );
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        wallet_account_interface.is_compatible_with(&swap_note)
    );

    // Basic fungible faucet
    assert_eq!(
        NoteAccountCompatibility::No,
        faucet_account_interface.is_compatible_with(&p2id_note)
    );
    assert_eq!(
        NoteAccountCompatibility::No,
        faucet_account_interface.is_compatible_with(&p2ide_note)
    );
    assert_eq!(
        NoteAccountCompatibility::No,
        faucet_account_interface.is_compatible_with(&swap_note)
    );
}

/// Checks the compatibility of the basic notes (P2ID, P2IDE and SWAP) against an account with a
/// custom interface containing a procedure from the basic wallet.
///
/// In that setup check against P2ID and P2IDE notes should result in `Maybe`, and the check against
/// SWAP should result in `No`.
#[test]
fn test_custom_account_default_note() {
    let account_custom_code_source = "
        use.miden::contracts::wallets::basic

        export.basic::receive_asset
    ";

    let account_component = AccountComponent::compile(
        account_custom_code_source,
        TransactionKernel::with_kernel_library(Arc::new(DefaultSourceManager::default())),
        vec![],
    )
    .unwrap()
    .with_supports_all_types();

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let target_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(account_component.clone())
        .build_existing()
        .unwrap();
    let target_account_interface = AccountInterface::from(&target_account);

    let p2id_note = create_p2id_note(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap(),
        vec![FungibleAsset::mock(10)],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .unwrap();

    let p2ide_note = create_p2ide_note(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap(),
        vec![FungibleAsset::mock(10)],
        None,
        None,
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .unwrap();

    let offered_asset = NonFungibleAsset::mock(&[5, 6, 7, 8]);
    let requested_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);

    let (swap_note, _) = create_swap_note(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        offered_asset,
        requested_asset,
        NoteType::Public,
        ZERO,
        NoteType::Public,
        ZERO,
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .unwrap();

    assert_eq!(
        NoteAccountCompatibility::Maybe,
        target_account_interface.is_compatible_with(&p2id_note)
    );
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        target_account_interface.is_compatible_with(&p2ide_note)
    );
    assert_eq!(
        NoteAccountCompatibility::No,
        target_account_interface.is_compatible_with(&swap_note)
    );
}

/// Checks the function `create_swap_note` should fail if the requested asset is the same as the
/// offered asset.
#[test]
fn test_required_asset_same_as_offered() {
    let offered_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);
    let requested_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);

    let result = create_swap_note(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        offered_asset,
        requested_asset,
        NoteType::Public,
        ZERO,
        NoteType::Public,
        ZERO,
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    );

    assert_matches!(result, Err(NoteError::Other { error_msg, .. }) if error_msg == "requested asset same as offered asset".into());
}

// CUSTOM NOTES
// ================================================================================================

#[test]
fn test_basic_wallet_custom_notes() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .with_assets(vec![FungibleAsset::mock(20)])
        .build_existing()
        .expect("failed to create wallet account");
    let wallet_account_interface = AccountInterface::from(&wallet_account);

    let sender_account_id = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap();
    let serial_num = RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let tag = NoteTag::from_account_id(wallet_account.id());
    let metadata = NoteMetadata::new(
        sender_account_id,
        NoteType::Public,
        tag,
        NoteExecutionHint::always(),
        Default::default(),
    )
    .unwrap();
    let vault = NoteAssets::new(vec![FungibleAsset::mock(100)]).unwrap();

    let compatible_source_code = "
        use.miden::tx
        use.miden::contracts::wallets::basic->wallet
        use.miden::contracts::faucets::basic_fungible->fungible_faucet

        begin
            push.1
            if.true
                # supported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note

                # unsupported procs
                call.fungible_faucet::distribute
                call.fungible_faucet::burn
            else
                # supported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note
            end
        end
    ";
    let note_script = ScriptBuilder::default().compile_note_script(compatible_source_code).unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteInputs::default());
    let compatible_custom_note = Note::new(vault.clone(), metadata, recipient);
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        wallet_account_interface.is_compatible_with(&compatible_custom_note)
    );

    let incompatible_source_code = "
        use.miden::contracts::wallets::basic->wallet
        use.miden::contracts::faucets::basic_fungible->fungible_faucet

        begin
            push.1
            if.true
                # unsupported procs
                call.fungible_faucet::distribute
                call.fungible_faucet::burn
            else
                # unsupported proc
                call.fungible_faucet::distribute

                # supported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note
            end
        end
    ";
    let note_script =
        ScriptBuilder::default().compile_note_script(incompatible_source_code).unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteInputs::default());
    let incompatible_custom_note = Note::new(vault, metadata, recipient);
    assert_eq!(
        NoteAccountCompatibility::No,
        wallet_account_interface.is_compatible_with(&incompatible_custom_note)
    );
}

#[test]
fn test_basic_fungible_faucet_custom_notes() {
    let mock_seed = Word::from([Felt::new(4), Felt::new(5), Felt::new(6), Felt::new(7)]).as_bytes();
    let faucet_account = AccountBuilder::new(mock_seed)
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(get_mock_auth_component())
        .with_component(
            BasicFungibleFaucet::new(
                TokenSymbol::new("POL").expect("invalid token symbol"),
                10,
                Felt::new(100),
            )
            .expect("failed to create a fungible faucet component"),
        )
        .build_existing()
        .expect("failed to create wallet account");
    let faucet_account_interface = AccountInterface::from(&faucet_account);

    let sender_account_id = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap();
    let serial_num = RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let tag = NoteTag::from_account_id(faucet_account.id());
    let metadata = NoteMetadata::new(
        sender_account_id,
        NoteType::Public,
        tag,
        NoteExecutionHint::always(),
        Default::default(),
    )
    .unwrap();
    let vault = NoteAssets::new(vec![FungibleAsset::mock(100)]).unwrap();

    let compatible_source_code = "
        use.miden::contracts::wallets::basic->wallet
        use.miden::contracts::faucets::basic_fungible->fungible_faucet

        begin
            push.1
            if.true
                # supported procs
                call.fungible_faucet::distribute
                call.fungible_faucet::burn
            else
                # supported proc
                call.fungible_faucet::distribute

                # unsupported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note
            end
        end
    ";
    let note_script = ScriptBuilder::default().compile_note_script(compatible_source_code).unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteInputs::default());
    let compatible_custom_note = Note::new(vault.clone(), metadata, recipient);
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        faucet_account_interface.is_compatible_with(&compatible_custom_note)
    );

    let incompatible_source_code = "
        use.miden::contracts::wallets::basic->wallet
        use.miden::contracts::faucets::basic_fungible->fungible_faucet

        begin
            push.1
            if.true
                # supported procs
                call.fungible_faucet::distribute
                call.fungible_faucet::burn

                # unsupported proc
                call.wallet::receive_asset
            else
                # supported proc
                call.fungible_faucet::burn

                # unsupported procs
                call.wallet::move_asset_to_note
            end
        end
    ";
    let note_script =
        ScriptBuilder::default().compile_note_script(incompatible_source_code).unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteInputs::default());
    let incompatible_custom_note = Note::new(vault, metadata, recipient);
    assert_eq!(
        NoteAccountCompatibility::No,
        faucet_account_interface.is_compatible_with(&incompatible_custom_note)
    );
}

/// Checks the compatibility of the note with custom code against an account with one custom
/// interface.
///
/// In that setup the note script should have at least one execution branch with procedures from the
/// account interface for being `Maybe` compatible.
#[test]
fn test_custom_account_custom_notes() {
    let account_custom_code_source = "
        export.procedure_1
            push.1.2.3.4 dropw
        end

        export.procedure_2
            push.5.6.7.8 dropw
        end
    ";

    let account_component = AccountComponent::compile_with_path(
        account_custom_code_source,
        TransactionKernel::with_kernel_library(Arc::new(DefaultSourceManager::default())),
        vec![],
        "test::account::component_1",
    )
    .unwrap()
    .with_supports_all_types();

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let target_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(account_component.clone())
        .build_existing()
        .unwrap();
    let target_account_interface = AccountInterface::from(&target_account);

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let sender_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .with_assets(vec![FungibleAsset::mock(20)])
        .build_existing()
        .expect("failed to create wallet account");

    let serial_num = RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let tag = NoteTag::from_account_id(target_account.id());
    let metadata = NoteMetadata::new(
        sender_account.id(),
        NoteType::Public,
        tag,
        NoteExecutionHint::always(),
        Default::default(),
    )
    .unwrap();
    let vault = NoteAssets::new(vec![FungibleAsset::mock(100)]).unwrap();

    let compatible_source_code = "
        use.miden::contracts::wallets::basic->wallet
        use.test::account::component_1->test_account

        begin
            push.1
            if.true
                # supported proc
                call.test_account::procedure_1

                # unsupported proc
                call.wallet::receive_asset
            else
                # supported procs
                call.test_account::procedure_1
                call.test_account::procedure_2
            end
        end
    ";
    let note_script = ScriptBuilder::default()
        .with_dynamically_linked_library(account_component.library())
        .unwrap()
        .compile_note_script(compatible_source_code)
        .unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteInputs::default());
    let compatible_custom_note = Note::new(vault.clone(), metadata, recipient);
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        target_account_interface.is_compatible_with(&compatible_custom_note)
    );

    let incompatible_source_code = "
        use.miden::contracts::wallets::basic->wallet
        use.test::account::component_1->test_account

        begin
            push.1
            if.true
                call.wallet::receive_asset
                call.test_account::procedure_1
            else
                call.test_account::procedure_2
                call.wallet::move_asset_to_note
            end
        end
    ";
    let note_script = ScriptBuilder::default()
        .with_dynamically_linked_library(account_component.library())
        .unwrap()
        .compile_note_script(incompatible_source_code)
        .unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteInputs::default());
    let incompatible_custom_note = Note::new(vault, metadata, recipient);
    assert_eq!(
        NoteAccountCompatibility::No,
        target_account_interface.is_compatible_with(&incompatible_custom_note)
    );
}

/// Checks the compatibility of the note with custom code against an account with many custom
/// interfaces.
///
/// In that setup the note script should have at least one execution branch with procedures from the
/// account interface for being `Maybe` compatible.
#[test]
fn test_custom_account_multiple_components_custom_notes() {
    let account_custom_code_source = "
        export.procedure_1
            push.1.2.3.4 dropw
        end

        export.procedure_2
            push.5.6.7.8 dropw
        end
    ";

    let custom_component = AccountComponent::compile_with_path(
        account_custom_code_source,
        TransactionKernel::with_kernel_library(Arc::new(DefaultSourceManager::default())),
        vec![],
        "test::account::component_1",
    )
    .unwrap()
    .with_supports_all_types();

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let target_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(custom_component.clone())
        .with_component(BasicWallet)
        .build_existing()
        .unwrap();
    let target_account_interface = AccountInterface::from(&target_account);

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let sender_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .with_assets(vec![FungibleAsset::mock(20)])
        .build_existing()
        .expect("failed to create wallet account");

    let serial_num = RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let tag = NoteTag::from_account_id(target_account.id());
    let metadata = NoteMetadata::new(
        sender_account.id(),
        NoteType::Public,
        tag,
        NoteExecutionHint::always(),
        Default::default(),
    )
    .unwrap();
    let vault = NoteAssets::new(vec![FungibleAsset::mock(100)]).unwrap();

    let compatible_source_code = "
        use.miden::contracts::wallets::basic->wallet
        use.miden::contracts::auth::basic->basic_auth
        use.test::account::component_1->test_account
        use.miden::contracts::faucets::basic_fungible->fungible_faucet

        begin
            push.1
            if.true
                # supported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note
                call.test_account::procedure_1
                call.test_account::procedure_2
            else
                # supported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note
                call.test_account::procedure_1
                call.test_account::procedure_2

                # unsupported proc
                call.fungible_faucet::distribute
            end
        end
    ";
    let note_script = ScriptBuilder::default()
        .with_dynamically_linked_library(custom_component.library())
        .unwrap()
        .compile_note_script(compatible_source_code)
        .unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteInputs::default());
    let compatible_custom_note = Note::new(vault.clone(), metadata, recipient);
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        target_account_interface.is_compatible_with(&compatible_custom_note)
    );

    let incompatible_source_code = "
        use.miden::contracts::wallets::basic->wallet
        use.miden::contracts::auth::basic->basic_auth
        use.test::account::component_1->test_account
        use.miden::contracts::faucets::basic_fungible->fungible_faucet

        begin
            push.1
            if.true
                # supported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note
                call.test_account::procedure_1
                call.test_account::procedure_2

                # unsupported proc
                call.fungible_faucet::distribute
            else
                # supported procs
                call.test_account::procedure_1
                call.test_account::procedure_2

                # unsupported proc
                call.fungible_faucet::burn
            end
        end
    ";
    let note_script = ScriptBuilder::default()
        .with_dynamically_linked_library(custom_component.library())
        .unwrap()
        .compile_note_script(incompatible_source_code)
        .unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteInputs::default());
    let incompatible_custom_note = Note::new(vault.clone(), metadata, recipient);
    assert_eq!(
        NoteAccountCompatibility::No,
        target_account_interface.is_compatible_with(&incompatible_custom_note)
    );
}

// HELPER TRAIT
// ================================================================================================

/// [AccountComponentExt] is a helper trait which only implements the `compile_with_path` procedure
/// for testing purposes.
trait AccountComponentExt {
    fn compile_with_path(
        source_code: impl ToString,
        assembler: Assembler,
        storage_slots: Vec<StorageSlot>,
        library_path: impl AsRef<str>,
    ) -> Result<AccountComponent, AccountError>;
}

impl AccountComponentExt for AccountComponent {
    /// Returns a new [`AccountComponent`] whose library is compiled from the provided `source_code`
    /// using the specified `assembler`, `library_path`, and with the given `storage_slots`.
    ///
    /// All procedures exported from the provided code will become members of the account's public
    /// interface when added to an [`AccountCode`](crate::account::AccountCode), and could be called
    /// using the provided library path.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the compilation of the provided source code fails.
    /// - The number of storage slots exceeds 255.
    fn compile_with_path(
        source_code: impl ToString,
        assembler: Assembler,
        storage_slots: Vec<StorageSlot>,
        library_path: impl AsRef<str>,
    ) -> Result<Self, AccountError> {
        let source = NamedSource::new(library_path, source_code.to_string());
        let library = assembler
            .assemble_library([source])
            .map_err(AccountError::AccountComponentAssemblyError)?;

        Self::new(library, storage_slots)
    }
}

/// Helper function to create a mock auth component for testing
fn get_mock_auth_component() -> AuthRpoFalcon512 {
    let mock_word = Word::from([0, 1, 2, 3u32]);
    let mock_public_key = PublicKeyCommitment::from(mock_word);
    AuthRpoFalcon512::new(mock_public_key)
}

// GET AUTH SCHEME TESTS
// ================================================================================================

#[test]
fn test_get_auth_scheme_rpo_falcon512() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from(&wallet_account);

    // Find the RpoFalcon512 component interface
    let rpo_falcon_component = wallet_account_interface
        .components()
        .iter()
        .find(|component| matches!(component, AccountComponentInterface::AuthRpoFalcon512(_)))
        .expect("should have RpoFalcon512 component");

    // Test get_auth_schemes method
    let auth_schemes = rpo_falcon_component.get_auth_schemes(wallet_account.storage());
    assert_eq!(auth_schemes.len(), 1);
    let auth_scheme = &auth_schemes[0];
    match auth_scheme {
        AuthScheme::RpoFalcon512 { pub_key } => {
            assert_eq!(*pub_key, PublicKeyCommitment::from(Word::from([0, 1, 2, 3u32])));
        },
        _ => panic!("Expected RpoFalcon512 auth scheme"),
    }
}

#[test]
fn test_get_auth_scheme_no_auth() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    let no_auth_account_interface = AccountInterface::from(&no_auth_account);

    // Find the NoAuth component interface
    let no_auth_component = no_auth_account_interface
        .components()
        .iter()
        .find(|component| matches!(component, AccountComponentInterface::AuthNoAuth))
        .expect("should have NoAuth component");

    // Test get_auth_schemes method
    let auth_schemes = no_auth_component.get_auth_schemes(no_auth_account.storage());
    assert_eq!(auth_schemes.len(), 1);
    let auth_scheme = &auth_schemes[0];
    match auth_scheme {
        AuthScheme::NoAuth => {},
        _ => panic!("Expected NoAuth auth scheme"),
    }
}

/// Test that non-auth components return None
#[test]
fn test_get_auth_scheme_non_auth_component() {
    let basic_wallet_component = AccountComponentInterface::BasicWallet;
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let auth_schemes = basic_wallet_component.get_auth_schemes(wallet_account.storage());
    assert!(auth_schemes.is_empty());
}

/// Test that the From<&Account> implementation correctly uses get_auth_scheme
#[test]
fn test_account_interface_from_account_uses_get_auth_scheme() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from(&wallet_account);

    // Should have exactly one auth scheme
    assert_eq!(wallet_account_interface.auth().len(), 1);

    match &wallet_account_interface.auth()[0] {
        AuthScheme::RpoFalcon512 { pub_key } => {
            let expected_pub_key = PublicKeyCommitment::from(Word::from([0, 1, 2, 3u32]));
            assert_eq!(*pub_key, expected_pub_key);
        },
        _ => panic!("Expected RpoFalcon512 auth scheme"),
    }

    // Test with NoAuth
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    let no_auth_account_interface = AccountInterface::from(&no_auth_account);

    // Should have exactly one auth scheme
    assert_eq!(no_auth_account_interface.auth().len(), 1);

    match &no_auth_account_interface.auth()[0] {
        AuthScheme::NoAuth => {},
        _ => panic!("Expected NoAuth auth scheme"),
    }
}

/// Test AccountInterface.get_auth_scheme() method with RpoFalcon512 and NoAuth
#[test]
fn test_account_interface_get_auth_scheme() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from(&wallet_account);

    // Test that auth() method provides the authentication schemes
    assert_eq!(wallet_account_interface.auth().len(), 1);
    match &wallet_account_interface.auth()[0] {
        AuthScheme::RpoFalcon512 { pub_key } => {
            assert_eq!(*pub_key, PublicKeyCommitment::from(Word::from([0, 1, 2, 3u32])));
        },
        _ => panic!("Expected RpoFalcon512 auth scheme"),
    }

    // Test AccountInterface.get_auth_scheme() method with NoAuth
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    let no_auth_account_interface = AccountInterface::from(&no_auth_account);

    // Test that auth() method provides the authentication schemes
    assert_eq!(no_auth_account_interface.auth().len(), 1);
    match &no_auth_account_interface.auth()[0] {
        AuthScheme::NoAuth => {},
        _ => panic!("Expected NoAuth auth scheme"),
    }

    // Note: We don't test the case where an account has no auth components because
    // accounts are required to have auth components in the current system design
}

#[test]
fn test_public_key_extraction_regular_account() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    // Test public key extraction like miden-client would do
    let pub_keys = get_public_keys_from_account(&wallet_account);

    assert_eq!(pub_keys.len(), 1);
    assert_eq!(pub_keys[0], Word::from([0, 1, 2, 3u32]));
}

#[test]
fn test_public_key_extraction_multisig_account() {
    // Create test public keys
    let pub_key_1 = PublicKeyCommitment::from(Word::from([1u32, 0, 0, 0]));
    let pub_key_2 = PublicKeyCommitment::from(Word::from([2u32, 0, 0, 0]));
    let pub_key_3 = PublicKeyCommitment::from(Word::from([3u32, 0, 0, 0]));
    let approvers = vec![pub_key_1, pub_key_2, pub_key_3];
    let threshold = 2u32;

    // Create multisig component
    let multisig_component = AuthRpoFalcon512Multisig::new(
        AuthRpoFalcon512MultisigConfig::new(approvers.clone(), threshold).unwrap(),
    )
    .expect("multisig component creation failed");

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let multisig_account = AccountBuilder::new(mock_seed)
        .with_auth_component(multisig_component)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create multisig account");

    let pub_keys = get_public_keys_from_account(&multisig_account);

    assert_eq!(pub_keys.len(), 3);
    assert_eq!(pub_keys[0], Word::from([1u32, 0, 0, 0]));
    assert_eq!(pub_keys[1], Word::from([2u32, 0, 0, 0]));
    assert_eq!(pub_keys[2], Word::from([3u32, 0, 0, 0]));
}

#[test]
fn test_public_key_extraction_no_auth_account() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    // Test public key extraction
    let pub_keys = get_public_keys_from_account(&no_auth_account);

    // NoAuth should not contribute any public keys
    assert_eq!(pub_keys.len(), 0);
}
