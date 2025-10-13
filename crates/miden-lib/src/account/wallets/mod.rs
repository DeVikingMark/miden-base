use alloc::string::String;

use miden_objects::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountStorageMode,
    AccountType,
};
use miden_objects::{AccountError, Word};
use thiserror::Error;

use super::AuthScheme;
use crate::account::auth::{AuthRpoFalcon512, AuthRpoFalcon512Multisig};
use crate::account::components::basic_wallet_library;
use crate::procedure_digest;

// BASIC WALLET
// ================================================================================================

// Initialize the digest of the `receive_asset` procedure of the Basic Wallet only once.
procedure_digest!(
    BASIC_WALLET_RECEIVE_ASSET,
    BasicWallet::RECEIVE_ASSET_PROC_NAME,
    basic_wallet_library
);

// Initialize the digest of the `move_asset_to_note` procedure of the Basic Wallet only once.
procedure_digest!(
    BASIC_WALLET_MOVE_ASSET_TO_NOTE,
    BasicWallet::MOVE_ASSET_TO_NOTE_PROC_NAME,
    basic_wallet_library
);

/// An [`AccountComponent`] implementing a basic wallet.
///
/// It reexports the procedures from `miden::contracts::wallets::basic`. When linking against this
/// component, the `miden` library (i.e. [`MidenLib`](crate::MidenLib)) must be available to the
/// assembler which is the case when using [`TransactionKernel::assembler()`][kasm]. The procedures
/// of this component are:
/// - `receive_asset`, which can be used to add an asset to the account.
/// - `move_asset_to_note`, which can be used to remove the specified asset from the account and add
///   it to the output note with the specified index.
///
/// All methods require authentication. Thus, this component must be combined with a component
/// providing authentication.
///
/// This component supports all account types.
///
/// [kasm]: crate::transaction::TransactionKernel::assembler
pub struct BasicWallet;

impl BasicWallet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    const RECEIVE_ASSET_PROC_NAME: &str = "receive_asset";
    const MOVE_ASSET_TO_NOTE_PROC_NAME: &str = "move_asset_to_note";

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the digest of the `receive_asset` wallet procedure.
    pub fn receive_asset_digest() -> Word {
        *BASIC_WALLET_RECEIVE_ASSET
    }

    /// Returns the digest of the `move_asset_to_note` wallet procedure.
    pub fn move_asset_to_note_digest() -> Word {
        *BASIC_WALLET_MOVE_ASSET_TO_NOTE
    }
}

impl From<BasicWallet> for AccountComponent {
    fn from(_: BasicWallet) -> Self {
        AccountComponent::new(basic_wallet_library(), vec![])
          .expect("basic wallet component should satisfy the requirements of a valid account component")
          .with_supports_all_types()
    }
}

// BASIC WALLET ERROR
// ================================================================================================

/// Basic wallet related errors.
#[derive(Debug, Error)]
pub enum BasicWalletError {
    #[error("unsupported authentication scheme: {0}")]
    UnsupportedAuthScheme(String),
    #[error("account creation failed")]
    AccountError(#[source] AccountError),
}

/// Creates a new account with basic wallet interface, the specified authentication scheme and the
/// account storage type. Basic wallets can be specified to have either mutable or immutable code.
///
/// The basic wallet interface exposes three procedures:
/// - `receive_asset`, which can be used to add an asset to the account.
/// - `move_asset_to_note`, which can be used to remove the specified asset from the account and add
///   it to the output note with the specified index.
///
/// All methods require authentication. The authentication procedure is defined by the specified
/// authentication scheme.
pub fn create_basic_wallet(
    init_seed: [u8; 32],
    auth_scheme: AuthScheme,
    account_type: AccountType,
    account_storage_mode: AccountStorageMode,
) -> Result<Account, BasicWalletError> {
    if matches!(account_type, AccountType::FungibleFaucet | AccountType::NonFungibleFaucet) {
        return Err(BasicWalletError::AccountError(AccountError::other(
            "basic wallet accounts cannot have a faucet account type",
        )));
    }

    let auth_component: AccountComponent = match auth_scheme {
        AuthScheme::RpoFalcon512 { pub_key } => AuthRpoFalcon512::new(pub_key).into(),
        AuthScheme::RpoFalcon512Multisig { threshold, pub_keys } => {
            AuthRpoFalcon512Multisig::new(threshold, pub_keys)
                .map_err(BasicWalletError::AccountError)?
                .into()
        },
        AuthScheme::NoAuth => {
            return Err(BasicWalletError::UnsupportedAuthScheme(
                "basic wallets cannot be created with NoAuth authentication scheme".into(),
            ));
        },
        AuthScheme::Unknown => {
            return Err(BasicWalletError::UnsupportedAuthScheme(
                "basic wallets cannot be created with Unknown authentication scheme".into(),
            ));
        },
    };

    let account = AccountBuilder::new(init_seed)
        .account_type(account_type)
        .storage_mode(account_storage_mode)
        .with_auth_component(auth_component)
        .with_component(BasicWallet)
        .build()
        .map_err(BasicWalletError::AccountError)?;

    Ok(account)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_objects::account::PublicKeyCommitment;
    use miden_objects::{ONE, Word};
    use miden_processor::utils::{Deserializable, Serializable};

    use super::{Account, AccountStorageMode, AccountType, AuthScheme, create_basic_wallet};
    use crate::account::wallets::BasicWallet;

    #[test]
    fn test_create_basic_wallet() {
        let pub_key = PublicKeyCommitment::from(Word::from([ONE; 4]));
        let wallet = create_basic_wallet(
            [1; 32],
            AuthScheme::RpoFalcon512 { pub_key },
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Public,
        );

        wallet.unwrap_or_else(|err| {
            panic!("{}", err);
        });
    }

    #[test]
    fn test_serialize_basic_wallet() {
        let pub_key = PublicKeyCommitment::from(Word::from([ONE; 4]));
        let wallet = create_basic_wallet(
            [1; 32],
            AuthScheme::RpoFalcon512 { pub_key },
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Public,
        )
        .unwrap();

        let bytes = wallet.to_bytes();
        let deserialized_wallet = Account::read_from_bytes(&bytes).unwrap();
        assert_eq!(wallet, deserialized_wallet);
    }

    /// Check that the obtaining of the basic wallet procedure digests does not panic.
    #[test]
    fn get_faucet_procedures() {
        let _receive_asset_digest = BasicWallet::receive_asset_digest();
        let _move_asset_to_note_digest = BasicWallet::move_asset_to_note_digest();
    }
}
