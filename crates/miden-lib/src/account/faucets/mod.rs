use alloc::string::String;

use miden_objects::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountStorage,
    AccountStorageMode,
    AccountType,
    StorageSlot,
};
use miden_objects::asset::{FungibleAsset, TokenSymbol};
use miden_objects::{AccountError, Felt, FieldElement, TokenSymbolError, Word};
use thiserror::Error;

use super::AuthScheme;
use super::interface::{AccountComponentInterface, AccountInterface};
use crate::account::auth::{
    AuthRpoFalcon512Acl,
    AuthRpoFalcon512AclConfig,
    AuthRpoFalcon512Multisig,
};
use crate::account::components::basic_fungible_faucet_library;
use crate::procedure_digest;
use crate::transaction::memory::FAUCET_STORAGE_DATA_SLOT;

// BASIC FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

// Initialize the digest of the `distribute` procedure of the Basic Fungible Faucet only once.
procedure_digest!(
    BASIC_FUNGIBLE_FAUCET_DISTRIBUTE,
    BasicFungibleFaucet::DISTRIBUTE_PROC_NAME,
    basic_fungible_faucet_library
);

// Initialize the digest of the `burn` procedure of the Basic Fungible Faucet only once.
procedure_digest!(
    BASIC_FUNGIBLE_FAUCET_BURN,
    BasicFungibleFaucet::BURN_PROC_NAME,
    basic_fungible_faucet_library
);

/// An [`AccountComponent`] implementing a basic fungible faucet.
///
/// It reexports the procedures from `miden::contracts::faucets::basic_fungible`. When linking
/// against this component, the `miden` library (i.e. [`MidenLib`](crate::MidenLib)) must be
/// available to the assembler which is the case when using
/// [`TransactionKernel::assembler()`][kasm]. The procedures of this component are:
/// - `distribute`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// `distribute` requires authentication while `burn` does not require authentication and can be
/// called by anyone. Thus, this component must be combined with a component providing
/// authentication.
///
/// This component supports accounts of type [`AccountType::FungibleFaucet`].
///
/// [kasm]: crate::transaction::TransactionKernel::assembler
pub struct BasicFungibleFaucet {
    symbol: TokenSymbol,
    decimals: u8,
    max_supply: Felt,
}

impl BasicFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of decimals supported by the component.
    pub const MAX_DECIMALS: u8 = 12;

    const DISTRIBUTE_PROC_NAME: &str = "distribute";
    const BURN_PROC_NAME: &str = "burn";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`BasicFungibleFaucet`] component from the given pieces of metadata.
    ///
    /// # Errors:
    /// Returns an error if:
    /// - the decimals parameter exceeds maximum value of [`Self::MAX_DECIMALS`].
    /// - the max supply parameter exceeds maximum possible amount for a fungible asset
    ///   ([`FungibleAsset::MAX_AMOUNT`])
    pub fn new(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
    ) -> Result<Self, FungibleFaucetError> {
        // First check that the metadata is valid.
        if decimals > Self::MAX_DECIMALS {
            return Err(FungibleFaucetError::TooManyDecimals {
                actual: decimals as u64,
                max: Self::MAX_DECIMALS,
            });
        } else if max_supply.as_int() > FungibleAsset::MAX_AMOUNT {
            return Err(FungibleFaucetError::MaxSupplyTooLarge {
                actual: max_supply.as_int(),
                max: FungibleAsset::MAX_AMOUNT,
            });
        }

        Ok(Self { symbol, decimals, max_supply })
    }

    /// Attempts to create a new [`BasicFungibleFaucet`] component from the associated account
    /// interface and storage.
    ///
    /// # Errors:
    /// Returns an error if:
    /// - the provided [`AccountInterface`] does not contain a
    ///   [`AccountComponentInterface::BasicFungibleFaucet`] component.
    /// - the decimals parameter exceeds maximum value of [`Self::MAX_DECIMALS`].
    /// - the max supply value exceeds maximum possible amount for a fungible asset of
    ///   [`FungibleAsset::MAX_AMOUNT`].
    /// - the token symbol encoded value exceeds the maximum value of
    ///   [`TokenSymbol::MAX_ENCODED_VALUE`].
    fn try_from_interface(
        interface: AccountInterface,
        storage: &AccountStorage,
    ) -> Result<Self, FungibleFaucetError> {
        for component in interface.components().iter() {
            if let AccountComponentInterface::BasicFungibleFaucet(offset) = component {
                // obtain metadata from storage using offset provided by BasicFungibleFaucet
                // interface
                let faucet_metadata = storage
                    .get_item(*offset)
                    .map_err(|_| FungibleFaucetError::InvalidStorageOffset(*offset))?;
                let [max_supply, decimals, token_symbol, _] = *faucet_metadata;

                // verify metadata values
                let token_symbol = TokenSymbol::try_from(token_symbol)
                    .map_err(FungibleFaucetError::InvalidTokenSymbol)?;
                let decimals = decimals.as_int().try_into().map_err(|_| {
                    FungibleFaucetError::TooManyDecimals {
                        actual: decimals.as_int(),
                        max: Self::MAX_DECIMALS,
                    }
                })?;

                return BasicFungibleFaucet::new(token_symbol, decimals, max_supply);
            }
        }

        Err(FungibleFaucetError::NoAvailableInterface)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the symbol of the faucet.
    pub fn symbol(&self) -> TokenSymbol {
        self.symbol
    }

    /// Returns the decimals of the faucet.
    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// Returns the max supply of the faucet.
    pub fn max_supply(&self) -> Felt {
        self.max_supply
    }

    /// Returns the digest of the `distribute` account procedure.
    pub fn distribute_digest() -> Word {
        *BASIC_FUNGIBLE_FAUCET_DISTRIBUTE
    }

    /// Returns the digest of the `burn` account procedure.
    pub fn burn_digest() -> Word {
        *BASIC_FUNGIBLE_FAUCET_BURN
    }
}

impl From<BasicFungibleFaucet> for AccountComponent {
    fn from(faucet: BasicFungibleFaucet) -> Self {
        // Note: data is stored as [a0, a1, a2, a3] but loaded onto the stack as
        // [a3, a2, a1, a0, ...]
        let metadata = Word::new([
            faucet.max_supply,
            Felt::from(faucet.decimals),
            faucet.symbol.into(),
            Felt::ZERO,
        ]);

        AccountComponent::new(basic_fungible_faucet_library(), vec![StorageSlot::Value(metadata)])
            .expect("basic fungible faucet component should satisfy the requirements of a valid account component")
            .with_supported_type(AccountType::FungibleFaucet)
    }
}

impl TryFrom<Account> for BasicFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from(&account);

        BasicFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

impl TryFrom<&Account> for BasicFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: &Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from(account);

        BasicFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

// FUNGIBLE FAUCET
// ================================================================================================

/// Extension trait for fungible faucet accounts. Provides methods to access the fungible faucet
/// account's reserved storage slot.
pub trait FungibleFaucetExt {
    const ISSUANCE_ELEMENT_INDEX: usize;
    const ISSUANCE_STORAGE_SLOT: u8;

    /// Returns the amount of tokens (in base units) issued from this fungible faucet.
    ///
    /// # Errors
    /// Returns an error if the account is not a fungible faucet account.
    fn get_token_issuance(&self) -> Result<Felt, FungibleFaucetError>;
}

impl FungibleFaucetExt for Account {
    const ISSUANCE_ELEMENT_INDEX: usize = 3;
    const ISSUANCE_STORAGE_SLOT: u8 = FAUCET_STORAGE_DATA_SLOT;

    fn get_token_issuance(&self) -> Result<Felt, FungibleFaucetError> {
        if self.account_type() != AccountType::FungibleFaucet {
            return Err(FungibleFaucetError::NotAFungibleFaucetAccount);
        }

        let slot = self
            .storage()
            .get_item(Self::ISSUANCE_STORAGE_SLOT)
            .map_err(|_| FungibleFaucetError::InvalidStorageOffset(Self::ISSUANCE_STORAGE_SLOT))?;
        Ok(slot[Self::ISSUANCE_ELEMENT_INDEX])
    }
}

/// Creates a new faucet account with basic fungible faucet interface,
/// account storage type, specified authentication scheme, and provided meta data (token symbol,
/// decimals, max supply).
///
/// The basic faucet interface exposes two procedures:
/// - `distribute`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// `distribute` requires authentication. The authentication procedure is defined by the specified
/// authentication scheme. `burn` does not require authentication and can be called by anyone.
///
/// The storage layout of the faucet account is:
/// - Slot 0: Reserved slot for faucets.
/// - Slot 1: Public Key of the authentication component.
/// - Slot 2: [num_tracked_procs, allow_unauthorized_output_notes, allow_unauthorized_input_notes,
///   0].
/// - Slot 3: A map with tracked procedure roots.
/// - Slot 4: Token metadata of the faucet.
pub fn create_basic_fungible_faucet(
    init_seed: [u8; 32],
    symbol: TokenSymbol,
    decimals: u8,
    max_supply: Felt,
    account_storage_mode: AccountStorageMode,
    auth_scheme: AuthScheme,
) -> Result<Account, FungibleFaucetError> {
    let distribute_proc_root = BasicFungibleFaucet::distribute_digest();

    let auth_component: AccountComponent = match auth_scheme {
        AuthScheme::RpoFalcon512 { pub_key } => AuthRpoFalcon512Acl::new(
            pub_key,
            AuthRpoFalcon512AclConfig::new()
                .with_auth_trigger_procedures(vec![distribute_proc_root])
                .with_allow_unauthorized_input_notes(true),
        )
        .map_err(FungibleFaucetError::AccountError)?
        .into(),
        AuthScheme::RpoFalcon512Multisig { threshold, pub_keys } => {
            AuthRpoFalcon512Multisig::new(threshold, pub_keys)
                .map_err(FungibleFaucetError::AccountError)?
                .into()
        },
        AuthScheme::NoAuth => {
            return Err(FungibleFaucetError::UnsupportedAuthScheme(
                "basic fungible faucets cannot be created with NoAuth authentication scheme".into(),
            ));
        },
        AuthScheme::Unknown => {
            return Err(FungibleFaucetError::UnsupportedAuthScheme(
                "basic fungible faucets cannot be created with Unknown authentication scheme"
                    .into(),
            ));
        },
    };

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(account_storage_mode)
        .with_auth_component(auth_component)
        .with_component(BasicFungibleFaucet::new(symbol, decimals, max_supply)?)
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}

// FUNGIBLE FAUCET ERROR
// ================================================================================================

/// Basic fungible faucet related errors.
#[derive(Debug, Error)]
pub enum FungibleFaucetError {
    #[error("faucet metadata decimals is {actual} which exceeds max value of {max}")]
    TooManyDecimals { actual: u64, max: u8 },
    #[error("faucet metadata max supply is {actual} which exceeds max value of {max}")]
    MaxSupplyTooLarge { actual: u64, max: u64 },
    #[error(
        "account interface provided for faucet creation does not have basic fungible faucet component"
    )]
    NoAvailableInterface,
    #[error("storage offset `{0}` is invalid")]
    InvalidStorageOffset(u8),
    #[error("invalid token symbol")]
    InvalidTokenSymbol(#[source] TokenSymbolError),
    #[error("unsupported authentication scheme: {0}")]
    UnsupportedAuthScheme(String),
    #[error("account creation failed")]
    AccountError(#[source] AccountError),
    #[error("account is not a fungible faucet account")]
    NotAFungibleFaucetAccount,
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_objects::account::PublicKeyCommitment;
    use miden_objects::{FieldElement, ONE, Word};

    use super::{
        AccountBuilder,
        AccountStorageMode,
        AccountType,
        AuthScheme,
        BasicFungibleFaucet,
        Felt,
        FungibleFaucetError,
        TokenSymbol,
        create_basic_fungible_faucet,
    };
    use crate::account::auth::AuthRpoFalcon512;
    use crate::account::wallets::BasicWallet;

    #[test]
    fn faucet_contract_creation() {
        let pub_key_word = Word::new([ONE; 4]);
        let auth_scheme: AuthScheme = AuthScheme::RpoFalcon512 { pub_key: pub_key_word.into() };

        // we need to use an initial seed to create the wallet account
        let init_seed: [u8; 32] = [
            90, 110, 209, 94, 84, 105, 250, 242, 223, 203, 216, 124, 22, 159, 14, 132, 215, 85,
            183, 204, 149, 90, 166, 68, 100, 73, 106, 168, 125, 237, 138, 16,
        ];

        let max_supply = Felt::new(123);
        let token_symbol_string = "POL";
        let token_symbol = TokenSymbol::try_from(token_symbol_string).unwrap();
        let decimals = 2u8;
        let storage_mode = AccountStorageMode::Private;

        let faucet_account = create_basic_fungible_faucet(
            init_seed,
            token_symbol,
            decimals,
            max_supply,
            storage_mode,
            auth_scheme,
        )
        .unwrap();

        // The reserved faucet slot should be initialized to an empty word.
        assert_eq!(faucet_account.storage().get_item(0).unwrap(), Word::empty());

        // The falcon auth component is added first so its assigned storage slot for the public key
        // will be 1.
        assert_eq!(faucet_account.storage().get_item(1).unwrap(), pub_key_word);

        // Slot 2 stores [num_tracked_procs, allow_unauthorized_output_notes,
        // allow_unauthorized_input_notes, 0]. With 1 tracked procedure (distribute),
        // allow_unauthorized_output_notes=false, and allow_unauthorized_input_notes=true,
        // this should be [1, 0, 1, 0].
        assert_eq!(
            faucet_account.storage().get_item(2).unwrap(),
            [Felt::ONE, Felt::ZERO, Felt::ONE, Felt::ZERO].into()
        );

        // The procedure root map in slot 3 should contain the distribute procedure root.
        let distribute_root = BasicFungibleFaucet::distribute_digest();
        assert_eq!(
            faucet_account
                .storage()
                .get_map_item(3, [Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO].into())
                .unwrap(),
            distribute_root
        );

        // Check that faucet metadata was initialized to the given values. The faucet component is
        // added second, so its assigned storage slot for the metadata will be 2.
        assert_eq!(
            faucet_account.storage().get_item(4).unwrap(),
            [Felt::new(123), Felt::new(2), token_symbol.into(), Felt::ZERO].into()
        );

        assert!(faucet_account.is_faucet());

        assert_eq!(faucet_account.account_type(), AccountType::FungibleFaucet);

        // Verify the faucet can be extracted and has correct metadata
        let faucet_component = BasicFungibleFaucet::try_from(faucet_account.clone()).unwrap();
        assert_eq!(faucet_component.symbol(), token_symbol);
        assert_eq!(faucet_component.decimals(), decimals);
        assert_eq!(faucet_component.max_supply(), max_supply);
    }

    #[test]
    fn faucet_create_from_account() {
        // prepare the test data
        let mock_word = Word::from([0, 1, 2, 3u32]);
        let mock_public_key = PublicKeyCommitment::from(mock_word);
        let mock_seed = mock_word.as_bytes();

        // valid account
        let token_symbol = TokenSymbol::new("POL").expect("invalid token symbol");
        let faucet_account = AccountBuilder::new(mock_seed)
            .account_type(AccountType::FungibleFaucet)
            .with_component(
                BasicFungibleFaucet::new(token_symbol, 10, Felt::new(100))
                    .expect("failed to create a fungible faucet component"),
            )
            .with_auth_component(AuthRpoFalcon512::new(mock_public_key))
            .build_existing()
            .expect("failed to create wallet account");

        let basic_ff = BasicFungibleFaucet::try_from(faucet_account)
            .expect("basic fungible faucet creation failed");
        assert_eq!(basic_ff.symbol, token_symbol);
        assert_eq!(basic_ff.decimals, 10);
        assert_eq!(basic_ff.max_supply, Felt::new(100));

        // invalid account: basic fungible faucet component is missing
        let invalid_faucet_account = AccountBuilder::new(mock_seed)
            .account_type(AccountType::FungibleFaucet)
            .with_auth_component(AuthRpoFalcon512::new(mock_public_key))
            // we need to add some other component so the builder doesn't fail
            .with_component(BasicWallet)
            .build_existing()
            .expect("failed to create wallet account");

        let err = BasicFungibleFaucet::try_from(invalid_faucet_account)
            .err()
            .expect("basic fungible faucet creation should fail");
        assert_matches!(err, FungibleFaucetError::NoAvailableInterface);
    }

    /// Check that the obtaining of the basic fungible faucet procedure digests does not panic.
    #[test]
    fn get_faucet_procedures() {
        let _distribute_digest = BasicFungibleFaucet::distribute_digest();
        let _burn_digest = BasicFungibleFaucet::burn_digest();
    }
}
