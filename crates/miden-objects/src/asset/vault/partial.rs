use alloc::string::ToString;

use miden_crypto::merkle::{InnerNodeInfo, MerkleError, PartialSmt, SmtLeaf, SmtProof};

use super::AssetVault;
use crate::Word;
use crate::asset::{Asset, AssetWitness};
use crate::errors::PartialAssetVaultError;
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

/// A partial representation of an [`AssetVault`], containing only proofs for a subset of assets.
///
/// Partial vault is used to provide verifiable access to specific assets in a vault
/// without the need to provide the full vault data. It contains all required data for loading
/// vault data into the transaction kernel for transaction execution.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PartialVault {
    /// An SMT with a partial view into an account's full [`AssetVault`].
    partial_smt: PartialSmt,
}

impl PartialVault {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new instance of a partial vault from the provided partial SMT.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided SMT does not track only valid [`Asset`]s.
    /// - the vault key at which the asset is stored does not match the vault key derived from the
    ///   asset.
    pub fn new(partial_smt: PartialSmt) -> Result<Self, PartialAssetVaultError> {
        Self::validate_entries(partial_smt.entries())?;

        Ok(PartialVault { partial_smt })
    }

    /// Converts an [`AssetVault`] into a partial vault representation.
    ///
    /// The resulting [`PartialVault`] will contain the _full_ merkle paths of the original asset
    /// vault.
    pub fn new_full(vault: AssetVault) -> Self {
        let partial_smt = PartialSmt::from(vault.asset_tree);

        PartialVault { partial_smt }
    }

    /// Converts an [`AssetVault`] into a partial vault representation.
    ///
    /// The resulting [`PartialVault`] will contain only a single, unspecified key-value pair
    /// in order to have the same root as the original storage map. Is it otherwise the most
    /// _minimal_ representation of the asset vault.
    pub fn new_minimal(vault: &AssetVault) -> Self {
        let mut partial_vault = PartialVault::default();

        // Construct a partial vault that tracks the empty word, but none of the assets that are
        // actually in the asset tree. That way, the partial vault has the same root as the full
        // vault. This is the most minimal and correct partial vault we can build.
        // TODO: Workaround for https://github.com/0xMiden/miden-base/issues/1966. Fix when implemented.
        partial_vault
            .add(vault.open(Word::empty()))
            .expect("adding the first proof should never fail");

        partial_vault
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the partial vault.
    pub fn root(&self) -> Word {
        self.partial_smt.root()
    }

    /// Returns an iterator over all inner nodes in the Sparse Merkle Tree proofs.
    ///
    /// This is useful for reconstructing parts of the Sparse Merkle Tree or for
    /// verification purposes.
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.partial_smt.inner_nodes()
    }

    /// Returns an iterator over all leaves in the Sparse Merkle Tree proofs.
    ///
    /// Each item returned is a tuple containing the leaf index and a reference to the leaf.
    pub fn leaves(&self) -> impl Iterator<Item = &SmtLeaf> {
        self.partial_smt.leaves().map(|(_, leaf)| leaf)
    }

    /// Returns an opening of the leaf associated with `vault_key`.
    ///
    /// The `vault_key` can be obtained with [`Asset::vault_key`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial vault.
    pub fn open(&self, vault_key: Word) -> Result<AssetWitness, PartialAssetVaultError> {
        let smt_proof = self
            .partial_smt
            .open(&vault_key)
            .map_err(PartialAssetVaultError::UntrackedAsset)?;
        // SAFETY: The partial vault should only contain valid assets.
        Ok(AssetWitness::new_unchecked(smt_proof))
    }

    /// Returns the [`Asset`] associated with the given `vault_key`.
    ///
    /// The return value is `None` if the asset does not exist in the vault.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn get(&self, vault_key: Word) -> Result<Option<Asset>, MerkleError> {
        self.partial_smt.get_value(&vault_key).map(|word| {
            if word.is_empty() {
                None
            } else {
                // SAFETY: If this returned a non-empty word, then it should be a valid asset,
                // because the vault should only track valid ones.
                Some(Asset::try_from(word).expect("partial vault should only track valid assets"))
            }
        })
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds an [`AssetWitness`] to this [`PartialVault`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the new root after the insertion of the leaf and the path does not match the existing root
    ///   (except when the first leaf is added).
    pub fn add(&mut self, witness: AssetWitness) -> Result<(), PartialAssetVaultError> {
        let proof = SmtProof::from(witness);
        self.partial_smt
            .add_proof(proof)
            .map_err(PartialAssetVaultError::FailedToAddProof)
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Validates that the provided entries are valid vault keys and assets.
    ///
    /// For brevity, the error conditions are only mentioned on the public methods that use this
    /// function.
    fn validate_entries<'a>(
        entries: impl IntoIterator<Item = &'a (Word, Word)>,
    ) -> Result<(), PartialAssetVaultError> {
        for (vault_key, asset) in entries {
            let asset = Asset::try_from(asset).map_err(|source| {
                PartialAssetVaultError::InvalidAssetInSmt { entry: *asset, source }
            })?;

            if asset.vault_key() != *vault_key {
                return Err(PartialAssetVaultError::VaultKeyMismatch {
                    expected: asset.vault_key(),
                    actual: *vault_key,
                });
            }
        }

        Ok(())
    }
}

impl Serializable for PartialVault {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.partial_smt)
    }
}

impl Deserializable for PartialVault {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let vault_partial_smt = source.read()?;

        PartialVault::new(vault_partial_smt)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_crypto::merkle::Smt;

    use super::*;
    use crate::asset::FungibleAsset;

    #[test]
    fn partial_vault_ensures_asset_validity() -> anyhow::Result<()> {
        let invalid_asset = Word::from([0, 0, 0, 5u32]);
        let smt = Smt::with_entries([(invalid_asset, invalid_asset)])?;
        let proof = smt.open(&invalid_asset);
        let partial_smt = PartialSmt::from_proofs([proof.clone()])?;

        let err = PartialVault::new(partial_smt).unwrap_err();
        assert_matches!(err, PartialAssetVaultError::InvalidAssetInSmt { entry, .. } => {
            assert_eq!(entry, invalid_asset);
        });

        Ok(())
    }

    #[test]
    fn partial_vault_ensures_asset_vault_key_matches() -> anyhow::Result<()> {
        let asset = FungibleAsset::mock(500);
        let invalid_vault_key = Word::from([0, 1, 2, 3u32]);
        let smt = Smt::with_entries([(invalid_vault_key, asset.into())])?;
        let proof = smt.open(&invalid_vault_key);
        let partial_smt = PartialSmt::from_proofs([proof.clone()])?;

        let err = PartialVault::new(partial_smt).unwrap_err();
        assert_matches!(err, PartialAssetVaultError::VaultKeyMismatch { expected, actual } => {
            assert_eq!(actual, invalid_vault_key);
            assert_eq!(expected, asset.vault_key());
        });

        Ok(())
    }
}
