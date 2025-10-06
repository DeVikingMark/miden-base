# Changelog

## 0.12.0 (TBD)

### Features

- Added `prove_dummy` APIs on `LocalTransactionProver` ([#1674](https://github.com/0xMiden/miden-base/pull/1674)).
- Added `add_signature` helper to simplify loading signatures into advice map ([#1725](https://github.com/0xMiden/miden-base/pull/1725)).
- [BREAKING] Enabled lazy loading of storage map entries during transaction execution ([#1857](https://github.com/0xMiden/miden-base/pull/1857)).
- Added `get_native_id` and `get_native_nonce` procedures to the `miden` library ([#1844](https://github.com/0xMiden/miden-base/pull/1844)).
- Added `prove_dummy` APIs on `LocalBatchProver` and `LocalBlockProver` ([#1811](https://github.com/0xMiden/miden-base/pull/1811)).
- Added `get_native_id` and `get_native_nonce` procedures to the `miden` library ([#1844](https://github.com/0xMiden/miden-base/pull/1844)).
- Enabled lazy loading of assets during transaction execution ([#1848](https://github.com/0xMiden/miden-base/pull/1848)).
- [BREAKING] Enabled lazy loading of foreign accounts during transaction execution ([#1873](https://github.com/0xMiden/miden-base/pull/1873)).
- Added lazy loading of the native asset ([#1855](https://github.com/0xMiden/miden-base/pull/1855)).
- Added `build_recipient` procedure to `miden::note` module ([#1807](https://github.com/0xMiden/miden-base/pull/1807)).
- [BREAKING] Move account seed into `PartialAccount` ([#1875](https://github.com/0xMiden/miden-base/pull/1875)).
- [BREAKING] Enabled lazy loading of assets and storage map items for foreign accounts during transaction execution ([#1888](https://github.com/0xMiden/miden-base/pull/1888)).
- Added `get_item_init` and `get_map_item_init` procedures to `miden::account` module for accessing initial storage state ([#1883](https://github.com/0xMiden/miden-base/pull/1883)).
- Updated `rpo_falcon512::verify_signatures` to use `account::get_map_item_init` ([#1885](https://github.com/0xMiden/miden-base/issues/1885))
- Added `update_signers_and_threshold` procedure to update owner public keys and threshold config in multisig authentication component ([#1707](https://github.com/0xMiden/miden-base/issues/1707)).
- Implement `SlotName` for named storage slots ([#1932](https://github.com/0xMiden/miden-base/issues/1932))
- [BREAKING] Removed `get_falcon_signature` from `miden-tx` crate ([#1924](https://github.com/0xMiden/miden-base/pull/1924)).
- Created a `Signature` wrapper to simplify the preparation of "native" signatures for use in the VM ([#1924](https://github.com/0xMiden/miden-base/pull/1924)).
- Implemented `input_note::get_sender` and `active_note::get_metadata` procedures in `miden` lib ([#1933]https://github.com/0xMiden/miden-base/pull/1933).
- Added `Address` serialization and deserialization ([#1937](https://github.com/0xMiden/miden-base/issues/1937))
- Added `StorageMap::{num_entries, num_leaves}` to retrieve the number of entries in a storage map ([#1935]https://github.com/0xMiden/miden-base/pull/1935).
- Added `AssetVault::{num_assets, num_leaves, inner_nodes}` ([#1939]https://github.com/0xMiden/miden-base/pull/1939).

### Changes

- [BREAKING] Incremented MSRV to 1.89.
- [BREAKING] Migrated to `miden-vm` v0.18 and `miden-crypto` v0.17 ([#1832](https://github.com/0xMiden/miden-base/pull/1832)).
- [BREAKING] Removed `MockChain::add_pending_p2id_note` in favor of using `MockChainBuilder` ([#1842](https://github.com/0xMiden/miden-base/pull/#1842)).
- [BREAKING] Removed versioning of the transaction kernel, leaving only one latest version ([#1793](https://github.com/0xMiden/miden-base/pull/1793)).
- [BREAKING] Moved `miden::asset::{create_fungible_asset, create_non_fungible_asset}` procedures to `miden::faucet` ([#1850](https://github.com/0xMiden/miden-base/pull/1850)).
- [BREAKING] Removed versioning of the transaction kernel, leaving only one latest version ([#1793](https://github.com/0xMiden/miden-base/pull/1793)).
- Added `AccountComponent::from_package()` method to create components from `miden-mast-package::Package` ([#1802](https://github.com/0xMiden/miden-base/pull/1802)).
- [BREAKING] Removed some of the `note` kernel procedures and use `input_note` procedures instead ([#1834](https://github.com/0xMiden/miden-base/pull/1834)).
- [BREAKING] Replaced `Account` with `PartialAccount` in `TransactionInputs` ([#1840](https://github.com/0xMiden/miden-base/pull/1840)).
- [BREAKING] Renamed `Account::init_commitment` to `Account::initial_commitment` ([#1840](https://github.com/0xMiden/miden-base/pull/1840)).
- [BREAKING] Rename the `is_onchain` method to `has_public_state` for `AccountId`, `AccountIdPrefix`, `Account`, `AccountInterface` and `AccountStorageMode` ([#1846](https://github.com/0xMiden/miden-base/pull/1846)).
- [BREAKING] Move `NetworkId` from account ID to address module ([#1851](https://github.com/0xMiden/miden-base/pull/1851)).
- Remove `ProvenTransactionExt`([#1867](https://github.com/0xMiden/miden-base/pull/1867)).
- [BREAKING] Renamed the `is_onchain` method to `has_public_state` for `AccountId`, `AccountIdPrefix`, `Account`, `AccountInterface` and `AccountStorageMode` ([#1846](https://github.com/0xMiden/miden-base/pull/1846)).
- [BREAKING] Moved `miden::asset::{create_fungible_asset, create_non_fungible_asset}` procedures to `miden::faucet` ([#1850](https://github.com/0xMiden/miden-base/pull/1850)).
- [BREAKING] Moved `NetworkId` from account ID to address module ([#1851](https://github.com/0xMiden/miden-base/pull/1851)).
- [BREAKING] Move `TransactionKernelError` to miden-tx ([#1859](https://github.com/0xMiden/miden-base/pull/1859)).
- [BREAKING] Changed `PartialStorageMap` to track the correct set of key+value pairings ([#1878](https://github.com/0xMiden/miden-base/pull/1878), [#1921](https://github.com/0xMiden/miden-base/pull/1921)).
- Change terminology of "current note" to "active note" ([#1863](https://github.com/0xMiden/miden-base/issues/1863)).
- [BREAKING] Move and rename `miden::tx::{add_asset_to_note, create_note}` procedures to `miden::output_note::{add_asset, create}` ([#1874](https://github.com/0xMiden/miden-base/pull/1874)).
- Merge `bench-prover` into `bench-tx` crate ([#1894](https://github.com/0xMiden/miden-base/pull/1894)).
- Replace `eqw` usages with `exec.word::test_eq` and `exec.word::eq`, remove `is_key_greater` and `is_key_less` from `link_map` module ([#1897](https://github.com/0xMiden/miden-base/pull/1897)).
- [BREAKING] Make AssetVault and PartialVault APIs more type safe ([#1916](https://github.com/0xMiden/miden-base/pull/1916)).
- [BREAKING] Remove `MockChain::add_pending_note` to simplify mock chain internals ([#1903](https://github.com/0xMiden/miden-base/pull/1903)).
- [BREAKING] Move active note procedures from `miden::note` to `miden::active_note` module ([#1901](https://github.com/0xMiden/miden-base/pull/1901)).
- [BREAKING] Remove account_seed from AccountFile ([#1917](https://github.com/0xMiden/miden-base/pull/1917)).
- Simplify `MockChain` internals and rework its documentation ([#1942]https://github.com/0xMiden/miden-base/pull/1942).
- [BREAKING] Change the signature of TransactionAuthenticator to return the native signature ([#1945](https://github.com/0xMiden/miden-base/pull/1945)).
- [BREAKING] Rename `MockChainBuilder::add_note` to `add_output_note` ([#1946](https://github.com/0xMiden/miden-base/pull/1946)).
- Dynamically lookup all masm `EventId`s from source ([#1954](https://github.com/0xMiden/miden-base/pull/1954)).

## 0.11.5 (2025-10-02)

- Add new `can_consume` method to the `NoteConsumptionChecker` ([#1928](https://github.com/0xMiden/miden-base/pull/1928)).

## 0.11.4 (2025-09-17)

- Updated `miden-vm` dependencies to `0.17.2` patch version. ([#1905](https://github.com/0xMiden/miden-base/pull/1905))

## 0.11.3 (2025-09-15)

- Added Serialize and Deserialize Traits on `SigningInputs` ([#1858](https://github.com/0xMiden/miden-base/pull/1858)).

## 0.11.2 (2025-09-08)

- Fixed foreign account inputs not being loaded in `LocalTransactionProver` ([#1866](https://github.com/0xMiden/miden-base/pull/#1866)).

## 0.11.1 (2025-08-28)

- Added `AddressInterface::Unspecified` to represent default addresses ([#1801](https://github.com/0xMiden/miden-base/pull/#1801)).

## 0.11.0 (2025-08-26)

### Features

- Added arguments to the auth procedure ([#1501](https://github.com/0xMiden/miden-base/pull/1501)).
- [BREAKING] Refactored `SWAP` note & added option to select the visibility of the associated payback note ([#1539](https://github.com/0xMiden/miden-base/pull/1539)).
- Added multi-signature authentication component as standard authentication component ([#1599](https://github.com/0xMiden/miden-base/issues/1599)).
- Added `account_compute_delta_commitment`, `input_note_get_assets_info`, `tx_get_num_input_notes`, and `tx_get_num_output_notes` procedures to the transaction kernel ([#1609](https://github.com/0xMiden/miden-base/pull/1609)).
- [BREAKING] Refactor `TransactionAuthenticator` to support arbitrary data signing ([#1616](https://github.com/0xMiden/miden-base/pull/1616)).
- Implemented new `from_unauthenticated_notes` constructor for `InputNotes` ([#1629](https://github.com/0xMiden/miden-base/pull/1629)).
- Added `output_note_get_assets_info` procedure to the transaction kernel ([#1638](https://github.com/0xMiden/miden-base/pull/1638)).
- Pass the full `TransactionSummary` to `TransactionAuthenticator` ([#1618](https://github.com/0xMiden/miden-base/pull/1618)).
- Added `PartialBlockchain::num_tracked_blocks()` ([#1643](https://github.com/0xMiden/miden-base/pull/1643)).
- Removed `TransactionScript::compile` & `NoteScript::compile` methods in favor of `ScriptBuilder` ([#1665](https://github.com/0xMiden/miden-base/pull/1665)).
- Added `get_initial_code_commitment`, `get_initial_storage_commitment` and `get_initial_vault_root` procedures to `miden::account` module ([#1667](https://github.com/0xMiden/miden-base/pull/1667)).
- Added `input_note_get_recipient`, `output_note_get_recipient`, `input_note_get_metadata`, `output_note_get_metadata` procedures to the transaction kernel ([#1648](https://github.com/0xMiden/miden-base/pull/1648)).
- Added `input_notes::get_assets` and `output_notes::get_assets` procedures to `miden` library ([#1648](https://github.com/0xMiden/miden-base/pull/1648)).
- Added issuance accessor for fungible faucet accounts. ([#1660](https://github.com/0xMiden/miden-base/pull/1660)).
- Added multi-signature authentication component as standard authentication component ([#1599](https://github.com/0xMiden/miden-base/issues/1599)).
- Added `FeeParameters` to `BlockHeader` and automatically compute and remove fees from account in the transaction kernel epilogue ([#1652](https://github.com/0xMiden/miden-base/pull/1652), [#1654](https://github.com/0xMiden/miden-base/pull/1654), [#1659](https://github.com/0xMiden/miden-base/pull/1659), [#1664](https://github.com/0xMiden/miden-base/pull/1664), [#1775](https://github.com/0xMiden/miden-base/pull/1775)).
- Added `Address` type to represent account-id based addresses ([#1713](https://github.com/0xMiden/miden-base/pull/1713), [#1750](https://github.com/0xMiden/miden-base/pull/1750)).
- [BREAKING] Consolidated to a single async interface and drop `#[maybe_async]` usage ([#1666](https://github.com/0xMiden/miden-base/pull/#1666)).
- [BREAKING] Made transaction execution and transaction authentication asynchronous ([#1699](https://github.com/0xMiden/miden-base/pull/1699)).
- [BREAKING] Return dedicated insufficient fee error from transaction host if account balance is too low ([#1744](https://github.com/0xMiden/miden-base/pull/#1744)).
- Added `asset_vault::peek_balance` ([#1745](https://github.com/0xMiden/miden-base/pull/1745)).
- Added `get_auth_scheme` method to `AccountComponentInterface` and `AccountInterface` for better authentication scheme extraction ([#1759](https://github.com/0xMiden/miden-base/pull/1759)).
- Added `AddressInterface` type to represent the interface of the account to which an `Address` points ([#1761](https://github.com/0xMiden/miden-base/pull/#1761)).
- Document `miden` library procedures and the context from which they can be called ([#1799](https://github.com/0xMiden/miden-base/pull/#1799)).
- Add `Address` type to represent account-id based addresses ([#1713](https://github.com/0xMiden/miden-base/pull/1713)).
- Document `Address` in Miden book ([#1792](https://github.com/0xMiden/miden-base/pull/1792)).
- Add `asset_vault::peek_balance` ([#1745](https://github.com/0xMiden/miden-base/pull/1745)).
- Add `get_auth_scheme` method to `AccountComponentInterface` and `AccountInterface` for better authentication scheme extraction ([#1759](https://github.com/0xMiden/miden-base/pull/1759)).
- Add `CustomNetworkId` in `NetworkID` ([#1787](https://github.com/0xMiden/miden-base/pull/1787)).

### Changes

- [BREAKING] Incremented MSRV to 1.88.
- Refactored account documentation into multiple sections ([#1523](https://github.com/0xMiden/miden-base/pull/1523)).
- Implemented `WellKnownComponents` enum ([#1532](https://github.com/0xMiden/miden-base/pull/1532)).
- [BREAKING] Remove pending account APIs on `MockChain` and introduce `MockChainBuilder` to simplify mock chain creation ([#1557](https://github.com/0xMiden/miden-base/pull/1557)).
- Made `ExecutedTransaction` implement `Send` for easier consumption ([#1560](https://github.com/0xMiden/miden-base/pull/1560)).
- [BREAKING] `Digest` was removed in favor of `Word` ([#1564](https://github.com/0xMiden/miden-base/pull/1564)).
- [BREAKING] Upgraded Miden VM to `0.16`, `miden-crypto` to `0.15` and `winterfell` crates to `0.13` ([#1564](https://github.com/0xMiden/miden-base/pull/1564), [#1594](https://github.com/0xMiden/miden-base/pull/1594)).
- [BREAKING] Renamed `{NoteInclusionProof, AccountWitness}::inner_nodes` to `authenticated_nodes` ([#1564](https://github.com/0xMiden/miden-base/pull/1564)).
- [BREAKING] Renamed `{TransactionId, NoteId, Nullifier}::inner` -> `as_word` ([#1571](https://github.com/0xMiden/miden-base/pull/1571)).
- Replaced `MerklePath` with `SparseMerklePath` in `NoteInclusionProof` ([#1572](https://github.com/0xMiden/miden-base/pull/1572)) .
- [BREAKING] Renamed authentication components to include "auth" prefix for clarity ([#1575](https://github.com/0xMiden/miden-base/issues/1575)).
- [BREAKING] Split `TransactionHost` into `TransactionProverHost` and `TransactionExecutorHost` ([#1581](https://github.com/0xMiden/miden-base/pull/1581)).
- Added `TransactionEvent::Unauthorized` to enable aborting the transaction execution to get its transaction summary for signing purposes ([#1596](https://github.com/0xMiden/miden-base/pull/1596), [#1634](https://github.com/0xMiden/miden-base/pull/1634), [#1651](https://github.com/0xMiden/miden-base/pull/1651)).
- [BREAKING] Implemented `SequentialCommit` for `AccountDelta` and renamed `AccountDelta::commitment()` to `AccountDelta::to_commitment()` ([#1603](https://github.com/0xMiden/miden-base/pull/1603)).
- Added robustness check to `create_swap_note`: error if `requested_asset` != `offered_asset` ([#1604](https://github.com/0xMiden/miden-base/pull/1604)).
- [BREAKING] Changed `account::incr_nonce` to always increment the nonce by one, disallow incrementing more than once and return the new nonce after incrementing ([#1608](https://github.com/0xMiden/miden-base/pull/1608), [#1633](https://github.com/0xMiden/miden-base/pull/1633)).
- Added `AccountTree::contains_account_id_prefix()` and `AccountTree::id_prefix_to_smt_key()` ([#1610](https://github.com/0xMiden/miden-base/pull/1610)).
- Added functions for pruning `PartialBlockchain` (#[1619](https://github.com/0xMiden/miden-base/pull/1619)).
- [BREAKING] Disallowed calling the auth procedure explicitly (from outside the epilogue) ([#1622](https://github.com/0xMiden/miden-base/pull/1622)).
- [BREAKING] Included account delta commitment in signing message for the `RpoFalcon512` family of account components ([#1624](https://github.com/0xMiden/miden-base/pull/1624)).
- [BREAKING] Renamed `TransactionEvent::FalconSigToStack` to `TransactionEvent::AuthRequest` ([#1626](https://github.com/0xMiden/miden-base/pull/1626)).
- [BREAKING] Made the naming of the transaction script arguments consistent ([#1632](https://github.com/0xMiden/miden-base/pull/1632)).
- [BREAKING] Moved `TransactionProverHost` and `TransactionExecutorHost` from dynamic dispatch to generics ([#1037](https://github.com/0xMiden/miden-node/issues/1037))
- [BREAKING] Changed `PartialStorage` and `PartialVault` to use `PartialSmt` instead of separate merkle proofs ([#1590](https://github.com/0xMiden/miden-base/pull/1590)).
- [BREAKING] Moved transaction inputs insertion out of transaction hosts ([#1639](https://github.com/0xMiden/miden-node/issues/1639))
- Implemented serialization for `MockChain` ([#1642](https://github.com/0xMiden/miden-base/pull/1642)).
- [BREAKING] Reduced `FungibleAsset::MAX_AMOUNT` by a small fraction which allows using felt-based arithmetic in the fungible asset account delta ([#1681](https://github.com/0xMiden/miden-base/pull/1681)).
- Avoid modifying an asset vault when adding a fungible asset with amount zero and the asset does not already exist ([#1668](https://github.com/0xMiden/miden-base/pull/1668)).
- [BREAKING] Updated `NoteConsumptionChecker::check_notes_consumability` and `TransactionExecutor::try_execute_notes` to return `NoteConsumptionInfo` containing lists of `Note` rather than `NoteId` ([#1680](https://github.com/0xMiden/miden-base/pull/1680)).
- Refactored epilogue to run as much code as possible before fees are computed ([#1698](https://github.com/0xMiden/miden-base/pull/1698)).
- Refactored epilogue to run as much code as possible before fees are computed ([#1698](https://github.com/0xMiden/miden-base/pull/1698), [#1705](https://github.com/0xMiden/miden-base/pull/1705)).
- [BREAKING] Removed note script utils and rename `note::add_note_assets_to_account` to `note::add_assets_to_account` ([#1694](https://github.com/0xMiden/miden-base/pull/1694)).
- Refactor `contracts::auth::basic` into a reusable library procedure `auth::rpo_falcon512` ([#1712](https://github.com/0xMiden/miden-base/pull/1712)).
- [BREAKING] Refactored `FungibleAsset::sub` to be more similar to `FungibleAsset::add` ([#1720](https://github.com/0xMiden/miden-base/pull/1720)).
- Update `NoteConsumptionChecker::check_notes_consumability` to use iterative elimination strategy to find a set of executable notes ([#1721](https://github.com/0xMiden/miden-base/pull/1721)).
- [BREAKING] Moved `IncrNonceAuthComponent`, `ConditionalAuthComponent` and `AccountMockComponent` to `miden-lib` ([#1722](https://github.com/0xMiden/miden-base/pull/1722)).
- [BREAKING] Split `AccountCode::mock_library` into an account and faucet library ([#1732](https://github.com/0xMiden/miden-base/pull/1732), [#1733](https://github.com/0xMiden/miden-base/pull/1733)).
- [BREAKING] Refactored `AccountError::AssumptionViolated` into `AccountError::Other` ([#1743](https://github.com/0xMiden/miden-base/pull/1743)).
- [BREAKING] Removed `PartialVault::{new, add}` to guarantee the vault tracks valid assets ([#1747](https://github.com/0xMiden/miden-base/pull/1747)).
- [BREAKING] Changed owner of `Arc<dyn SourceManagerSync` and unify usage over manually `+Send` `+Sync` bounds ([#1749](https://github.com/0xMiden/miden-base/pull/1749)).
- [BREAKING] Removed account ID bech32 encoding. Use `Address::{from_bech32, to_bech32}` instead ([#1762](https://github.com/0xMiden/miden-base/pull/1762)).
- [BREAKING] Updated `account::get_storage_commitment` procedure to `account::compute_storage_commitment`([#1763](https://github.com/0xMiden/miden-base/pull/1763)).
- Implemented caching for the account storage commitment (([#1763](https://github.com/0xMiden/miden-base/pull/1763))).
- [BREAKING] Merge the current and initial account code commitment procedures into one ([#1776](https://github.com/0xMiden/miden-base/pull/1776)).
- Added `TransactionExecutorError::InsufficientFee` variant([#1786](https://github.com/0xMiden/miden-base/pull/1786)).
- [BREAKING] Made source manager an instance variable of the `TransactionExecutor` ([#1788](https://github.com/0xMiden/miden-base/pull/1788)).

## 0.10.1 (2025-08-02)

- Added `NoAuth` component to the set of standard components ([#1620](https://github.com/0xMiden/miden-base/pull/1620)).

## 0.10.0 (2025-07-08)

### Features

- Added `bench-prover` crate to benchmark proving times ([#1378](https://github.com/0xMiden/miden-base/pull/1378)).
- Allowed NOOP transactions and state-updating transactions against the same account in the same block ([#1393](https://github.com/0xMiden/miden-base/pull/1393)).
- Added P2IDE standard note ([#1421](https://github.com/0xMiden/miden-base/pull/1421)).
- [BREAKING] Implemented transaction script arguments for the `TransactionScript` ([#1406](https://github.com/0xMiden/miden-base/pull/1406)).
- [BREAKING] Implemented in-kernel account delta tracking ([#1471](https://github.com/0xMiden/miden-base/pull/1471), [#1404](https://github.com/0xMiden/miden-base/pull/1404), [#1460](https://github.com/0xMiden/miden-base/pull/1460), [#1481](https://github.com/0xMiden/miden-base/pull/1481), [#1491](https://github.com/0xMiden/miden-base/pull/1491)).
- Add `with_auth_component` to `AccountBuilder` ([#1480](https://github.com/0xMiden/miden-base/pull/1480)).
- Added `ScriptBuilder` to streamline building note & transaction scripts ([#1507](https://github.com/0xMiden/miden-base/pull/1507)).
- Added procedure `was_procedure_called` to `miden::account` library module ([#1521](https://github.com/0xMiden/miden-base/pull/1521)).
- Enabled loading MASM source files into `TransactionKernel::assembler` for better errors ([#1527](https://github.com/0xMiden/miden-base/pull/1527)).

### Changes

- [BREAKING] Refactored `NoteTag` to an enum ([#1322](https://github.com/0xMiden/miden-base/pull/1322)).
- [BREAKING] Removed `AccountIdAnchor` from account ID generation process ([#1391](https://github.com/0xMiden/miden-base/pull/1391)).
- Implemented map based on a sorted linked list in transaction kernel library ([#1396](https://github.com/0xMiden/miden-base/pull/1396), [#1428](https://github.com/0xMiden/miden-base/pull/1428), [#1478](https://github.com/0xMiden/miden-base/pull/1478)).
- Added shutdown configuration options to the `miden-proving-service` proxy ([#1405](https://github.com/0xMiden/miden-base/pull/1405)).
- Added support for workers configuration in the proxy with environment variables ([#1412](https://github.com/0xMiden/miden-base/pull/1412)).
- Implemented `Display` for `NoteType` ([#1420](https://github.com/0xMiden/miden-base/pull/1420)).
- [BREAKING] Removed `NoteExecutionMode` from `from_account_id` ([#1422](https://github.com/0xMiden/miden-base/pull/1422)).
- [BREAKING] Refactored transaction kernel advice inputs ([#1425](https://github.com/0xMiden/miden-base/pull/1425)).
- [BREAKING] Moved transaction script argument from `TransactionScript` to `TransactionArgs`. ([#1426](https://github.com/0xMiden/miden-base/pull/1426)).
- [BREAKING] Removed transaction inputs from `TransactionScript`. ([#1426](https://github.com/0xMiden/miden-base/pull/1426)).
- Removed miden-proving-service binary crate and miden-proving-service-client crate ([#1427](https://github.com/0xMiden/miden-base/pull/1427)).
- Removed doc update checks on CI ([#1435](https://github.com/0xMiden/miden-base/pull/1435)).
- [BREAKING] Introduced `ScriptMastForestStore` and refactor MAST forest provisioning in the `TransactionExecutor` ([#1438](https://github.com/0xMiden/miden-base/pull/1438)).
- [BREAKING] Allowed list of keys in `AccountFile` ([#1451](https://github.com/0xMiden/miden-base/pull/1451)).
- [BREAKING] `TransactionHost::new` now expects `&PartialAccount` instead `AccountHeader` ([#1452](https://github.com/0xMiden/miden-base/pull/1452)).
- Load account and input notes advice maps into the advice provider before executing them ([#1452](https://github.com/0xMiden/miden-base/pull/1452)).
- Added support for private accounts in `MockChain` ([#1453](https://github.com/0xMiden/miden-base/pull/1453)).
- Improved error message quality in `CodeExecutor::run` and `TransactionContext::execute_code` ([#1458](https://github.com/0xMiden/miden-base/pull/1458)).
- Temporarily bumped ACCOUNT_UPDATE_MAX_SIZE to 256 KiB for compiler testing ([#1464](https://github.com/0xMiden/miden-base/pull/1464)).
- [BREAKING] `TransactionExecutor` now holds plain references instead of `Arc` for its trait objects ([#1469](https://github.com/0xMiden/miden-base/pull/1469)).
- [BREAKING] Store account ID in account delta ([#1493](https://github.com/0xMiden/miden-base/pull/1493)).
- [BREAKING] Removed P2IDR and replace with P2IDE ([#1483](https://github.com/0xMiden/miden-base/pull/1483)).
- [BREAKING] Refactored nonce in delta from `Option<Felt>` to `Felt` ([#1492](https://github.com/0xMiden/miden-base/pull/1492)).
- Normalized account deltas to avoid including no-op updates ([#1496](https://github.com/0xMiden/miden-base/pull/1496)).
- Added `Note::is_network_note()` accessor ([#1485](https://github.com/0xMiden/miden-base/pull/1485)).
- [BREAKING] Refactored account authentication to require a procedure containing `auth__` in its name ([#1480](https://github.com/0xMiden/miden-base/pull/1480)).
- [BREAKING] Updated handling of the shared modules ([#1490](https://github.com/0xMiden/miden-base/pull/1490)).
- [BREAKING] Refactored transaction to output `ACCOUNT_UPDATE_COMMITMENT` ([#1500](https://github.com/0xMiden/miden-base/pull/1500)).
- Added a new constructor for `TransactionExecutor` that accepts `ExecutionOptions` ([#1502](https://github.com/0xMiden/miden-base/pull/1502)).
- [BREAKING] Introduced errors in `MockChain` API ([#1508](https://github.com/0xMiden/miden-base/pull/1508)).
- [BREAKING] `TransactionAdviceInputs` cannot return `Err` anymore ([#1517](https://github.com/0xMiden/miden-base/pull/1517)).
- Implemented serialization for `LexicographicWord` ([#1524](https://github.com/0xMiden/miden-base/pull/1524)).
- Made `Account:increment_nonce()` method public ([#1533](https://github.com/0xMiden/miden-base/pull/1533)).
- Defined the commitment to an empty account delta as `EMPTY_WORD` ([#1528](https://github.com/0xMiden/miden-base/pull/1528)).
- [BREAKING] Renamed `account_get_current_commitment` to `account_compute_current_commitment` and include the latest storage commitment in the returned commitment ([#1529](https://github.com/0xMiden/miden-base/pull/1529)).
- [BREAKING] Remove `create_note` from `BasicWallet`, expose it and `add_asset_to_note` in `miden::tx` ([#1525](https://github.com/0xMiden/miden-base/pull/1525)).
- Add a new auth component `RpoFalcon512Acl` ([#1531](https://github.com/0xMiden/miden-base/pull/1531)).
- [BREAKING] Change `BasicFungibleFaucet` to use `RpoFalcon512Acl` for authentication ([#1531](https://github.com/0xMiden/miden-base/pull/1531)).
- Introduce `MockChain` methods for executing at an older block (#1541).
- [BREAKING] Change authentication component procedure name prefix from `auth__*` to `auth_*` ([#1861](https://github.com/0xMiden/miden-base/issues/1861)).

### Fixes

- [BREAKING] Forbid the execution of the empty transactions ([#1459](https://github.com/0xMiden/miden-base/pull/1459)).

## 0.9.5 (2025-06-20) - `miden-lib` crate only

- Added `symbol()`, `decimals()`, and `max_supply()` accessors to the `TokenSymbol` struct.

## 0.9.4 (2025-06-12)

- Refactor proving service client errors ([#1448](https://github.com/0xMiden/miden-base/pull/1448))

## 0.9.3 (2025-06-12)

- Add TLS support to `miden-proving-service-client` ([#1447](https://github.com/0xMiden/miden-base/pull/1447))

## 0.9.2 (2025-06-10)

- Refreshed Cargo.lock file.

## 0.9.1 (2025-05-30)

### Fixes

- Expose types used in public APIs ([#1385](https://github.com/0xMiden/miden-base/pull/1385)).
- Version check always fails in proxy ([#1407](https://github.com/0xMiden/miden-base/pull/1407)).

## 0.9.0 (2025-05-20)

### Features

- Added pretty print for `AccountCode` ([#1273](https://github.com/0xMiden/miden-base/pull/1273)).
- Add iterators over concrete asset types in `NoteAssets` ([#1346](https://github.com/0xMiden/miden-base/pull/1346)).
- Add the ability to create `BasicFungibleFaucet` from `Account` ([#1376](https://github.com/0xMiden/miden-base/pull/1376)).

### Fixes

- [BREAKING] Hash keys in storage maps before insertion into the SMT ([#1250](https://github.com/0xMiden/miden-base/pull/1250)).
- Fix error when creating accounts with empty storage ([#1307](https://github.com/0xMiden/miden-base/pull/1307)).
- [BREAKING] Move the number of note inputs to the separate memory address ([#1327](https://github.com/0xMiden/miden-base/pull/1327)).
- [BREAKING] Change Token Symbol encoding ([#1334](https://github.com/0xMiden/miden-base/pull/1334)).

### Changes

- [BREAKING] Refactored how foreign account inputs are passed to `TransactionExecutor` ([#1229](https://github.com/0xMiden/miden-base/pull/1229)).
- [BREAKING] Add `TransactionHeader` and include it in batches and blocks ([#1247](https://github.com/0xMiden/miden-base/pull/1247)).
- Add `AccountTree` and `PartialAccountTree` wrappers and enforce ID prefix uniqueness ([#1254](https://github.com/0xMiden/miden-base/pull/1254), [#1301](https://github.com/0xMiden/miden-base/pull/1301)).
- Added getter for proof security level in `ProvenBatch` and `ProvenBlock` ([#1259](https://github.com/0xMiden/miden-base/pull/1259)).
- [BREAKING] Replaced the `ProvenBatch::new_unchecked` with the `ProvenBatch::new` method to initialize the struct with validations ([#1260](https://github.com/0xMiden/miden-base/pull/1260)).
- [BREAKING] Add `AccountStorageMode::Network` for network accounts ([#1275](https://github.com/0xMiden/miden-base/pull/1275), [#1349](https://github.com/0xMiden/miden-base/pull/1349)).
- Added support for environment variables to set up the `miden-proving-service` worker ([#1281](https://github.com/0xMiden/miden-base/pull/1281)).
- Added field identifier structs for component metadata ([#1292](https://github.com/0xMiden/miden-base/pull/1292)).
- Move `NullifierTree` and `BlockChain` from node to base ([#1304](https://github.com/0xMiden/miden-base/pull/1304)).
- Rename `ChainMmr` to `PartialBlockchain` ([#1305](https://github.com/0xMiden/miden-base/pull/1305)).
- Add safe `PartialBlockchain` constructor ([#1308](https://github.com/0xMiden/miden-base/pull/1308)).
- [BREAKING] Move `MockChain` and `TransactionContext` to new `miden-testing` crate ([#1309](https://github.com/0xMiden/miden-base/pull/1309)).
- [BREAKING] Add support for private notes in `MockChain` ([#1310](https://github.com/0xMiden/miden-base/pull/1310)).
- Generalized account-related inputs to the transaction kernel ([#1311](https://github.com/0xMiden/miden-base/pull/1311)).
- [BREAKING] Refactor `MockChain` to use batch and block provers ([#1315](https://github.com/0xMiden/miden-base/pull/1315)).
- [BREAKING] Upgrade VM to 0.14 and refactor transaction kernel error extraction ([#1353](https://github.com/0xMiden/miden-base/pull/1353)).
- [BREAKING] Update MSRV to 1.87.

## 0.8.3 (2025-04-22) - `miden-proving-service` crate only

### Fixes

- Version check always fails ([#1300](https://github.com/0xMiden/miden-base/pull/1300)).

## 0.8.2 (2025-04-18) - `miden-proving-service` crate only

### Changes

- Added a retry strategy for worker's health check ([#1255](https://github.com/0xMiden/miden-base/pull/1255)).
- Added a status endpoint for the `miden-proving-service` worker and proxy ([#1255](https://github.com/0xMiden/miden-base/pull/1255)).

## 0.8.1 (2025-03-26) - `miden-objects` and `miden-tx` crates only.

### Changes

- [BREAKING] Changed `TransactionArgs` API to accept `AsRef<NoteRecipient>` for extending the advice map in relation to output notes ([#1251](https://github.com/0xMiden/miden-base/pull/1251)).

## 0.8.0 (2025-03-21)

### Features

- Added an endpoint to the `miden-proving-service` to update the workers ([#1107](https://github.com/0xMiden/miden-base/pull/1107)).
- [BREAKING] Added the `get_block_timestamp` procedure to the `miden` library ([#1138](https://github.com/0xMiden/miden-base/pull/1138)).
- Implemented `AccountInterface` structure ([#1171](https://github.com/0xMiden/miden-base/pull/1171)).
- Implement user-facing bech32 encoding for `AccountId`s ([#1185](https://github.com/0xMiden/miden-base/pull/1185)).
- Implemented `execute_tx_view_script` procedure for the `TransactionExecutor` ([#1197](https://github.com/0xMiden/miden-base/pull/1197)).
- Enabled nested FPI calls ([#1227](https://github.com/0xMiden/miden-base/pull/1227)).
- Implement `check_notes_consumability` procedure for the `TransactionExecutor` ([#1269](https://github.com/0xMiden/miden-base/pull/1269)).

### Changes

- [BREAKING] Moved `generated` module from `miden-proving-service-client` crate to `tx_prover::generated` hierarchy ([#1102](https://github.com/0xMiden/miden-base/pull/1102)).
- Renamed the protobuf file of the transaction prover to `tx_prover.proto` ([#1110](https://github.com/0xMiden/miden-base/pull/1110)).
- [BREAKING] Renamed `AccountData` to `AccountFile` ([#1116](https://github.com/0xMiden/miden-base/pull/1116)).
- Implement transaction batch prover in Rust ([#1112](https://github.com/0xMiden/miden-base/pull/1112)).
- Added the `is_non_fungible_asset_issued` procedure to the `miden` library ([#1125](https://github.com/0xMiden/miden-base/pull/1125)).
- [BREAKING] Refactored config file for `miden-proving-service` to be based on environment variables ([#1120](https://github.com/0xMiden/miden-base/pull/1120)).
- Added block number as a public input to the transaction kernel. Updated prologue logic to validate the global input block number is consistent with the commitment block number ([#1126](https://github.com/0xMiden/miden-base/pull/1126)).
- Made NoteFile and AccountFile more consistent ([#1133](https://github.com/0xMiden/miden-base/pull/1133)).
- [BREAKING] Implement most block constraints in `ProposedBlock` ([#1123](https://github.com/0xMiden/miden-base/pull/1123), [#1141](https://github.com/0xMiden/miden-base/pull/1141)).
- Added serialization for `ProposedBatch`, `BatchId`, `BatchNoteTree` and `ProvenBatch` ([#1140](https://github.com/0xMiden/miden-base/pull/1140)).
- Added `prefix` to `Nullifier` ([#1153](https://github.com/0xMiden/miden-base/pull/1153)).
- [BREAKING] Implemented a `RemoteBatchProver`. `miden-proving-service` workers can prove batches ([#1142](https://github.com/0xMiden/miden-base/pull/1142)).
- [BREAKING] Implement `LocalBlockProver` and rename `Block` to `ProvenBlock` ([#1152](https://github.com/0xMiden/miden-base/pull/1152), [#1168](https://github.com/0xMiden/miden-base/pull/1168), [#1172](https://github.com/0xMiden/miden-base/pull/1172)).
- [BREAKING] Added native types to `AccountComponentTemplate` ([#1124](https://github.com/0xMiden/miden-base/pull/1124)).
- Implemented `RemoteBlockProver`. `miden-proving-service` workers can prove blocks ([#1169](https://github.com/0xMiden/miden-base/pull/1169)).
- Used `Smt::with_entries` to error on duplicates in `StorageMap::with_entries` ([#1167](https://github.com/0xMiden/miden-base/pull/1167)).
- [BREAKING] Added `InitStorageData::from_toml()`, improved storage entry validations in `AccountComponentMetadata` ([#1170](https://github.com/0xMiden/miden-base/pull/1170)).
- [BREAKING] Rework miden-lib error codes into categories ([#1196](https://github.com/0xMiden/miden-base/pull/1196)).
- [BREAKING] Moved the `TransactionScriptBuilder` from `miden-client` to `miden-base` ([#1206](https://github.com/0xMiden/miden-base/pull/1206)).
- [BREAKING] Enable timestamp customization on `MockChain::seal_block` ([#1208](https://github.com/0xMiden/miden-base/pull/1208)).
- [BREAKING] Renamed constants and comments: `OnChain` -> `Public` and `OffChain` -> `Private` ([#1218](https://github.com/0xMiden/miden-base/pull/1218)).
- [BREAKING] Replace "hash" with "commitment" in `BlockHeader::{prev_hash, chain_root, kernel_root, tx_hash, proof_hash, sub_hash, hash}` ([#1209](https://github.com/0xMiden/miden-base/pull/1209), [#1221](https://github.com/0xMiden/miden-base/pull/1221), [#1226](https://github.com/0xMiden/miden-base/pull/1226)).
- [BREAKING] Incremented minimum supported Rust version to 1.85.
- [BREAKING] Change advice for Falcon signature verification ([#1183](https://github.com/0xMiden/miden-base/pull/1183)).
- Added `info` log level by default in the proving service ([#1200](https://github.com/0xMiden/miden-base/pull/1200)).
- Made Prometheus metrics optional in the proving service proxy via the `enable_metrics` configuration option ([#1200](https://github.com/0xMiden/miden-base/pull/1200)).
- Improved logging in the proving service proxy for better diagnostics ([#1200](https://github.com/0xMiden/miden-base/pull/1200)).
- Fixed issues with the proving service proxy's signal handling and port binding ([#1200](https://github.com/0xMiden/miden-base/pull/1200)).
- [BREAKING] Simplified worker update configuration by using a single URL parameter instead of separate host and port ([#1249](https://github.com/0xMiden/miden-base/pull/1249)).

## 0.7.2 (2025-01-28) - `miden-objects` crate only

### Changes

- Added serialization for `ExecutedTransaction` ([#1113](https://github.com/0xMiden/miden-base/pull/1113)).

## 0.7.1 (2025-01-24) - `miden-objects` crate only

### Fixes

- Added missing doc comments ([#1100](https://github.com/0xMiden/miden-base/pull/1100)).
- Fixed setting of supporting types when instantiating `AccountComponent` from templates ([#1103](https://github.com/0xMiden/miden-base/pull/1103)).

## 0.7.0 (2025-01-22)

### Highlights

- [BREAKING] Extend `AccountId` to two `Felt`s and require block hash in derivation ([#982](https://github.com/0xMiden/miden-base/pull/982)).
- Introduced `AccountComponentTemplate` with TOML serialization and templating ([#1015](https://github.com/0xMiden/miden-base/pull/1015), [#1027](https://github.com/0xMiden/miden-base/pull/1027)).
- Introduce `AccountIdBuilder` to simplify `AccountId` generation in tests ([#1045](https://github.com/0xMiden/miden-base/pull/1045)).
- [BREAKING] Migrate to the element-addressable memory ([#1084](https://github.com/0xMiden/miden-base/pull/1084)).

### Changes

- Implemented serialization for `AccountHeader` ([#996](https://github.com/0xMiden/miden-base/pull/996)).
- Updated Pingora crates to 0.4 and added polling time to the configuration file ([#997](https://github.com/0xMiden/miden-base/pull/997)).
- Added support for `miden-tx-prover` proxy to update workers on a running proxy ([#989](https://github.com/0xMiden/miden-base/pull/989)).
- Refactored `miden-tx-prover` proxy load balancing strategy ([#976](https://github.com/0xMiden/miden-base/pull/976)).
- [BREAKING] Implemented better error display when queues are full in the prover service ([#967](https://github.com/0xMiden/miden-base/pull/967)).
- [BREAKING] Removed `AccountBuilder::build_testing` and make `Account::initialize_from_components` private ([#969](https://github.com/0xMiden/miden-base/pull/969)).
- [BREAKING] Added error messages to errors and implement `core::error::Error` ([#974](https://github.com/0xMiden/miden-base/pull/974)).
- Implemented new `digest!` macro ([#984](https://github.com/0xMiden/miden-base/pull/984)).
- Added Format Guidebook to the `miden-lib` crate ([#987](https://github.com/0xMiden/miden-base/pull/987)).
- Added conversion from `Account` to `AccountDelta` for initial account state representation as delta ([#983](https://github.com/0xMiden/miden-base/pull/983)).
- [BREAKING] Added `miden::note::get_script_hash` procedure ([#995](https://github.com/0xMiden/miden-base/pull/995)).
- [BREAKING] Refactor error messages in `miden-lib` and `miden-tx` and use `thiserror` 2.0 ([#1005](https://github.com/0xMiden/miden-base/pull/1005), [#1090](https://github.com/0xMiden/miden-base/pull/1090)).
- Added health check endpoints to the prover service ([#1006](https://github.com/0xMiden/miden-base/pull/1006)).
- Removed workers list from the proxy configuration file ([#1018](https://github.com/0xMiden/miden-base/pull/1018)).
- Added tracing to the `miden-tx-prover` CLI ([#1014](https://github.com/0xMiden/miden-base/pull/1014)).
- Added metrics to the `miden-tx-prover` proxy ([#1017](https://github.com/0xMiden/miden-base/pull/1017)).
- Implemented `to_hex` for `AccountIdPrefix` and `epoch_block_num` for `BlockHeader` ([#1039](https://github.com/0xMiden/miden-base/pull/1039)).
- [BREAKING] Updated the names and values of the kernel procedure offsets and corresponding kernel procedures ([#1037](https://github.com/0xMiden/miden-base/pull/1037)).
- Introduce `AccountIdError` and make account ID byte representations (`u128`, `[u8; 15]`) consistent ([#1055](https://github.com/0xMiden/miden-base/pull/1055)).
- Refactor `AccountId` and `AccountIdPrefix` into version wrappers ([#1058](https://github.com/0xMiden/miden-base/pull/1058)).
- Remove multi-threaded account seed generation due to single-threaded generation being faster ([#1061](https://github.com/0xMiden/miden-base/pull/1061)).
- Made `AccountIdError` public ([#1067](https://github.com/0xMiden/miden-base/pull/1067)).
- Made `BasicFungibleFaucet::MAX_DECIMALS` public ([#1063](https://github.com/0xMiden/miden-base/pull/1063)).
- [BREAKING] Removed `miden-tx-prover` crate and created `miden-proving-service` and `miden-proving-service-client` ([#1047](https://github.com/0xMiden/miden-base/pull/1047)).
- Removed deduplicate `masm` procedures across kernel and miden lib to a shared `util` module ([#1070](https://github.com/0xMiden/miden-base/pull/1070)).
- [BREAKING] Added `BlockNumber` struct ([#1043](https://github.com/0xMiden/miden-base/pull/1043), [#1080](https://github.com/0xMiden/miden-base/pull/1080), [#1082](https://github.com/0xMiden/miden-base/pull/1082)).
- [BREAKING] Removed `GENESIS_BLOCK` public constant ([#1088](https://github.com/0xMiden/miden-base/pull/1088)).
- Add CI check for unused dependencies ([#1075](https://github.com/0xMiden/miden-base/pull/1075)).
- Added storage placeholder types and support for templated map ([#1074](https://github.com/0xMiden/miden-base/pull/1074)).
- [BREAKING] Move crates into `crates/` and rename plural modules to singular ([#1091](https://github.com/0xMiden/miden-base/pull/1091)).

## 0.6.2 (2024-11-20)

- Avoid writing to the filesystem during docs.rs build ([#970](https://github.com/0xMiden/miden-base/pull/970)).

## 0.6.1 (2024-11-08)

### Features

- [BREAKING] Added CLI for the transaction prover services both the workers and the proxy ([#955](https://github.com/0xMiden/miden-base/pull/955)).

### Fixes

- Fixed `AccountId::new_with_type_and_mode()` ([#958](https://github.com/0xMiden/miden-base/pull/958)).
- Updated the ABI for the assembly procedures ([#971](https://github.com/0xMiden/miden-base/pull/971)).

## 0.6.0 (2024-11-05)

### Features

- Created a proving service that receives `TransactionWitness` and returns the proof using gRPC ([#881](https://github.com/0xMiden/miden-base/pull/881)).
- Implemented ability to invoke procedures against the foreign account ([#882](https://github.com/0xMiden/miden-base/pull/882), [#890](https://github.com/0xMiden/miden-base/pull/890), [#896](https://github.com/0xMiden/miden-base/pull/896)).
- Implemented kernel procedure to set transaction expiration block delta ([#897](https://github.com/0xMiden/miden-base/pull/897)).
- [BREAKING] Introduce a new way to build `Account`s from `AccountComponent`s ([#941](https://github.com/0xMiden/miden-base/pull/941)).
- [BREAKING] Introduce an `AccountBuilder` ([#952](https://github.com/0xMiden/miden-base/pull/952)).

### Changes

- [BREAKING] Changed `TransactionExecutor` and `TransactionHost` to use trait objects ([#897](https://github.com/0xMiden/miden-base/pull/897)).
- Made note scripts public ([#880](https://github.com/0xMiden/miden-base/pull/880)).
- Implemented serialization for `TransactionWitness`, `ChainMmr`, `TransactionInputs` and `TransactionArgs` ([#888](https://github.com/0xMiden/miden-base/pull/888)).
- [BREAKING] Renamed the `TransactionProver` struct to `LocalTransactionProver` and added the `TransactionProver` trait ([#865](https://github.com/0xMiden/miden-base/pull/865)).
- Implemented `Display`, `TryFrom<&str>` and `FromStr` for `AccountStorageMode` ([#861](https://github.com/0xMiden/miden-base/pull/861)).
- Implemented offset based storage access ([#843](https://github.com/0xMiden/miden-base/pull/843)).
- [BREAKING] `AccountStorageType` enum was renamed to `AccountStorageMode` along with its variants ([#854](https://github.com/0xMiden/miden-base/pull/854)).
- [BREAKING] `AccountStub` structure was renamed to `AccountHeader` ([#855](https://github.com/0xMiden/miden-base/pull/855)).
- [BREAKING] Kernel procedures now have to be invoked using `dynexec` instruction ([#803](https://github.com/0xMiden/miden-base/pull/803)).
- Refactored `AccountStorage` from `Smt` to sequential hash ([#846](https://github.com/0xMiden/miden-base/pull/846)).
- [BREAKING] Refactored batch/block note trees ([#834](https://github.com/0xMiden/miden-base/pull/834)).
- Set all procedures storage offsets of faucet accounts to `1` ([#875](https://github.com/0xMiden/miden-base/pull/875)).
- Added `AccountStorageHeader` ([#876](https://github.com/0xMiden/miden-base/pull/876)).
- Implemented generation of transaction kernel procedure hashes in build.rs ([#887](https://github.com/0xMiden/miden-base/pull/887)).
- [BREAKING] `send_asset` procedure was removed from the basic wallet ([#829](https://github.com/0xMiden/miden-base/pull/829)).
- [BREAKING] Updated limits, introduced additional limits ([#889](https://github.com/0xMiden/miden-base/pull/889)).
- Introduced `AccountDelta` maximum size limit of 32 KiB ([#889](https://github.com/0xMiden/miden-base/pull/889)).
- [BREAKING] Moved `MAX_NUM_FOREIGN_ACCOUNTS` into `miden-objects` ([#904](https://github.com/0xMiden/miden-base/pull/904)).
- Implemented `storage_size`, updated storage bounds ([#886](https://github.com/0xMiden/miden-base/pull/886)).
- [BREAKING] Auto-generate `KERNEL_ERRORS` list from the transaction kernel's MASM files and rework error constant names ([#906](https://github.com/0xMiden/miden-base/pull/906)).
- Implement `Serializable` for `FungibleAsset` ([#907](https://github.com/0xMiden/miden-base/pull/907)).
- [BREAKING] Changed `TransactionProver` trait to be `maybe_async_trait` based on the `async` feature ([#913](https://github.com/0xMiden/miden-base/pull/913)).
- [BREAKING] Changed type of `EMPTY_STORAGE_MAP_ROOT` constant to `RpoDigst`, which references constant from `miden-crypto` ([#916](https://github.com/0xMiden/miden-base/pull/916)).
- Added `RemoteTransactionProver` struct to `miden-tx-prover` ([#921](https://github.com/0xMiden/miden-base/pull/921)).
- [BREAKING] Migrated to v0.11 version of Miden VM ([#929](https://github.com/0xMiden/miden-base/pull/929)).
- Added `total_cycles` and `trace_length` to the `TransactionMeasurements` ([#953](https://github.com/0xMiden/miden-base/pull/953)).
- Added ability to load libraries into `TransactionExecutor` and `LocalTransactionProver` ([#954](https://github.com/0xMiden/miden-base/pull/954)).

## 0.5.1 (2024-08-28) - `miden-objects` crate only

- Implemented `PrettyPrint` and `Display` for `NoteScript`.

## 0.5.0 (2024-08-27)

### Features

- [BREAKING] Increase of nonce does not require changes in account state any more ([#796](https://github.com/0xMiden/miden-base/pull/796)).
- Changed `AccountCode` procedures from merkle tree to sequential hash + added storage_offset support ([#763](https://github.com/0xMiden/miden-base/pull/763)).
- Implemented merging of account deltas ([#797](https://github.com/0xMiden/miden-base/pull/797)).
- Implemented `create_note` and `move_asset_into_note` basic wallet procedures ([#808](https://github.com/0xMiden/miden-base/pull/808)).
- Made `miden_lib::notes::build_swap_tag()` function public ([#817](https://github.com/0xMiden/miden-base/pull/817)).
- [BREAKING] Changed the `NoteFile::NoteDetails` type to struct and added a `after_block_num` field ([#823](https://github.com/0xMiden/miden-base/pull/823)).

### Changes

- Renamed "consumed" and "created" notes into "input" and "output" respectively ([#791](https://github.com/0xMiden/miden-base/pull/791)).
- [BREAKING] Renamed `NoteType::OffChain` into `NoteType::Private`.
- [BREAKING] Renamed public accessors of the `Block` struct to match the updated fields ([#791](https://github.com/0xMiden/miden-base/pull/791)).
- [BREAKING] Changed the `TransactionArgs` to use `AdviceInputs` ([#793](https://github.com/0xMiden/miden-base/pull/793)).
- Setters in `memory` module don't drop the setting `Word` anymore ([#795](https://github.com/0xMiden/miden-base/pull/795)).
- Added `CHANGELOG.md` warning message on CI ([#799](https://github.com/0xMiden/miden-base/pull/799)).
- Added high-level methods for `MockChain` and related structures ([#807](https://github.com/0xMiden/miden-base/pull/807)).
- [BREAKING] Renamed `NoteExecutionHint` to `NoteExecutionMode` and added new `NoteExecutionHint` to `NoteMetadata` ([#812](https://github.com/0xMiden/miden-base/pull/812), [#816](https://github.com/0xMiden/miden-base/pull/816)).
- [BREAKING] Changed the interface of the `miden::tx::add_asset_to_note` ([#808](https://github.com/0xMiden/miden-base/pull/808)).
- [BREAKING] Refactored and simplified `NoteOrigin` and `NoteInclusionProof` structs ([#810](https://github.com/0xMiden/miden-base/pull/810), [#814](https://github.com/0xMiden/miden-base/pull/814)).
- [BREAKING] Refactored account storage and vault deltas ([#822](https://github.com/0xMiden/miden-base/pull/822)).
- Added serialization and equality comparison for `TransactionScript` ([#824](https://github.com/0xMiden/miden-base/pull/824)).
- [BREAKING] Migrated to Miden VM v0.10 ([#826](https://github.com/0xMiden/miden-base/pull/826)).
- Added conversions for `NoteExecutionHint` ([#827](https://github.com/0xMiden/miden-base/pull/827)).
- [BREAKING] Removed `serde`-based serialization from `miden-object` structs ([#838](https://github.com/0xMiden/miden-base/pull/838)).

## 0.4.0 (2024-07-03)

### Features

- [BREAKING] Introduce `OutputNote::Partial` variant ([#698](https://github.com/0xMiden/miden-base/pull/698)).
- [BREAKING] Added support for input notes with delayed verification of inclusion proofs ([#724](https://github.com/0xMiden/miden-base/pull/724), [#732](https://github.com/0xMiden/miden-base/pull/732), [#759](https://github.com/0xMiden/miden-base/pull/759), [#770](https://github.com/0xMiden/miden-base/pull/770), [#772](https://github.com/0xMiden/miden-base/pull/772)).
- Added new `NoteFile` object to represent serialized notes ([#721](https://github.com/0xMiden/miden-base/pull/721)).
- Added transaction IDs to the `Block` struct ([#734](https://github.com/0xMiden/miden-base/pull/734)).
- Added ability for users to set the aux field when creating a note ([#752](https://github.com/0xMiden/miden-base/pull/752)).

### Enhancements

- Replaced `cargo-make` with just `make` for running tasks ([#696](https://github.com/0xMiden/miden-base/pull/696)).
- [BREAKING] Split `Account` struct constructor into `new()` and `from_parts()` ([#699](https://github.com/0xMiden/miden-base/pull/699)).
- Generalized `build_recipient_hash` procedure to build recipient hash for custom notes ([#706](https://github.com/0xMiden/miden-base/pull/706)).
- [BREAKING] Changed the encoding of inputs notes in the advice map for consumed notes ([#707](https://github.com/0xMiden/miden-base/pull/707)).
- Created additional `emit` events for kernel related `.masm` procedures ([#708](https://github.com/0xMiden/miden-base/pull/708)).
- Implemented `build_recipient_hash` procedure to build recipient hash for custom notes ([#710](https://github.com/0xMiden/miden-base/pull/710)).
- Removed the `mock` crate in favor of having mock code behind the `testing` flag in remaining crates ([#711](https://github.com/0xMiden/miden-base/pull/711)).
- [BREAKING] Created `auth` module for `TransactionAuthenticator` and other related objects ([#714](https://github.com/0xMiden/miden-base/pull/714)).
- Added validation for the output stack to make sure it was properly cleaned ([#717](https://github.com/0xMiden/miden-base/pull/717)).
- Made `DataStore` conditionally async using `winter-maybe-async` ([#725](https://github.com/0xMiden/miden-base/pull/725)).
- Changed note pointer from Memory `note_ptr` to `note_index` ([#728](https://github.com/0xMiden/miden-base/pull/728)).
- [BREAKING] Changed rng to mutable reference in note creation functions ([#733](https://github.com/0xMiden/miden-base/pull/733)).
- [BREAKING] Replaced `ToNullifier` trait with `ToInputNoteCommitments`, which includes the `note_id` for delayed note authentication ([#732](https://github.com/0xMiden/miden-base/pull/732)).
- Added `Option<NoteTag>`to `NoteFile` ([#741](https://github.com/0xMiden/miden-base/pull/741)).
- Fixed documentation and added `make doc` CI job ([#746](https://github.com/0xMiden/miden-base/pull/746)).
- Updated and improved [.pre-commit-config.yaml](.pre-commit-config.yaml) file ([#748](https://github.com/0xMiden/miden-base/pull/748)).
- Created `get_serial_number` procedure to get the serial num of the currently processed note ([#760](https://github.com/0xMiden/miden-base/pull/760)).
- [BREAKING] Added support for conversion from `Nullifier` to `InputNoteCommitment`, commitment header return reference ([#774](https://github.com/0xMiden/miden-base/pull/774)).
- Added `compute_inputs_hash` procedure for hash computation of the arbitrary number of note inputs ([#750](https://github.com/0xMiden/miden-base/pull/750)).

## 0.3.1 (2024-06-12)

- Replaced `cargo-make` with just `make` for running tasks ([#696](https://github.com/0xMiden/miden-base/pull/696)).
- Made `DataStore` conditionally async using `winter-maybe-async` ([#725](https://github.com/0xMiden/miden-base/pull/725))
- Fixed `StorageMap`s implementation and included into apply_delta ([#745](https://github.com/0xMiden/miden-base/pull/745))

## 0.3.0 (2024-05-14)

- Introduce the `miden-bench-tx` crate used for transactions benchmarking ([#577](https://github.com/0xMiden/miden-base/pull/577)).
- [BREAKING] Removed the transaction script root output from the transaction kernel ([#608](https://github.com/0xMiden/miden-base/pull/608)).
- [BREAKING] Refactored account update details, moved `Block` to `miden-objects` ([#618](https://github.com/0xMiden/miden-base/pull/618), [#621](https://github.com/0xMiden/miden-base/pull/621)).
- [BREAKING] Made `TransactionExecutor` generic over `TransactionAuthenticator` ([#628](https://github.com/0xMiden/miden-base/pull/628)).
- [BREAKING] Changed type of `version` and `timestamp` fields to `u32`, moved `version` to the beginning of block header ([#639](https://github.com/0xMiden/miden-base/pull/639)).
- [BREAKING] Renamed `NoteEnvelope` into `NoteHeader` and introduced `NoteDetails` ([#664](https://github.com/0xMiden/miden-base/pull/664)).
- [BREAKING] Updated `create_swap_note()` procedure to return `NoteDetails` and defined SWAP note tag format ([#665](https://github.com/0xMiden/miden-base/pull/665)).
- Implemented `OutputNoteBuilder` ([#669](https://github.com/0xMiden/miden-base/pull/669)).
- [BREAKING] Added support for full details of private notes, renamed `OutputNote` variants and changed their meaning ([#673](https://github.com/0xMiden/miden-base/pull/673)).
- [BREAKING] Added `add_asset_to_note` procedure to the transaction kernel ([#674](https://github.com/0xMiden/miden-base/pull/674)).
- Made `TransactionArgs::add_expected_output_note()` more flexible ([#681](https://github.com/0xMiden/miden-base/pull/681)).
- [BREAKING] Enabled support for notes without assets and refactored `create_note` procedure in the transaction kernel ([#686](https://github.com/0xMiden/miden-base/pull/686)).

## 0.2.3 (2024-04-26) - `miden-tx` crate only

- Fixed handling of debug mode in `TransactionExecutor` ([#627](https://github.com/0xMiden/miden-base/pull/627))

## 0.2.2 (2024-04-23) - `miden-tx` crate only

- Added `with_debug_mode()` methods to `TransactionCompiler` and `TransactionExecutor` ([#562](https://github.com/0xMiden/miden-base/pull/562)).

## 0.2.1 (2024-04-12)

- [BREAKING] Return a reference to `NoteMetadata` from output notes ([#593](https://github.com/0xMiden/miden-base/pull/593)).
- Add more type conversions for `NoteType` ([#597](https://github.com/0xMiden/miden-base/pull/597)).
- Fix note input padding for expected output notes ([#598](https://github.com/0xMiden/miden-base/pull/598)).

## 0.2.0 (2024-04-11)

- [BREAKING] Implement support for public accounts ([#481](https://github.com/0xMiden/miden-base/pull/481), [#485](https://github.com/0xMiden/miden-base/pull/485), [#538](https://github.com/0xMiden/miden-base/pull/538)).
- [BREAKING] Implement support for public notes ([#515](https://github.com/0xMiden/miden-base/pull/515), [#540](https://github.com/0xMiden/miden-base/pull/540), [#572](https://github.com/0xMiden/miden-base/pull/572)).
- Improved `ProvenTransaction` validation ([#532](https://github.com/0xMiden/miden-base/pull/532)).
- [BREAKING] Updated `no-std` setup ([#533](https://github.com/0xMiden/miden-base/pull/533)).
- Improved `ProvenTransaction` serialization ([#543](https://github.com/0xMiden/miden-base/pull/543)).
- Implemented note tree wrapper structs ([#560](https://github.com/0xMiden/miden-base/pull/560)).
- [BREAKING] Migrated to v0.9 version of Miden VM ([#567](https://github.com/0xMiden/miden-base/pull/567)).
- [BREAKING] Added account storage type parameter to `create_basic_wallet` and `create_basic_fungible_faucet` (miden-lib
  crate only) ([#587](https://github.com/0xMiden/miden-base/pull/587)).
- Removed serialization of source locations from account code ([#590](https://github.com/0xMiden/miden-base/pull/590)).

## 0.1.1 (2024-03-07) - `miden-objects` crate only

- Added `BlockHeader::mock()` method ([#511](https://github.com/0xMiden/miden-base/pull/511))

## 0.1.0 (2024-03-05)

- Initial release.
