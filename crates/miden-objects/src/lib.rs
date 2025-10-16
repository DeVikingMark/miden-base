#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod account;
pub mod address;
pub mod asset;
pub mod batch;
pub mod block;
pub mod note;
pub mod transaction;

#[cfg(any(feature = "testing", test))]
pub mod testing;

mod constants;
mod errors;

// RE-EXPORTS
// ================================================================================================

pub use constants::*;
pub use errors::{
    AccountDeltaError,
    AccountError,
    AccountIdError,
    AccountTreeError,
    AddressError,
    AssetError,
    AssetVaultError,
    BatchAccountUpdateError,
    FeeError,
    NetworkIdError,
    NoteError,
    NullifierTreeError,
    PartialBlockchainError,
    ProposedBatchError,
    ProposedBlockError,
    ProvenBatchError,
    ProvenTransactionError,
    SlotNameError,
    StorageMapError,
    TokenSymbolError,
    TransactionInputError,
    TransactionOutputError,
    TransactionScriptError,
};
pub use miden_core::mast::{MastForest, MastNodeId};
pub use miden_core::prettier::PrettyPrint;
pub use miden_core::{EMPTY_WORD, Felt, FieldElement, ONE, StarkField, WORD_SIZE, ZERO};
pub use miden_crypto::hash::rpo::Rpo256 as Hasher;
pub use miden_crypto::word;
pub use miden_crypto::word::{LexicographicWord, Word, WordError};

pub mod assembly {
    pub use miden_assembly::ast::{Module, ModuleKind, ProcedureName, QualifiedProcedureName};
    pub use miden_assembly::debuginfo::SourceManagerSync;
    pub use miden_assembly::{
        Assembler,
        DefaultSourceManager,
        KernelLibrary,
        Library,
        LibraryNamespace,
        LibraryPath,
        Parse,
        ParseOptions,
        SourceFile,
        SourceId,
        SourceManager,
        SourceSpan,
        debuginfo,
        diagnostics,
        mast,
    };
}

pub mod crypto {
    pub use miden_crypto::{SequentialCommit, dsa, hash, merkle, rand, utils};
}

pub mod utils {
    pub use miden_core::utils::*;
    pub use miden_crypto::utils::{HexParseError, bytes_to_hex_string, hex_to_bytes};
    pub use miden_utils_sync as sync;

    pub mod serde {
        pub use miden_core::utils::{
            ByteReader,
            ByteWriter,
            Deserializable,
            DeserializationError,
            Serializable,
        };
    }
}

pub mod vm {
    pub use miden_assembly_syntax::ast::{AttributeSet, QualifiedProcedureName};
    pub use miden_core::sys_events::SystemEvent;
    pub use miden_core::{AdviceMap, Program, ProgramInfo};
    pub use miden_mast_package::{MastArtifact, Package, PackageExport, PackageManifest};
    pub use miden_processor::{AdviceInputs, FutureMaybeSend, RowIndex, StackInputs, StackOutputs};
    pub use miden_verifier::ExecutionProof;
}
