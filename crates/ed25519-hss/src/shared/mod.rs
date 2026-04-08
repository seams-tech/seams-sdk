pub mod context;
pub mod error;
pub mod reference;
pub mod reference_boundary;

pub use context::CanonicalContext;
pub use error::{ProtoError, ProtoResult};
pub use reference::{
    add_le_bytes_mod_2_256, clamp_rfc8032, derive_output_shares, eval_f_expand,
    eval_nonlinear_expansion, extract_a_bytes_from_hash, public_key_from_base_shares,
    public_key_from_scalar_bytes, recover_a_from_base_shares, reduce_scalar_mod_l,
    sha512_one_block, FExpandInput, FExpandOutput, NonlinearExpansionOutput,
    OutputShareDerivationOutput,
};
pub use reference_boundary::{eval_f_expand_visible_boundary, visible_boundary_from_output, FExpandVisibleBoundary};
