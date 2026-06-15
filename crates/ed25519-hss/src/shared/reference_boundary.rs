use crate::shared::{eval_f_expand, FExpandInput, FExpandOutput, ProtoResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FExpandVisibleBoundary {
    pub canonical_seed: [u8; 32],
    pub x_client_base: [u8; 32],
    pub x_server_base: [u8; 32],
}

pub fn visible_boundary_from_output(output: &FExpandOutput) -> FExpandVisibleBoundary {
    FExpandVisibleBoundary {
        canonical_seed: output.d,
        x_client_base: output.x_client_base,
        x_server_base: output.x_server_base,
    }
}

pub fn eval_f_expand_visible_boundary(input: &FExpandInput) -> ProtoResult<FExpandVisibleBoundary> {
    let output = eval_f_expand(input)?;
    Ok(visible_boundary_from_output(&output))
}
