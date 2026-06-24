use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::shared::{
    eval_f_expand, CanonicalContext, FExpandInput, FExpandOutput, ProtoError, ProtoResult,
};

pub const FIXED_HIDDEN_CORE_CANDIDATE_VERSION: &str = "fixed_hidden_core_candidate_v0";
pub const FIXED_HIDDEN_CORE_FUNCTION_ID: &str =
    "ed25519_seed_expand/one_block_sha512_clamp_share_output_v0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateBackendFamily {
    PrimeOrderSizeOptimized,
    PrimeOrderComputeOptimized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateBackendSpec {
    pub family: CandidateBackendFamily,
    pub source: String,
    pub public_data_bits: u64,
    pub public_data_bytes: u64,
    pub parameter_summary: Vec<String>,
    pub evaluator_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedHiddenCoreCandidate {
    pub candidate_version: String,
    pub fixed_function_id: String,
    pub context_descriptor: CandidateContextDescriptor,
    pub context_binding: [u8; 32],
    pub backend: CandidateBackendSpec,
    pub template: CandidateTemplateArtifact,
    pub artifact_inventory: CandidateArtifactInventory,
    pub message_flow: Vec<CandidateMessageStep>,
    pub evaluator_plan: CandidateEvaluatorPlan,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateContextDescriptor {
    pub application_binding_digest: [u8; 32],
    pub participant_ids: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateTemplateArtifact {
    pub candidate_digest: [u8; 32],
    pub round_template_digest: [u8; 32],
    pub template_descriptor_bytes: u64,
    pub context_bound: bool,
    pub fixed_function_only: bool,
    pub cross_session_reusable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateArtifactInventory {
    pub totals: CandidateArtifactTotals,
    pub line_items: Vec<CandidateArtifactLineItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateArtifactTotals {
    pub template_descriptor_bytes: u64,
    pub known_cross_session_public_bytes: u64,
    pub known_per_run_public_control_bytes: u64,
    pub known_per_run_client_private_input_bytes: u64,
    pub known_per_run_server_private_input_bytes: u64,
    pub known_structural_internal_bytes: u64,
    pub known_client_output_bytes: u64,
    pub known_server_output_bytes: u64,
    pub known_public_output_bytes: u64,
    pub unknown_encoded_payload_item_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateArtifactLineItem {
    pub name: String,
    pub scope: ArtifactScope,
    pub visibility: ArtifactVisibility,
    pub logical_width_bytes: u64,
    pub encoded_width_bytes: Option<u64>,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactScope {
    CrossSessionTemplate,
    PerRunPublicControl,
    ClientPrivateInput,
    ServerPrivateInput,
    StructuralInternal,
    ClientOutput,
    ServerOutput,
    PublicOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactVisibility {
    Public,
    ClientPrivate,
    ServerPrivate,
    HiddenEvaluator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateMessageStep {
    pub step: u8,
    pub actor: String,
    pub direction: String,
    pub artifact_names: Vec<String>,
    pub description: String,
    pub reuse_scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateEvaluatorPlan {
    pub hidden_core_stages: Vec<String>,
    pub cross_session_reuse: Vec<String>,
    pub structural_reuse: Vec<String>,
    pub cpu_fallback: CandidateExecutionPath,
    pub accelerator_path: CandidateExecutionPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateExecutionPath {
    pub label: String,
    pub preferred_surfaces: Vec<String>,
    pub target_latency_ms: Option<u64>,
    pub assumptions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSimulationReport {
    pub candidate: FixedHiddenCoreCandidate,
    pub client_input_commitment: [u8; 32],
    pub server_input_commitment: [u8; 32],
    pub run_binding: [u8; 32],
    pub output: FExpandOutput,
}

pub fn build_fixed_hidden_core_candidate(
    context: &CanonicalContext,
) -> ProtoResult<FixedHiddenCoreCandidate> {
    build_fixed_hidden_core_candidate_for_backend(
        context,
        CandidateBackendFamily::PrimeOrderSizeOptimized,
    )
}

pub fn build_fixed_hidden_core_candidate_for_backend(
    context: &CanonicalContext,
    backend_family: CandidateBackendFamily,
) -> ProtoResult<FixedHiddenCoreCandidate> {
    let normalized_context = context.normalized()?;
    let context_binding = normalized_context.binding_digest()?;
    let backend = backend_spec(backend_family);
    let round_template_digest = sha256_concat(&[
        b"succinct-garbling-proto/round-template/v0",
        &context_binding,
        backend_family.as_str().as_bytes(),
    ]);

    let template_descriptor = TemplateDescriptorDigestView {
        candidate_version: FIXED_HIDDEN_CORE_CANDIDATE_VERSION.to_string(),
        fixed_function_id: FIXED_HIDDEN_CORE_FUNCTION_ID.to_string(),
        backend_family: backend_family.as_str().to_string(),
        context_binding,
        round_template_digest,
        estimated_public_data_bytes: backend.public_data_bytes,
        participant_ids: normalized_context.participant_ids.clone(),
    };

    let template_descriptor_bytes = bincode::serialize(&template_descriptor)
        .map_err(|err| {
            ProtoError::Decode(format!(
                "failed to serialize candidate template descriptor: {err}"
            ))
        })?
        .len() as u64;

    let candidate_digest =
        sha256_bytes(&bincode::serialize(&template_descriptor).map_err(|err| {
            ProtoError::Decode(format!(
                "failed to serialize candidate digest material: {err}"
            ))
        })?);

    let line_items = vec![
        CandidateArtifactLineItem {
            name: "context_binding".to_string(),
            scope: ArtifactScope::CrossSessionTemplate,
            visibility: ArtifactVisibility::Public,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description:
                "Canonical-context binding reused across sessions for the same SSR identity."
                    .to_string(),
        },
        CandidateArtifactLineItem {
            name: "candidate_digest".to_string(),
            scope: ArtifactScope::CrossSessionTemplate,
            visibility: ArtifactVisibility::Public,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description:
                "Stable digest naming the fixed-function candidate artifact and evaluator shape."
                    .to_string(),
        },
        CandidateArtifactLineItem {
            name: "round_template_digest".to_string(),
            scope: ArtifactScope::CrossSessionTemplate,
            visibility: ArtifactVisibility::Public,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description:
                "Digest for the internal fixed SHA-512 round template reused inside evaluation."
                    .to_string(),
        },
        CandidateArtifactLineItem {
            name: "succinct_hidden_core_encoding".to_string(),
            scope: ArtifactScope::CrossSessionTemplate,
            visibility: ArtifactVisibility::Public,
            logical_width_bytes: 0,
            encoded_width_bytes: Some(backend.public_data_bytes),
            description:
                format!(
                    "Backend-specific public data estimate for {} derived from literature formulas.",
                    backend_family.as_str()
                ),
        },
        CandidateArtifactLineItem {
            name: "client_input_commitment".to_string(),
            scope: ArtifactScope::PerRunPublicControl,
            visibility: ArtifactVisibility::Public,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description:
                "Per-run transcript binding for client-held inputs; oracle-only placeholder commitment."
                    .to_string(),
        },
        CandidateArtifactLineItem {
            name: "server_input_commitment".to_string(),
            scope: ArtifactScope::PerRunPublicControl,
            visibility: ArtifactVisibility::Public,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description:
                "Per-run transcript binding for server-held inputs; oracle-only placeholder commitment."
                    .to_string(),
        },
        CandidateArtifactLineItem {
            name: "run_binding".to_string(),
            scope: ArtifactScope::PerRunPublicControl,
            visibility: ArtifactVisibility::Public,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description:
                "Transcript digest binding the template and both input commitments for one evaluation."
                    .to_string(),
        },
        CandidateArtifactLineItem {
            name: "y_client".to_string(),
            scope: ArtifactScope::ClientPrivateInput,
            visibility: ArtifactVisibility::ClientPrivate,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description: "Client private root share entering the hidden evaluator.".to_string(),
        },
        CandidateArtifactLineItem {
            name: "tau_client".to_string(),
            scope: ArtifactScope::ClientPrivateInput,
            visibility: ArtifactVisibility::ClientPrivate,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description:
                "Client rerandomization share for the output-share projection.".to_string(),
        },
        CandidateArtifactLineItem {
            name: "y_server".to_string(),
            scope: ArtifactScope::ServerPrivateInput,
            visibility: ArtifactVisibility::ServerPrivate,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description: "Server private root share entering the hidden evaluator.".to_string(),
        },
        CandidateArtifactLineItem {
            name: "tau_server".to_string(),
            scope: ArtifactScope::ServerPrivateInput,
            visibility: ArtifactVisibility::ServerPrivate,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description:
                "Server rerandomization share for the output-share projection.".to_string(),
        },
        CandidateArtifactLineItem {
            name: "hidden_scalar_a".to_string(),
            scope: ArtifactScope::StructuralInternal,
            visibility: ArtifactVisibility::HiddenEvaluator,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description:
                "Internal hidden result of the fixed nonlinear core; never exposed as plaintext."
                    .to_string(),
        },
        CandidateArtifactLineItem {
            name: "x_client_base".to_string(),
            scope: ArtifactScope::ClientOutput,
            visibility: ArtifactVisibility::ClientPrivate,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description: "Durable base share returned to the client.".to_string(),
        },
        CandidateArtifactLineItem {
            name: "x_server_base".to_string(),
            scope: ArtifactScope::ServerOutput,
            visibility: ArtifactVisibility::ServerPrivate,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description: "Durable base share returned to the server.".to_string(),
        },
        CandidateArtifactLineItem {
            name: "public_key".to_string(),
            scope: ArtifactScope::PublicOutput,
            visibility: ArtifactVisibility::Public,
            logical_width_bytes: 32,
            encoded_width_bytes: Some(32),
            description: "Public verification output A = [a]B.".to_string(),
        },
    ];

    let totals = CandidateArtifactTotals::from_items(template_descriptor_bytes, &line_items);

    Ok(FixedHiddenCoreCandidate {
        candidate_version: FIXED_HIDDEN_CORE_CANDIDATE_VERSION.to_string(),
        fixed_function_id: FIXED_HIDDEN_CORE_FUNCTION_ID.to_string(),
        context_descriptor: CandidateContextDescriptor {
            application_binding_digest: normalized_context.application_binding_digest,
            participant_ids: normalized_context.participant_ids,
        },
        context_binding,
        backend,
        template: CandidateTemplateArtifact {
            candidate_digest,
            round_template_digest,
            template_descriptor_bytes,
            context_bound: true,
            fixed_function_only: true,
            cross_session_reusable: true,
        },
        artifact_inventory: CandidateArtifactInventory { totals, line_items },
        message_flow: vec![
            CandidateMessageStep {
                step: 1,
                actor: "server".to_string(),
                direction: "publish or reuse".to_string(),
                artifact_names: vec![
                    "context_binding".to_string(),
                    "candidate_digest".to_string(),
                    "round_template_digest".to_string(),
                    "succinct_hidden_core_encoding".to_string(),
                ],
                description:
                    "Cross-session template artifact is bound to canonical context and cached for rebuild flows."
                        .to_string(),
                reuse_scope: "cross_session".to_string(),
            },
            CandidateMessageStep {
                step: 2,
                actor: "client".to_string(),
                direction: "commit".to_string(),
                artifact_names: vec!["client_input_commitment".to_string()],
                description:
                    "Client binds y_client and tau_client to the run transcript without exposing plaintext."
                        .to_string(),
                reuse_scope: "per_run".to_string(),
            },
            CandidateMessageStep {
                step: 3,
                actor: "server".to_string(),
                direction: "commit".to_string(),
                artifact_names: vec!["server_input_commitment".to_string(), "run_binding".to_string()],
                description:
                    "Server binds y_server and tau_server; evaluator transcript digest names this run."
                        .to_string(),
                reuse_scope: "per_run".to_string(),
            },
            CandidateMessageStep {
                step: 4,
                actor: "evaluator".to_string(),
                direction: "evaluate hidden core".to_string(),
                artifact_names: vec!["hidden_scalar_a".to_string()],
                description:
                    "Evaluator applies the fixed one-block SHA-512 + clamp template with structural round reuse."
                        .to_string(),
                reuse_scope: "structural_internal".to_string(),
            },
            CandidateMessageStep {
                step: 5,
                actor: "output-share layer".to_string(),
                direction: "emit outputs".to_string(),
                artifact_names: vec![
                    "x_client_base".to_string(),
                    "x_server_base".to_string(),
                    "public_key".to_string(),
                ],
                description:
                    "Output projector rerandomizes hidden a into durable base shares and public A."
                        .to_string(),
                reuse_scope: "per_run".to_string(),
            },
        ],
        evaluator_plan: CandidateEvaluatorPlan {
            hidden_core_stages: vec![
                "add y_client + y_server mod 2^256".to_string(),
                "evaluate fixed one-block SHA-512".to_string(),
                "clamp h[0..31] and reduce into scalar a".to_string(),
                "hand off hidden a to output-share projector".to_string(),
            ],
            cross_session_reuse: vec![
                "context-bound candidate descriptor".to_string(),
                "fixed padding schedule for one-block SHA-512".to_string(),
                "fixed output projector layout".to_string(),
            ],
            structural_reuse: vec![
                "identical stage order for every evaluation".to_string(),
                "same round-template digest for each run in a context".to_string(),
                "batch identical hidden-core stages when an accelerator exists".to_string(),
            ],
            cpu_fallback: CandidateExecutionPath {
                label: "cpu_only".to_string(),
                preferred_surfaces: vec![
                    "native desktop".to_string(),
                    "native mobile".to_string(),
                    "browser wasm".to_string(),
                ],
                target_latency_ms: Some(2_000),
                assumptions: vec![
                    "CPU fallback is a rebuild-only safety path, not the preferred UX.".to_string(),
                    "Fixed-function template should still avoid generalized evaluator machinery.".to_string(),
                ],
            },
            accelerator_path: CandidateExecutionPath {
                label: "browser_or_native_accelerator".to_string(),
                preferred_surfaces: vec![
                    "browser WebGPU".to_string(),
                    "native mobile GPU".to_string(),
                    "native mobile NPU".to_string(),
                ],
                target_latency_ms: Some(750),
                assumptions: vec![
                    "Accelerator path must preserve the same fixed-function template digest.".to_string(),
                    "Batching and per-round concurrency come from repeated hidden-core stage shape.".to_string(),
                ],
            },
        },
        notes: vec![
            "This candidate is fixed-function only and deliberately excludes general-purpose succinct garbling.".to_string(),
            format!(
                "This candidate is parameterized by the {} backend family with public-data bytes estimated from literature formulas.",
                backend_family.as_str()
            ),
            "Current commitments are oracle-backed placeholders used to make transcript binding explicit in the research crate.".to_string(),
        ],
    })
}

pub fn simulate_fixed_hidden_core_candidate(
    input: &FExpandInput,
) -> ProtoResult<CandidateSimulationReport> {
    simulate_fixed_hidden_core_candidate_for_backend(
        input,
        CandidateBackendFamily::PrimeOrderSizeOptimized,
    )
}

pub fn simulate_fixed_hidden_core_candidate_for_backend(
    input: &FExpandInput,
    backend_family: CandidateBackendFamily,
) -> ProtoResult<CandidateSimulationReport> {
    let candidate = build_fixed_hidden_core_candidate_for_backend(&input.context, backend_family)?;
    let client_input_commitment = sha256_concat(&[
        b"succinct-garbling-proto/client-input-commitment/v0",
        &input.y_client,
        &input.tau_client,
    ]);
    let server_input_commitment = sha256_concat(&[
        b"succinct-garbling-proto/server-input-commitment/v0",
        &input.y_server,
        &input.tau_server,
    ]);
    let run_binding = sha256_concat(&[
        b"succinct-garbling-proto/run-binding/v0",
        &candidate.context_binding,
        &candidate.template.candidate_digest,
        &client_input_commitment,
        &server_input_commitment,
    ]);

    Ok(CandidateSimulationReport {
        candidate,
        client_input_commitment,
        server_input_commitment,
        run_binding,
        output: eval_f_expand(input)?,
    })
}

impl FixedHiddenCoreCandidate {
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Fixed Hidden-Core Candidate V0\n\n");
        out.push_str("## Identity\n\n");
        out.push_str(&format!(
            "- Candidate version: `{}`\n- Fixed function: `{}`\n- Backend family: `{}`\n- Estimated public data: `{}` bytes (`{}` bits)\n- Context binding: `{}`\n- Candidate digest: `{}`\n- Round-template digest: `{}`\n\n",
            self.candidate_version,
            self.fixed_function_id,
            self.backend.family.as_str(),
            self.backend.public_data_bytes,
            self.backend.public_data_bits,
            hex::encode(self.context_binding),
            hex::encode(self.template.candidate_digest),
            hex::encode(self.template.round_template_digest),
        ));
        out.push_str("## Artifact Inventory\n\n");
        out.push_str(&format!(
            "- Template descriptor bytes: `{}`\n- Known cross-session public bytes: `{}`\n- Encoded hidden-core public data bytes: `{}`\n- Known per-run public control bytes: `{}`\n- Known client private input bytes: `{}`\n- Known server private input bytes: `{}`\n- Known structural internal bytes: `{}`\n- Known output bytes: client `{}`, server `{}`, public `{}`\n- Unknown encoded payload items: `{}`\n\n",
            self.template.template_descriptor_bytes,
            self.artifact_inventory.totals.known_cross_session_public_bytes,
            self.backend.public_data_bytes,
            self.artifact_inventory.totals.known_per_run_public_control_bytes,
            self.artifact_inventory.totals.known_per_run_client_private_input_bytes,
            self.artifact_inventory.totals.known_per_run_server_private_input_bytes,
            self.artifact_inventory.totals.known_structural_internal_bytes,
            self.artifact_inventory.totals.known_client_output_bytes,
            self.artifact_inventory.totals.known_server_output_bytes,
            self.artifact_inventory.totals.known_public_output_bytes,
            self.artifact_inventory.totals.unknown_encoded_payload_item_count,
        ));

        out.push_str("## Message Flow\n\n");
        for step in &self.message_flow {
            out.push_str(&format!(
                "{}. {} `{}` {}\n",
                step.step, step.actor, step.direction, step.description
            ));
        }

        out.push_str("\n## Reuse Split\n\n");
        for item in &self.evaluator_plan.cross_session_reuse {
            out.push_str(&format!("- Cross-session: {}\n", item));
        }
        for item in &self.evaluator_plan.structural_reuse {
            out.push_str(&format!("- Structural internal: {}\n", item));
        }

        out.push_str("\n## Evaluator Plan\n\n");
        out.push_str(&format!(
            "- CPU fallback target: `{:?}` ms on {:?}\n- Accelerator target: `{:?}` ms on {:?}\n\n",
            self.evaluator_plan.cpu_fallback.target_latency_ms,
            self.evaluator_plan.cpu_fallback.preferred_surfaces,
            self.evaluator_plan.accelerator_path.target_latency_ms,
            self.evaluator_plan.accelerator_path.preferred_surfaces,
        ));

        out.push_str("## Backend Parameters\n\n");
        out.push_str(&format!("- Source: {}\n", self.backend.source));
        for item in &self.backend.parameter_summary {
            out.push_str(&format!("- Parameter: {}\n", item));
        }
        for note in &self.backend.evaluator_notes {
            out.push_str(&format!("- Backend note: {}\n", note));
        }
        out.push('\n');

        out.push_str("## Notes\n\n");
        for note in &self.notes {
            out.push_str(&format!("- {}\n", note));
        }

        out
    }

    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!(
                "candidate: {} function={} backend={}",
                self.candidate_version,
                self.fixed_function_id,
                self.backend.family.as_str(),
            ),
            format!(
                "template: descriptor={}B cross_session_known={}B encoded_hidden_core={}B per_run_public={}B unknown_encoded_items={}",
                self.template.template_descriptor_bytes,
                self.artifact_inventory.totals.known_cross_session_public_bytes,
                self.backend.public_data_bytes,
                self.artifact_inventory.totals.known_per_run_public_control_bytes,
                self.artifact_inventory.totals.unknown_encoded_payload_item_count,
            ),
            format!(
                "outputs: client={}B server={}B public={}B",
                self.artifact_inventory.totals.known_client_output_bytes,
                self.artifact_inventory.totals.known_server_output_bytes,
                self.artifact_inventory.totals.known_public_output_bytes,
            ),
        ]
    }
}

impl CandidateSimulationReport {
    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!(
                "simulation: candidate={} context_binding={}",
                self.candidate.candidate_version,
                hex::encode(self.candidate.context_binding),
            ),
            format!(
                "commitments: client={} server={} run={}",
                hex::encode(self.client_input_commitment),
                hex::encode(self.server_input_commitment),
                hex::encode(self.run_binding),
            ),
            format!(
                "outputs: x_client={} x_server={} A={}",
                hex::encode(self.output.x_client_base),
                hex::encode(self.output.x_server_base),
                hex::encode(self.output.public_key),
            ),
        ]
    }
}

impl CandidateArtifactTotals {
    fn from_items(
        template_descriptor_bytes: u64,
        line_items: &[CandidateArtifactLineItem],
    ) -> CandidateArtifactTotals {
        let mut totals = CandidateArtifactTotals {
            template_descriptor_bytes,
            known_cross_session_public_bytes: 0,
            known_per_run_public_control_bytes: 0,
            known_per_run_client_private_input_bytes: 0,
            known_per_run_server_private_input_bytes: 0,
            known_structural_internal_bytes: 0,
            known_client_output_bytes: 0,
            known_server_output_bytes: 0,
            known_public_output_bytes: 0,
            unknown_encoded_payload_item_count: 0,
        };

        for item in line_items {
            if item.encoded_width_bytes.is_none() {
                totals.unknown_encoded_payload_item_count += 1;
            }

            match item.scope {
                ArtifactScope::CrossSessionTemplate => {
                    totals.known_cross_session_public_bytes += item.logical_width_bytes;
                }
                ArtifactScope::PerRunPublicControl => {
                    totals.known_per_run_public_control_bytes += item.logical_width_bytes;
                }
                ArtifactScope::ClientPrivateInput => {
                    totals.known_per_run_client_private_input_bytes += item.logical_width_bytes;
                }
                ArtifactScope::ServerPrivateInput => {
                    totals.known_per_run_server_private_input_bytes += item.logical_width_bytes;
                }
                ArtifactScope::StructuralInternal => {
                    totals.known_structural_internal_bytes += item.logical_width_bytes;
                }
                ArtifactScope::ClientOutput => {
                    totals.known_client_output_bytes += item.logical_width_bytes;
                }
                ArtifactScope::ServerOutput => {
                    totals.known_server_output_bytes += item.logical_width_bytes;
                }
                ArtifactScope::PublicOutput => {
                    totals.known_public_output_bytes += item.logical_width_bytes;
                }
            }
        }

        totals
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TemplateDescriptorDigestView {
    candidate_version: String,
    fixed_function_id: String,
    backend_family: String,
    context_binding: [u8; 32],
    round_template_digest: [u8; 32],
    estimated_public_data_bytes: u64,
    participant_ids: Vec<u16>,
}

impl CandidateBackendFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrimeOrderSizeOptimized => "prime_order_size_optimized",
            Self::PrimeOrderComputeOptimized => "prime_order_compute_optimized",
        }
    }
}

fn backend_spec(family: CandidateBackendFamily) -> CandidateBackendSpec {
    const LAMBDA: u64 = 128;

    match family {
        CandidateBackendFamily::PrimeOrderSizeOptimized => {
            let beta = 8u64;
            let log_p = 256u64;
            let public_data_bits =
                LAMBDA + (((6 * LAMBDA) / beta) + LAMBDA + ((2 * LAMBDA * LAMBDA) / beta)) * log_p;

            CandidateBackendSpec {
                family,
                source: "Ishai-Li-Lin 2025/442, Table 3 and prime-order size-optimized formula"
                    .to_string(),
                public_data_bits,
                public_data_bytes: bits_to_bytes(public_data_bits),
                parameter_summary: vec![
                    "lambda=128".to_string(),
                    "group=256-bit elliptic curve".to_string(),
                    "beta=8 digit decomposition".to_string(),
                    "random-oracle ElGamal first-component optimization".to_string(),
                ],
                evaluator_notes: vec![
                    "Chosen as the first concrete backend because it minimizes public-data size among the published families.".to_string(),
                    "Evaluation remains group-heavy, so accelerator evidence is still required.".to_string(),
                ],
            }
        }
        CandidateBackendFamily::PrimeOrderComputeOptimized => {
            let beta = 4u64;
            let log_p = 5_000u64;
            let public_data_bits =
                LAMBDA + (((6 * LAMBDA) / beta) + LAMBDA + ((2 * LAMBDA * LAMBDA) / beta)) * log_p;

            CandidateBackendSpec {
                family,
                source: "Ishai-Li-Lin 2025/442, Table 3 and prime-order compute-optimized formula"
                    .to_string(),
                public_data_bits,
                public_data_bytes: bits_to_bytes(public_data_bits),
                parameter_summary: vec![
                    "lambda=128".to_string(),
                    "group=conversion-friendly 5000-bit prime".to_string(),
                    "beta=4 digit decomposition".to_string(),
                ],
                evaluator_notes: vec![
                    "Computation-oriented prime-order setting from the paper.".to_string(),
                    "Size is much larger than the size-optimized elliptic-curve variant."
                        .to_string(),
                ],
            }
        }
    }
}

fn bits_to_bytes(bits: u64) -> u64 {
    bits.div_ceil(8)
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
