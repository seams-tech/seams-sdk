use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::candidate::{CandidateBackendFamily, FixedHiddenCoreCandidate};
use crate::error::{ProtoError, ProtoResult};

pub const CANDIDATE_ARTIFACT_STUB_VERSION: &str = "candidate_artifact_stub_v0";
pub const DEFAULT_ARTIFACT_STUB_CHUNK_SIZE_BYTES: u64 = 4_096;
const ARTIFACT_STUB_HEADER_BYTES: usize = 96;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateArtifactStub {
    pub stub_version: String,
    pub backend_family: CandidateBackendFamily,
    pub total_bytes: u64,
    pub header_bytes: u64,
    pub payload_bytes: u64,
    pub chunk_size_bytes: u64,
    pub chunk_count: usize,
    pub artifact_digest: [u8; 32],
    pub header_digest: [u8; 32],
    pub candidate_digest: [u8; 32],
    pub context_binding: [u8; 32],
    pub chunks: Vec<CandidateArtifactStubChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateArtifactStubChunk {
    pub index: u32,
    pub offset_bytes: u64,
    pub length_bytes: u64,
    pub digest: [u8; 32],
}

pub fn build_candidate_artifact_stub(
    candidate: &FixedHiddenCoreCandidate,
) -> ProtoResult<CandidateArtifactStub> {
    build_candidate_artifact_stub_with_chunk_size(candidate, DEFAULT_ARTIFACT_STUB_CHUNK_SIZE_BYTES)
}

pub fn build_candidate_artifact_stub_with_chunk_size(
    candidate: &FixedHiddenCoreCandidate,
    chunk_size_bytes: u64,
) -> ProtoResult<CandidateArtifactStub> {
    if chunk_size_bytes == 0 {
        return Err(ProtoError::InvalidInput(
            "chunk_size_bytes must be positive".to_string(),
        ));
    }

    let artifact_bytes = materialize_candidate_artifact_stub_bytes(candidate)?;
    let header_digest = sha256_bytes(&artifact_bytes[..ARTIFACT_STUB_HEADER_BYTES]);
    let artifact_digest = sha256_bytes(&artifact_bytes);
    let mut chunks = Vec::new();

    for (index, chunk) in artifact_bytes.chunks(chunk_size_bytes as usize).enumerate() {
        chunks.push(CandidateArtifactStubChunk {
            index: index as u32,
            offset_bytes: index as u64 * chunk_size_bytes,
            length_bytes: chunk.len() as u64,
            digest: sha256_bytes(chunk),
        });
    }

    Ok(CandidateArtifactStub {
        stub_version: CANDIDATE_ARTIFACT_STUB_VERSION.to_string(),
        backend_family: candidate.backend.family,
        total_bytes: artifact_bytes.len() as u64,
        header_bytes: ARTIFACT_STUB_HEADER_BYTES as u64,
        payload_bytes: artifact_bytes.len() as u64 - ARTIFACT_STUB_HEADER_BYTES as u64,
        chunk_size_bytes,
        chunk_count: chunks.len(),
        artifact_digest,
        header_digest,
        candidate_digest: candidate.template.candidate_digest,
        context_binding: candidate.context_binding,
        chunks,
    })
}

pub fn materialize_candidate_artifact_stub_bytes(
    candidate: &FixedHiddenCoreCandidate,
) -> ProtoResult<Vec<u8>> {
    let total_bytes = usize::try_from(candidate.backend.public_data_bytes).map_err(|_| {
        ProtoError::InvalidInput("artifact size does not fit into usize".to_string())
    })?;
    if total_bytes < ARTIFACT_STUB_HEADER_BYTES {
        return Err(ProtoError::InvalidInput(format!(
            "artifact size {} is smaller than stub header {}",
            total_bytes, ARTIFACT_STUB_HEADER_BYTES
        )));
    }

    let mut out = Vec::with_capacity(total_bytes);
    out.extend_from_slice(&artifact_stub_header(candidate));
    let payload_len = total_bytes - ARTIFACT_STUB_HEADER_BYTES;
    out.extend_from_slice(&expand_stub_payload(candidate, payload_len));
    Ok(out)
}

impl CandidateArtifactStub {
    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!(
                "artifact_stub: backend={} total={}B header={}B payload={}B chunks={}",
                self.backend_family.as_str(),
                self.total_bytes,
                self.header_bytes,
                self.payload_bytes,
                self.chunk_count,
            ),
            format!(
                "digests: artifact={} header={}",
                hex::encode(self.artifact_digest),
                hex::encode(self.header_digest),
            ),
        ]
    }
}

fn artifact_stub_header(candidate: &FixedHiddenCoreCandidate) -> [u8; ARTIFACT_STUB_HEADER_BYTES] {
    let mut header = [0u8; ARTIFACT_STUB_HEADER_BYTES];
    header[..8].copy_from_slice(b"SGPSTUB0");
    header[8..16].copy_from_slice(&candidate.backend.public_data_bytes.to_le_bytes());
    header[16..24].copy_from_slice(&DEFAULT_ARTIFACT_STUB_CHUNK_SIZE_BYTES.to_le_bytes());
    header[24..56].copy_from_slice(&candidate.context_binding);
    header[56..88].copy_from_slice(&candidate.template.candidate_digest);
    let backend_tag = sha256_bytes(candidate.backend.family.as_str().as_bytes());
    header[88..96].copy_from_slice(&backend_tag[..8]);
    header
}

fn expand_stub_payload(candidate: &FixedHiddenCoreCandidate, payload_len: usize) -> Vec<u8> {
    let seed = payload_seed(candidate);
    let mut out = Vec::with_capacity(payload_len);
    let mut counter = 0u64;

    while out.len() < payload_len {
        let block = sha256_concat(&[
            b"succinct-garbling-proto/artifact-stub-payload/v0",
            &seed,
            &counter.to_be_bytes(),
        ]);
        let remaining = payload_len - out.len();
        let take = remaining.min(block.len());
        out.extend_from_slice(&block[..take]);
        counter += 1;
    }

    out
}

fn payload_seed(candidate: &FixedHiddenCoreCandidate) -> [u8; 32] {
    sha256_concat(&[
        b"succinct-garbling-proto/artifact-stub-seed/v0",
        &candidate.context_binding,
        &candidate.template.candidate_digest,
        &candidate.template.round_template_digest,
        candidate.backend.family.as_str().as_bytes(),
    ])
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
