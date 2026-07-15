//! Fixed-fixture, non-production Phase 5 separate-role stream benchmark facade.

use core::fmt;
use std::io::Read;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::phase5_process::{
    run_phase5_activation_deriver_a, run_phase5_activation_deriver_b, run_phase5_export_deriver_a,
    run_phase5_export_deriver_b, Phase5StreamMetrics,
};
use super::phase5_transport::{EofBodyWriter, ExactEofBodyReader};
use super::role_protocol_support::{
    activation_deriver_a_fixture_start, activation_deriver_b_fixture_start,
    export_deriver_a_fixture_start, export_deriver_b_fixture_start,
};
use super::stream::{Chunk128KiB, Chunk256KiB, Chunk64KiB, FixedChunkProfile};

/// Opaque failure from the isolated Phase 5 role-process benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase5RoleBenchmarkError;

impl fmt::Display for Phase5RoleBenchmarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("isolated Phase 5 role-process benchmark failed")
    }
}

impl std::error::Error for Phase5RoleBenchmarkError {}

/// Exact bounded-stream counters observed by one benchmark role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase5RoleStreamMetrics {
    table_payload_bytes: usize,
    body_bytes: u64,
    frame_count: u32,
    peak_table_buffer_bytes: usize,
    peak_arena_bytes: usize,
}

impl Phase5RoleStreamMetrics {
    /// Returns the total Half-Gates table payload bytes.
    pub const fn table_payload_bytes(self) -> usize {
        self.table_payload_bytes
    }

    /// Returns table payload plus canonical frame headers.
    pub const fn body_bytes(self) -> u64 {
        self.body_bytes
    }

    /// Returns the number of canonical table frames.
    pub const fn frame_count(self) -> u32 {
        self.frame_count
    }

    /// Returns the largest live table payload buffer.
    pub const fn peak_table_buffer_bytes(self) -> usize {
        self.peak_table_buffer_bytes
    }

    /// Returns the measured fixed-schedule wire arena allocation.
    pub const fn peak_arena_bytes(self) -> usize {
        self.peak_arena_bytes
    }
}

impl From<Phase5StreamMetrics> for Phase5RoleStreamMetrics {
    fn from(metrics: Phase5StreamMetrics) -> Self {
        Self {
            table_payload_bytes: metrics.table_payload_bytes(),
            body_bytes: metrics.body_bytes(),
            frame_count: metrics.frame_count(),
            peak_table_buffer_bytes: metrics.peak_table_buffer_bytes(),
            peak_arena_bytes: metrics.peak_arena_bytes(),
        }
    }
}

/// One role's activation packages and exact fixed-profile stream counters.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Phase5ActivationRoleFixturePackages {
    client_package: Vec<u8>,
    signing_worker_package: Vec<u8>,
    #[zeroize(skip)]
    metrics: Phase5RoleStreamMetrics,
}

impl Phase5ActivationRoleFixturePackages {
    /// Returns this role's client-only recipient package.
    pub fn client_package(&self) -> &[u8] {
        &self.client_package
    }

    /// Returns this role's SigningWorker-only recipient package.
    pub fn signing_worker_package(&self) -> &[u8] {
        &self.signing_worker_package
    }

    /// Returns this role's exact bounded-stream counters.
    pub const fn stream_metrics(&self) -> Phase5RoleStreamMetrics {
        self.metrics
    }
}

impl fmt::Debug for Phase5ActivationRoleFixturePackages {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Phase5ActivationRoleFixturePackages")
            .field("packages", &"[REDACTED]")
            .field("metrics", &self.metrics)
            .finish()
    }
}

/// One role's export package and exact fixed-profile stream counters.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Phase5ExportRoleFixturePackage {
    package: Vec<u8>,
    #[zeroize(skip)]
    metrics: Phase5RoleStreamMetrics,
}

impl Phase5ExportRoleFixturePackage {
    /// Returns this role's export-only recipient package.
    pub fn package(&self) -> &[u8] {
        &self.package
    }

    /// Returns this role's exact bounded-stream counters.
    pub const fn stream_metrics(&self) -> Phase5RoleStreamMetrics {
        self.metrics
    }
}

impl fmt::Debug for Phase5ExportRoleFixturePackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Phase5ExportRoleFixturePackage")
            .field("package", &"[REDACTED]")
            .field("metrics", &self.metrics)
            .finish()
    }
}

fn run_activation_deriver_a_fixture<
    C: FixedChunkProfile,
    CR: Read,
    CW: EofBodyWriter,
    TW: EofBodyWriter,
>(
    session: [u8; 32],
    control_reader: CR,
    control_writer: CW,
    table_writer: TW,
) -> Result<Phase5ActivationRoleFixturePackages, Phase5RoleBenchmarkError> {
    let start =
        activation_deriver_a_fixture_start(session).map_err(|_| Phase5RoleBenchmarkError)?;
    let completed = run_phase5_activation_deriver_a::<C, _, _, _>(
        start,
        control_reader,
        control_writer,
        table_writer,
    )
    .map_err(|_| Phase5RoleBenchmarkError)?;
    let client_package = completed.encode_client_package();
    let signing_worker_package = completed.encode_signing_worker_package();
    Ok(Phase5ActivationRoleFixturePackages {
        client_package: client_package.as_slice().to_vec(),
        signing_worker_package: signing_worker_package.as_slice().to_vec(),
        metrics: completed.stream_metrics().into(),
    })
}

fn run_activation_deriver_b_fixture<
    C: FixedChunkProfile,
    CR: Read,
    CW: EofBodyWriter,
    TR: ExactEofBodyReader,
>(
    session: [u8; 32],
    control_reader: CR,
    control_writer: CW,
    table_reader: TR,
) -> Result<Phase5ActivationRoleFixturePackages, Phase5RoleBenchmarkError> {
    let start =
        activation_deriver_b_fixture_start(session).map_err(|_| Phase5RoleBenchmarkError)?;
    let completed = run_phase5_activation_deriver_b::<C, _, _, _>(
        start,
        control_reader,
        control_writer,
        table_reader,
    )
    .map_err(|_| Phase5RoleBenchmarkError)?;
    let client_package = completed.encode_client_package();
    let signing_worker_package = completed.encode_signing_worker_package();
    Ok(Phase5ActivationRoleFixturePackages {
        client_package: client_package.as_slice().to_vec(),
        signing_worker_package: signing_worker_package.as_slice().to_vec(),
        metrics: completed.stream_metrics().into(),
    })
}

fn run_export_deriver_a_fixture<
    C: FixedChunkProfile,
    CR: Read,
    CW: EofBodyWriter,
    TW: EofBodyWriter,
>(
    session: [u8; 32],
    control_reader: CR,
    control_writer: CW,
    table_writer: TW,
) -> Result<Phase5ExportRoleFixturePackage, Phase5RoleBenchmarkError> {
    let start = export_deriver_a_fixture_start(session).map_err(|_| Phase5RoleBenchmarkError)?;
    let completed = run_phase5_export_deriver_a::<C, _, _, _>(
        start,
        control_reader,
        control_writer,
        table_writer,
    )
    .map_err(|_| Phase5RoleBenchmarkError)?;
    let package = completed.encode_package();
    Ok(Phase5ExportRoleFixturePackage {
        package: package.as_slice().to_vec(),
        metrics: completed.stream_metrics().into(),
    })
}

fn run_export_deriver_b_fixture<
    C: FixedChunkProfile,
    CR: Read,
    CW: EofBodyWriter,
    TR: ExactEofBodyReader,
>(
    session: [u8; 32],
    control_reader: CR,
    control_writer: CW,
    table_reader: TR,
) -> Result<Phase5ExportRoleFixturePackage, Phase5RoleBenchmarkError> {
    let start = export_deriver_b_fixture_start(session).map_err(|_| Phase5RoleBenchmarkError)?;
    let completed = run_phase5_export_deriver_b::<C, _, _, _>(
        start,
        control_reader,
        control_writer,
        table_reader,
    )
    .map_err(|_| Phase5RoleBenchmarkError)?;
    let package = completed.encode_package();
    Ok(Phase5ExportRoleFixturePackage {
        package: package.as_slice().to_vec(),
        metrics: completed.stream_metrics().into(),
    })
}

macro_rules! define_a_profile_fixture {
    ($name:ident, $profile:ty, $inner:ident, $output:ty, $documentation:literal) => {
        #[doc = $documentation]
        pub fn $name<CR: Read, CW: EofBodyWriter, TW: EofBodyWriter>(
            session: [u8; 32],
            control_reader: CR,
            control_writer: CW,
            table_writer: TW,
        ) -> Result<$output, Phase5RoleBenchmarkError> {
            $inner::<$profile, _, _, _>(session, control_reader, control_writer, table_writer)
        }
    };
}

macro_rules! define_b_profile_fixture {
    ($name:ident, $profile:ty, $inner:ident, $output:ty, $documentation:literal) => {
        #[doc = $documentation]
        pub fn $name<CR: Read, CW: EofBodyWriter, TR: ExactEofBodyReader>(
            session: [u8; 32],
            control_reader: CR,
            control_writer: CW,
            table_reader: TR,
        ) -> Result<$output, Phase5RoleBenchmarkError> {
            $inner::<$profile, _, _, _>(session, control_reader, control_writer, table_reader)
        }
    };
}

define_a_profile_fixture!(
    run_activation_deriver_a_64k_fixture,
    Chunk64KiB,
    run_activation_deriver_a_fixture,
    Phase5ActivationRoleFixturePackages,
    "Runs only Deriver A's fixed 64 KiB activation-stream role."
);
define_a_profile_fixture!(
    run_activation_deriver_a_128k_fixture,
    Chunk128KiB,
    run_activation_deriver_a_fixture,
    Phase5ActivationRoleFixturePackages,
    "Runs only Deriver A's fixed 128 KiB activation-stream role."
);
define_a_profile_fixture!(
    run_activation_deriver_a_256k_fixture,
    Chunk256KiB,
    run_activation_deriver_a_fixture,
    Phase5ActivationRoleFixturePackages,
    "Runs only Deriver A's fixed 256 KiB activation-stream role."
);
define_b_profile_fixture!(
    run_activation_deriver_b_64k_fixture,
    Chunk64KiB,
    run_activation_deriver_b_fixture,
    Phase5ActivationRoleFixturePackages,
    "Runs only Deriver B's fixed 64 KiB activation-stream role."
);
define_b_profile_fixture!(
    run_activation_deriver_b_128k_fixture,
    Chunk128KiB,
    run_activation_deriver_b_fixture,
    Phase5ActivationRoleFixturePackages,
    "Runs only Deriver B's fixed 128 KiB activation-stream role."
);
define_b_profile_fixture!(
    run_activation_deriver_b_256k_fixture,
    Chunk256KiB,
    run_activation_deriver_b_fixture,
    Phase5ActivationRoleFixturePackages,
    "Runs only Deriver B's fixed 256 KiB activation-stream role."
);
define_a_profile_fixture!(
    run_export_deriver_a_64k_fixture,
    Chunk64KiB,
    run_export_deriver_a_fixture,
    Phase5ExportRoleFixturePackage,
    "Runs only Deriver A's fixed 64 KiB export-stream role."
);
define_a_profile_fixture!(
    run_export_deriver_a_128k_fixture,
    Chunk128KiB,
    run_export_deriver_a_fixture,
    Phase5ExportRoleFixturePackage,
    "Runs only Deriver A's fixed 128 KiB export-stream role."
);
define_a_profile_fixture!(
    run_export_deriver_a_256k_fixture,
    Chunk256KiB,
    run_export_deriver_a_fixture,
    Phase5ExportRoleFixturePackage,
    "Runs only Deriver A's fixed 256 KiB export-stream role."
);
define_b_profile_fixture!(
    run_export_deriver_b_64k_fixture,
    Chunk64KiB,
    run_export_deriver_b_fixture,
    Phase5ExportRoleFixturePackage,
    "Runs only Deriver B's fixed 64 KiB export-stream role."
);
define_b_profile_fixture!(
    run_export_deriver_b_128k_fixture,
    Chunk128KiB,
    run_export_deriver_b_fixture,
    Phase5ExportRoleFixturePackage,
    "Runs only Deriver B's fixed 128 KiB export-stream role."
);
define_b_profile_fixture!(
    run_export_deriver_b_256k_fixture,
    Chunk256KiB,
    run_export_deriver_b_fixture,
    Phase5ExportRoleFixturePackage,
    "Runs only Deriver B's fixed 256 KiB export-stream role."
);
