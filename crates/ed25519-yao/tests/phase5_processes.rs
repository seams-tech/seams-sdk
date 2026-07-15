#![cfg(all(feature = "passive-benchmark", unix))]

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use curve25519_dalek::scalar::Scalar;

const ROLE_BINARY: &str = env!("CARGO_BIN_EXE_benchmark_phase5_role");
const PACKAGE_MAGIC: &[u8; 8] = b"EYAOPKG1";
const PACKAGE_HEADER_BYTES: usize = 152;
const ACTIVATION_PACKAGE_BYTES: usize = 216;
const EXPORT_PACKAGE_BYTES: usize = 184;
const ACTIVATION_FAMILY_TAG: u8 = 0x93;
const EXPORT_FAMILY_TAG: u8 = 0x94;
const DERIVER_A_ROLE_TAG: u8 = 0xa1;
const DERIVER_B_ROLE_TAG: u8 = 0xb2;
const CLIENT_RECIPIENT_TAG: u8 = 0x01;
const SIGNING_WORKER_RECIPIENT_TAG: u8 = 0x02;
const EXPORT_RECIPIENT_TAG: u8 = 0x03;
const CLIENT_SCALAR_SHARE_OUTPUT_KIND: u8 = 0x21;
const SIGNING_WORKER_SCALAR_SHARE_OUTPUT_KIND: u8 = 0x22;
const EXPORT_SEED_SHARE_OUTPUT_KIND: u8 = 0x23;
const FIXTURE_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const FIXTURE_BASE: [u8; 32] = [
    0x7c, 0x2c, 0xac, 0x12, 0xe6, 0x9b, 0xe9, 0x6a, 0xe9, 0x06, 0x50, 0x65, 0x46, 0x23, 0x85, 0xe8,
    0xfc, 0xff, 0x27, 0x68, 0xd9, 0x80, 0xc0, 0xa3, 0xa5, 0x20, 0xf0, 0x06, 0x90, 0x4d, 0xe9, 0x0f,
];

#[test]
fn activation_streams_in_two_os_processes_with_exact_profile_bounds() {
    for profile in StreamProfile::ALL {
        let (a, b, _) = run_roles("activation", profile);
        let a = parse_activation_role(&a, DERIVER_A_ROLE_TAG);
        let b = parse_activation_role(&b, DERIVER_B_ROLE_TAG);
        assert_eq!(
            (a.client_share + b.client_share).to_bytes(),
            FIXTURE_BASE,
            "{} activation client reconstruction",
            profile.cli_name()
        );
        assert_eq!(
            (a.worker_share + b.worker_share).to_bytes(),
            FIXTURE_BASE,
            "{} activation worker reconstruction",
            profile.cli_name()
        );
        assert_eq!(
            a.transcript,
            b.transcript,
            "{} activation transcript agreement",
            profile.cli_name()
        );
        assert_eq!(
            a.metrics,
            StreamMetrics::activation(profile),
            "{} Deriver A activation metrics",
            profile.cli_name()
        );
        assert_eq!(
            b.metrics,
            StreamMetrics::activation(profile),
            "{} Deriver B activation metrics",
            profile.cli_name()
        );
    }
}

#[test]
fn export_streams_in_two_os_processes_with_exact_profile_bounds() {
    for profile in StreamProfile::ALL {
        let (a, b, _) = run_roles("export", profile);
        let a = parse_export_role(&a, DERIVER_A_ROLE_TAG);
        let b = parse_export_role(&b, DERIVER_B_ROLE_TAG);
        assert_eq!(
            wrapping_add(a.share, b.share),
            FIXTURE_SEED,
            "{} export reconstruction",
            profile.cli_name()
        );
        assert_eq!(
            a.transcript,
            b.transcript,
            "{} export transcript agreement",
            profile.cli_name()
        );
        assert_eq!(
            a.metrics,
            StreamMetrics::export(),
            "{} Deriver A export metrics",
            profile.cli_name()
        );
        assert_eq!(
            b.metrics,
            StreamMetrics::export(),
            "{} Deriver B export metrics",
            profile.cli_name()
        );
    }
}

#[test]
#[ignore = "explicit release-mode Phase 5 two-process latency benchmark"]
fn native_two_process_stream_wall_benchmark() {
    const ITERATIONS: usize = 20;
    for profile in StreamProfile::ALL {
        let mut activation = Vec::with_capacity(ITERATIONS);
        let mut export = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            activation.push(run_roles("activation", profile).2);
            export.push(run_roles("export", profile).2);
        }
        println!(
            "phase5_two_process profile={} iterations={ITERATIONS} activation_p50_us={} activation_p95_us={} export_p50_us={} export_p95_us={}",
            profile.cli_name(),
            percentile_micros(&mut activation, 50, 100),
            percentile_micros(&mut activation, 95, 100),
            percentile_micros(&mut export, 50, 100),
            percentile_micros(&mut export, 95, 100),
        );
    }
}

fn run_roles(family: &str, profile: StreamProfile) -> (String, String, Duration) {
    static PROCESS_LOCK: Mutex<()> = Mutex::new(());
    let _process_guard = PROCESS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let control_socket = unique_socket_path(family, profile, "control");
    let table_socket = unique_socket_path(family, profile, "table");
    let session = random_session_hex();
    let started = Instant::now();
    let mut b = spawn_role(
        family,
        profile,
        "b",
        &control_socket,
        &table_socket,
        &session,
    );
    wait_for_socket_paths(&mut b, &control_socket, &table_socket);
    let a = spawn_role(
        family,
        profile,
        "a",
        &control_socket,
        &table_socket,
        &session,
    );
    let a = a.wait_with_output().expect("wait for Deriver A");
    let b = b.wait_with_output().expect("wait for Deriver B");
    let wall = started.elapsed();
    let _ = std::fs::remove_file(control_socket);
    let _ = std::fs::remove_file(table_socket);
    let b = successful_stdout("B", b);
    let a = successful_stdout("A", a);
    (a, b, wall)
}

fn wait_for_socket_paths(
    b: &mut std::process::Child,
    control_socket: &std::path::Path,
    table_socket: &std::path::Path,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !(control_socket.exists() && table_socket.exists()) {
        if let Some(status) = b.try_wait().expect("poll Deriver B") {
            let mut stderr = String::new();
            b.stderr
                .as_mut()
                .expect("Deriver B stderr")
                .read_to_string(&mut stderr)
                .expect("read Deriver B stderr");
            panic!(
                "Deriver B exited before binding both channels ({}, {}): {status}: {stderr}",
                control_socket.display(),
                table_socket.display(),
            );
        }
        assert!(
            Instant::now() < deadline,
            "Deriver B did not bind both dedicated Phase 5 channels"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn spawn_role(
    family: &str,
    profile: StreamProfile,
    role: &str,
    control_socket: &std::path::Path,
    table_socket: &std::path::Path,
    session: &str,
) -> std::process::Child {
    Command::new(ROLE_BINARY)
        .args([
            family,
            profile.cli_name(),
            role,
            control_socket.to_str().expect("UTF-8 control socket"),
            table_socket.to_str().expect("UTF-8 table socket"),
            session,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn Deriver {role}: {error}"))
}

#[derive(Debug, Clone, Copy)]
enum StreamProfile {
    K64,
    K128,
    K256,
}

impl StreamProfile {
    const ALL: [Self; 3] = [Self::K64, Self::K128, Self::K256];

    const fn cli_name(self) -> &'static str {
        match self {
            Self::K64 => "64k",
            Self::K128 => "128k",
            Self::K256 => "256k",
        }
    }
}

fn successful_stdout(role: &str, output: Output) -> String {
    assert!(
        output.status.success(),
        "Deriver {role} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("role output is UTF-8")
        .trim()
        .to_owned()
}

struct ActivationRoleOutput {
    client_share: Scalar,
    worker_share: Scalar,
    transcript: [u8; 32],
    metrics: StreamMetrics,
}

struct ExportRoleOutput {
    share: [u8; 32],
    transcript: [u8; 32],
    metrics: StreamMetrics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StreamMetrics {
    table_payload_bytes: usize,
    body_bytes: u64,
    frame_count: u32,
    peak_table_buffer_bytes: usize,
}

impl StreamMetrics {
    const fn activation(profile: StreamProfile) -> Self {
        match profile {
            StreamProfile::K64 => Self {
                table_payload_bytes: 2_104_960,
                body_bytes: 2_107_996,
                frame_count: 33,
                peak_table_buffer_bytes: 65_536,
            },
            StreamProfile::K128 => Self {
                table_payload_bytes: 2_104_960,
                body_bytes: 2_106_524,
                frame_count: 17,
                peak_table_buffer_bytes: 131_072,
            },
            StreamProfile::K256 => Self {
                table_payload_bytes: 2_104_960,
                body_bytes: 2_105_788,
                frame_count: 9,
                peak_table_buffer_bytes: 262_144,
            },
        }
    }

    const fn export() -> Self {
        Self {
            table_payload_bytes: 40_800,
            body_bytes: 40_892,
            frame_count: 1,
            peak_table_buffer_bytes: 40_800,
        }
    }
}

fn parse_activation_role(encoded: &str, role_tag: u8) -> ActivationRoleOutput {
    let (packages, metrics) = encoded.split_once('|').expect("packages and metrics");
    let (client, worker) = packages.split_once(':').expect("two recipient packages");
    let client = decode_hex(client);
    let worker = decode_hex(worker);
    validate_package(
        &client,
        ACTIVATION_PACKAGE_BYTES,
        ACTIVATION_FAMILY_TAG,
        role_tag,
        CLIENT_RECIPIENT_TAG,
        CLIENT_SCALAR_SHARE_OUTPUT_KIND,
    );
    validate_package(
        &worker,
        ACTIVATION_PACKAGE_BYTES,
        ACTIVATION_FAMILY_TAG,
        role_tag,
        SIGNING_WORKER_RECIPIENT_TAG,
        SIGNING_WORKER_SCALAR_SHARE_OUTPUT_KIND,
    );
    assert_eq!(&client[112..144], &worker[112..144]);
    ActivationRoleOutput {
        client_share: parse_scalar(&client[PACKAGE_HEADER_BYTES..PACKAGE_HEADER_BYTES + 32]),
        worker_share: parse_scalar(&worker[PACKAGE_HEADER_BYTES..PACKAGE_HEADER_BYTES + 32]),
        transcript: client[112..144].try_into().expect("transcript"),
        metrics: parse_metrics(metrics),
    }
}

fn parse_export_role(encoded: &str, role_tag: u8) -> ExportRoleOutput {
    let (package, metrics) = encoded.split_once('|').expect("package and metrics");
    let package = decode_hex(package);
    validate_package(
        &package,
        EXPORT_PACKAGE_BYTES,
        EXPORT_FAMILY_TAG,
        role_tag,
        EXPORT_RECIPIENT_TAG,
        EXPORT_SEED_SHARE_OUTPUT_KIND,
    );
    ExportRoleOutput {
        share: package[PACKAGE_HEADER_BYTES..PACKAGE_HEADER_BYTES + 32]
            .try_into()
            .expect("seed share"),
        transcript: package[112..144].try_into().expect("transcript"),
        metrics: parse_metrics(metrics),
    }
}

fn validate_package(
    encoded: &[u8],
    expected_bytes: usize,
    family_tag: u8,
    role_tag: u8,
    recipient_tag: u8,
    output_kind: u8,
) {
    assert_eq!(encoded.len(), expected_bytes);
    assert_eq!(&encoded[..8], PACKAGE_MAGIC);
    assert_eq!(encoded[8], 1);
    assert_eq!(encoded[9], family_tag);
    assert_eq!(encoded[10], role_tag);
    assert_eq!(encoded[11], recipient_tag);
    assert_eq!(encoded[12], output_kind);
    assert_eq!(encoded[13], 0);
    assert!(encoded[112..144].iter().any(|byte| *byte != 0));
}

fn parse_metrics(encoded: &str) -> StreamMetrics {
    let fields: Vec<&str> = encoded.split(',').collect();
    assert_eq!(fields.len(), 5);
    let peak_arena_bytes = fields[4].parse::<usize>().expect("peak arena bytes");
    assert_ne!(peak_arena_bytes, 0);
    StreamMetrics {
        table_payload_bytes: fields[0].parse().expect("table payload bytes"),
        body_bytes: fields[1].parse().expect("body bytes"),
        frame_count: fields[2].parse().expect("frame count"),
        peak_table_buffer_bytes: fields[3].parse().expect("peak table buffer"),
    }
}

fn parse_scalar(bytes: &[u8]) -> Scalar {
    let bytes: [u8; 32] = bytes.try_into().expect("scalar bytes");
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).expect("canonical scalar")
}

fn wrapping_add(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    let mut carry = 0_u16;
    let mut index = 0_usize;
    while index < output.len() {
        let sum = left[index] as u16 + right[index] as u16 + carry;
        output[index] = sum as u8;
        carry = sum >> 8;
        index += 1;
    }
    output
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert!(encoded.len().is_multiple_of(2));
    let bytes = encoded.as_bytes();
    bytes
        .chunks_exact(2)
        .map(|pair| (decode_nibble(pair[0]) << 4) | decode_nibble(pair[1]))
        .collect()
}

fn decode_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("lowercase hex required"),
    }
}

fn random_session_hex() -> String {
    loop {
        let mut session = [0_u8; 32];
        getrandom::getrandom(&mut session).expect("OS session randomness");
        if session.iter().any(|byte| *byte != 0) {
            let mut encoded = String::with_capacity(64);
            for byte in session {
                use core::fmt::Write as _;
                write!(encoded, "{byte:02x}").expect("writing to String succeeds");
            }
            return encoded;
        }
    }
}

fn unique_socket_path(family: &str, profile: StreamProfile, channel: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let ordinal = NEXT.fetch_add(1, Ordering::Relaxed);
    let family_tag = match family {
        "activation" => "a",
        "export" => "e",
        _ => "x",
    };
    let channel_tag = match channel {
        "control" => "c",
        "table" => "t",
        _ => "x",
    };
    std::env::temp_dir().join(format!(
        "ey{family_tag}{}{channel_tag}-{}-{ordinal}.sock",
        profile.cli_name(),
        std::process::id(),
    ))
}

fn percentile_micros(values: &mut [Duration], numerator: usize, denominator: usize) -> u128 {
    values.sort_unstable();
    let index = (values.len() * numerator).div_ceil(denominator) - 1;
    values[index].as_micros()
}
