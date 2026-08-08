//! Production-linked checks for the fixed 128 KiB local protocol.
//!
//! These finite checks deliberately drive the public role façade. They provide
//! runtime conformance and public-shape evidence. They are not universal
//! refinement or cryptographic privacy proofs.

use ed25519_yao::local_protocol as protocol;
use ed25519_yao_generator::{
    evaluate_activation, evaluate_full_clear_reference_export_v1, DeriverAContribution,
    DeriverBContribution, RawDeriverAContribution, RawDeriverBContribution,
};
use std::fmt::Write;

type CheckResult<T> = Result<T, String>;

const GENERATED_CASE_COUNT: usize = 6;
const SCALAR_ORDER_MINUS_ONE: [u8; 32] = [
    0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Activation,
    Export,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    DeriverA,
    DeriverB,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublicMessageShape {
    direction: protocol::WireDirection,
    kind: protocol::WireMessageKind,
    payload_bytes: usize,
}

#[derive(Debug, Clone)]
struct ProtocolCase {
    name: String,
    a_y_client: [u8; 32],
    a_y_server: [u8; 32],
    a_tau_client: [u8; 32],
    a_tau_server: [u8; 32],
    b_y_client: [u8; 32],
    b_y_server: [u8; 32],
    b_tau_client: [u8; 32],
    b_tau_server: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PassiveDeriverView {
    family: Family,
    role: Role,
    sent: Vec<PublicMessageShape>,
    received: Vec<PublicMessageShape>,
    frame_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicShape {
    family: Family,
    role: Role,
    sent: Vec<PublicMessageShape>,
    received: Vec<PublicMessageShape>,
    frame_count: u32,
}

#[derive(Debug, Default)]
struct RelayTrace {
    deriver_a_sent: Vec<PublicMessageShape>,
    deriver_a_received: Vec<PublicMessageShape>,
    deriver_b_sent: Vec<PublicMessageShape>,
    deriver_b_received: Vec<PublicMessageShape>,
}

struct RelayResult<AC, BC> {
    a: AC,
    b: BC,
    trace: RelayTrace,
}

pub(crate) fn run_runtime_conformance_check() -> CheckResult<()> {
    let cases = protocol_cases();
    for (index, case) in cases.iter().enumerate() {
        let expected_activation = DeriverAContribution::try_from(RawDeriverAContribution {
            y_client: case.a_y_client,
            y_server: case.a_y_server,
            tau_client: case.a_tau_client,
            tau_server: case.a_tau_server,
        })
        .map_err(|error| format!("activation A oracle input: {error}"))?;
        let expected_activation_b = DeriverBContribution::try_from(RawDeriverBContribution {
            y_client: case.b_y_client,
            y_server: case.b_y_server,
            tau_client: case.b_tau_client,
            tau_server: case.b_tau_server,
        })
        .map_err(|error| format!("activation B oracle input: {error}"))?;
        let activation = evaluate_activation(&expected_activation, &expected_activation_b);
        let activation_result = run_activation_case(session_for(Family::Activation, index), case)?;
        if activation_result.client != activation.material().x_client_base().expose_bytes()
            || activation_result.worker != activation.material().x_server_base().expose_bytes()
        {
            return Err(format!(
                "activation output mismatch for case `{}`",
                case.name
            ));
        }

        let expected_export =
            evaluate_full_clear_reference_export_v1(&expected_activation, &expected_activation_b);
        let export_result = run_export_case(session_for(Family::Export, index), case)?;
        if export_result != expected_export.seed().expose_bytes() {
            return Err(format!("export output mismatch for case `{}`", case.name));
        }
    }
    println!(
        "runtime-conformance-check ok: {} activation and {} export boundary/property cases",
        cases.len(),
        cases.len()
    );
    Ok(())
}

pub(crate) fn run_passive_public_shape_check() -> CheckResult<()> {
    let cases = protocol_cases();
    let mut activation_baseline = None;
    let mut export_baseline = None;
    for (index, case) in cases.iter().enumerate() {
        let activation = activation_views(session_for(Family::Activation, index), case)?;
        check_view_pair(&activation, &mut activation_baseline, case)?;
        let export = export_views(session_for(Family::Export, index), case)?;
        check_view_pair(&export, &mut export_baseline, case)?;
    }

    replayed_opening_messages_are_rejected()?;
    println!(
        "passive-public-shape-check ok: {} activation and {} export role-local views plus 4 opening-flight cross-session replay rejections",
        cases.len() * 2,
        cases.len() * 2
    );
    Ok(())
}

pub(crate) fn render_runtime_public_shape_lean() -> CheckResult<String> {
    let case = boundary_cases()
        .into_iter()
        .next()
        .ok_or_else(|| "protocol boundary case set is empty".to_owned())?;
    let activation = activation_views([0x71; 32], &case)?;
    let export = export_views([0x72; 32], &case)?;
    assert_expected_view(&activation.0)?;
    assert_expected_view(&activation.1)?;
    assert_expected_view(&export.0)?;
    assert_expected_view(&export.1)?;

    let mut source = String::new();
    source.push_str(
        "-- This file is generated from production local-protocol executions.\n\
         -- Regenerate with UPDATE_ED25519_YAO_RUNTIME_PUBLIC_SHAPE=1 cargo yao-fv lean-check.\n\n\
         namespace Ed25519YaoModel\n\n\
         inductive RuntimeProtocolFamily where\n\
           | activation\n\
           | export\n\
           deriving DecidableEq, Repr\n\n\
         inductive RuntimeDeriverRole where\n\
           | deriverA\n\
           | deriverB\n\
           deriving DecidableEq, Repr\n\n\
         inductive RuntimeWireDirection where\n\
           | deriverAToDeriverB\n\
           | deriverBToDeriverA\n\
           deriving DecidableEq, Repr\n\n\
         inductive RuntimeWireMessageKind where\n\
           | baseOtOffer\n\
           | baseOtChoices\n\
           | directInputLabels\n\
           | otExtensionMatrix\n\
           | maskedInputLabels\n\
           | streamManifest\n\
           | tableFrame\n\
           | outputTranslation\n\
           | returnedOutputLabels\n\
           deriving DecidableEq, Repr\n\n\
         structure RuntimeMessageShape where\n\
           direction : RuntimeWireDirection\n\
           kind : RuntimeWireMessageKind\n\
           payloadBytes : Nat\n\
           deriving DecidableEq, Repr\n\n\
         structure RuntimeRoleView where\n\
           family : RuntimeProtocolFamily\n\
           role : RuntimeDeriverRole\n\
           sent : List RuntimeMessageShape\n\
           received : List RuntimeMessageShape\n\
           frameCount : Nat\n\
           deriving DecidableEq, Repr\n\n",
    );
    render_lean_role_view(&mut source, "activationDeriverAView", &activation.0)?;
    render_lean_role_view(&mut source, "activationDeriverBView", &activation.1)?;
    render_lean_role_view(&mut source, "exportDeriverAView", &export.0)?;
    render_lean_role_view(&mut source, "exportDeriverBView", &export.1)?;
    source.push_str(
        "def runtimeRoleView : RuntimeProtocolFamily → RuntimeDeriverRole → RuntimeRoleView\n\
           | .activation, .deriverA => activationDeriverAView\n\
           | .activation, .deriverB => activationDeriverBView\n\
           | .export, .deriverA => exportDeriverAView\n\
           | .export, .deriverB => exportDeriverBView\n\n\
         end Ed25519YaoModel\n",
    );
    Ok(source)
}

fn render_lean_role_view(
    source: &mut String,
    name: &str,
    view: &PassiveDeriverView,
) -> CheckResult<()> {
    writeln!(source, "def {name} : RuntimeRoleView :=")
        .map_err(|_| "runtime public-shape Lean rendering failed".to_owned())?;
    writeln!(source, "  {{ family := .{}", lean_family(view.family))
        .map_err(|_| "runtime public-shape Lean rendering failed".to_owned())?;
    writeln!(source, "    role := .{}", lean_role(view.role))
        .map_err(|_| "runtime public-shape Lean rendering failed".to_owned())?;
    render_lean_message_list(source, "sent", &view.sent)?;
    render_lean_message_list(source, "received", &view.received)?;
    writeln!(source, "    frameCount := {} }}\n", view.frame_count)
        .map_err(|_| "runtime public-shape Lean rendering failed".to_owned())
}

fn render_lean_message_list(
    source: &mut String,
    field: &str,
    messages: &[PublicMessageShape],
) -> CheckResult<()> {
    writeln!(source, "    {field} :=")
        .map_err(|_| "runtime public-shape Lean rendering failed".to_owned())?;
    for (index, message) in messages.iter().enumerate() {
        let prefix = if index == 0 { "      [" } else { "       " };
        let suffix = if index + 1 == messages.len() {
            "]"
        } else {
            ","
        };
        writeln!(
            source,
            "{prefix}⟨.{}, .{}, {}⟩{suffix}",
            lean_direction(message.direction),
            lean_message_kind(message.kind),
            message.payload_bytes
        )
        .map_err(|_| "runtime public-shape Lean rendering failed".to_owned())?;
    }
    Ok(())
}

fn lean_family(family: Family) -> &'static str {
    match family {
        Family::Activation => "activation",
        Family::Export => "export",
    }
}

fn lean_role(role: Role) -> &'static str {
    match role {
        Role::DeriverA => "deriverA",
        Role::DeriverB => "deriverB",
    }
}

fn lean_direction(direction: protocol::WireDirection) -> &'static str {
    match direction {
        protocol::WireDirection::DeriverAToDeriverB => "deriverAToDeriverB",
        protocol::WireDirection::DeriverBToDeriverA => "deriverBToDeriverA",
    }
}

fn lean_message_kind(kind: protocol::WireMessageKind) -> &'static str {
    match kind {
        protocol::WireMessageKind::BaseOtOffer => "baseOtOffer",
        protocol::WireMessageKind::BaseOtChoices => "baseOtChoices",
        protocol::WireMessageKind::DirectInputLabels => "directInputLabels",
        protocol::WireMessageKind::OtExtensionMatrix => "otExtensionMatrix",
        protocol::WireMessageKind::MaskedInputLabels => "maskedInputLabels",
        protocol::WireMessageKind::StreamManifest => "streamManifest",
        protocol::WireMessageKind::TableFrame => "tableFrame",
        protocol::WireMessageKind::OutputTranslation => "outputTranslation",
        protocol::WireMessageKind::ReturnedOutputLabels => "returnedOutputLabels",
    }
}

fn check_view_pair(
    views: &(PassiveDeriverView, PassiveDeriverView),
    baseline: &mut Option<(PassiveDeriverView, PassiveDeriverView)>,
    case: &ProtocolCase,
) -> CheckResult<()> {
    assert_expected_view(&views.0)?;
    assert_expected_view(&views.1)?;
    if let Some(expected) = baseline {
        if !same_public_shape(&expected.0, &views.0) || !same_public_shape(&expected.1, &views.1) {
            return Err(format!(
                "public message shape depends on private input bytes for case `{}`",
                case.name
            ));
        }
    } else {
        *baseline = Some(views.clone());
    }
    Ok(())
}

fn activation_views(
    session: [u8; 32],
    case: &ProtocolCase,
) -> CheckResult<(PassiveDeriverView, PassiveDeriverView)> {
    let a_inputs = protocol::ActivationDeriverAInputs::new(
        case.a_y_client,
        case.a_y_server,
        case.a_tau_client,
        case.a_tau_server,
    )
    .map_err(|_| "activation A input construction failed".to_owned())?;
    let b_inputs = protocol::ActivationDeriverBInputs::new(
        case.b_y_client,
        case.b_y_server,
        case.b_tau_client,
        case.b_tau_server,
    )
    .map_err(|_| "activation B input construction failed".to_owned())?;
    let relay = run_relay(
        session,
        protocol::Activation128KiBDeriverA::with_inputs(session, a_inputs)
            .map_err(|_| "activation A role construction failed".to_owned())?,
        protocol::Activation128KiBDeriverB::with_inputs(session, b_inputs)
            .map_err(|_| "activation B role construction failed".to_owned())?,
        protocol::Activation128KiBDeriverA::handle,
        protocol::Activation128KiBDeriverB::handle,
    )?;
    let a_view = project_view(
        Family::Activation,
        Role::DeriverA,
        &relay.trace,
        relay.a.stream_metrics().frame_count(),
    )?;
    let b_view = project_view(
        Family::Activation,
        Role::DeriverB,
        &relay.trace,
        relay.b.stream_metrics().frame_count(),
    )?;
    Ok((a_view, b_view))
}

fn export_views(
    session: [u8; 32],
    case: &ProtocolCase,
) -> CheckResult<(PassiveDeriverView, PassiveDeriverView)> {
    let a_inputs = protocol::ExportDeriverAInputs::new(case.a_y_client, case.a_y_server)
        .map_err(|_| "export A input construction failed".to_owned())?;
    let b_inputs = protocol::ExportDeriverBInputs::new(case.b_y_client, case.b_y_server)
        .map_err(|_| "export B input construction failed".to_owned())?;
    let relay = run_relay(
        session,
        protocol::Export128KiBDeriverA::with_inputs(session, a_inputs)
            .map_err(|_| "export A role construction failed".to_owned())?,
        protocol::Export128KiBDeriverB::with_inputs(session, b_inputs)
            .map_err(|_| "export B role construction failed".to_owned())?,
        protocol::Export128KiBDeriverA::handle,
        protocol::Export128KiBDeriverB::handle,
    )?;
    let a_view = project_view(
        Family::Export,
        Role::DeriverA,
        &relay.trace,
        relay.a.stream_metrics().frame_count(),
    )?;
    let b_view = project_view(
        Family::Export,
        Role::DeriverB,
        &relay.trace,
        relay.b.stream_metrics().frame_count(),
    )?;
    Ok((a_view, b_view))
}

fn same_public_shape(left: &PassiveDeriverView, right: &PassiveDeriverView) -> bool {
    left.family == right.family
        && left.role == right.role
        && left.sent == right.sent
        && left.received == right.received
        && left.frame_count == right.frame_count
}

fn session_for(family: Family, index: usize) -> [u8; 32] {
    let tag: u8 = match family {
        Family::Activation => 0xa1,
        Family::Export => 0xe1,
    };
    [tag.wrapping_add(index as u8); 32]
}

fn protocol_cases() -> Vec<ProtocolCase> {
    let mut cases = boundary_cases();
    for index in 0..GENERATED_CASE_COUNT {
        cases.push(generated_case(index));
    }
    cases
}

fn boundary_cases() -> Vec<ProtocolCase> {
    let zero = [0_u8; 32];
    let one = scalar_from_u64(1);
    let two = scalar_from_u64(2);
    let three = scalar_from_u64(3);
    let mut low_carry = [0_u8; 32];
    low_carry[0] = 0xff;
    let mut cross_byte = [0_u8; 32];
    cross_byte[0] = 1;
    let mut high_bit = [0_u8; 32];
    high_bit[31] = 0x80;
    vec![
        ProtocolCase {
            name: "all-zero".to_owned(),
            a_y_client: zero,
            a_y_server: zero,
            a_tau_client: zero,
            a_tau_server: zero,
            b_y_client: zero,
            b_y_server: zero,
            b_tau_client: zero,
            b_tau_server: zero,
        },
        ProtocolCase {
            name: "independent-small-scalars".to_owned(),
            a_y_client: patterned_bytes(0x11, 0x17),
            a_y_server: patterned_bytes(0x22, 0x1d),
            a_tau_client: one,
            a_tau_server: two,
            b_y_client: patterned_bytes(0x33, 0x23),
            b_y_server: patterned_bytes(0x44, 0x29),
            b_tau_client: three,
            b_tau_server: scalar_from_u64(4),
        },
        ProtocolCase {
            name: "little-endian-carry".to_owned(),
            a_y_client: low_carry,
            a_y_server: cross_byte,
            a_tau_client: scalar_from_u64(0xff),
            a_tau_server: one,
            b_y_client: patterned_bytes(0xfe, 0xff),
            b_y_server: patterned_bytes(0x01, 0x01),
            b_tau_client: scalar_from_u64(0xffff),
            b_tau_server: one,
        },
        ProtocolCase {
            name: "full-width-y-wrap".to_owned(),
            a_y_client: [0xff; 32],
            a_y_server: one,
            a_tau_client: one,
            a_tau_server: two,
            b_y_client: [0xff; 32],
            b_y_server: high_bit,
            b_tau_client: three,
            b_tau_server: scalar_from_u64(5),
        },
        ProtocolCase {
            name: "scalar-order-wrap".to_owned(),
            a_y_client: patterned_bytes(0x80, 0x03),
            a_y_server: patterned_bytes(0x7f, 0xfb),
            a_tau_client: SCALAR_ORDER_MINUS_ONE,
            a_tau_server: one,
            b_y_client: patterned_bytes(0xa5, 0x5b),
            b_y_server: patterned_bytes(0x5a, 0xa7),
            b_tau_client: SCALAR_ORDER_MINUS_ONE,
            b_tau_server: SCALAR_ORDER_MINUS_ONE,
        },
        ProtocolCase {
            name: "endianness-sentinels".to_owned(),
            a_y_client: endianness_sentinel(0x01, 0x80),
            a_y_server: endianness_sentinel(0x02, 0x40),
            a_tau_client: scalar_from_u64(0x0102_0304_0506_0708),
            a_tau_server: scalar_from_u64(0x1112_1314_1516_1718),
            b_y_client: endianness_sentinel(0x04, 0x20),
            b_y_server: endianness_sentinel(0x08, 0x10),
            b_tau_client: scalar_from_u64(0x2122_2324_2526_2728),
            b_tau_server: scalar_from_u64(0x3132_3334_3536_3738),
        },
    ]
}

fn generated_case(index: usize) -> ProtocolCase {
    let seed = 0x9e37_79b9_7f4a_7c15_u64 ^ (index as u64).wrapping_mul(0x1000_0000_01b3);
    ProtocolCase {
        name: format!("fixed-seed-{index}"),
        a_y_client: generated_bytes(seed, 0),
        a_y_server: generated_bytes(seed, 1),
        a_tau_client: scalar_from_u64(generated_u64(seed, 2)),
        a_tau_server: scalar_from_u64(generated_u64(seed, 3)),
        b_y_client: generated_bytes(seed, 4),
        b_y_server: generated_bytes(seed, 5),
        b_tau_client: scalar_from_u64(generated_u64(seed, 6)),
        b_tau_server: scalar_from_u64(generated_u64(seed, 7)),
    }
}

fn patterned_bytes(start: u8, step: u8) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = start.wrapping_add(step.wrapping_mul(index as u8));
    }
    bytes
}

fn endianness_sentinel(low: u8, high: u8) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[0] = low;
    bytes[7] = low.wrapping_mul(3);
    bytes[24] = high.wrapping_mul(3);
    bytes[31] = high;
    bytes
}

fn scalar_from_u64(value: u64) -> [u8; 32] {
    let mut scalar = [0_u8; 32];
    scalar[..8].copy_from_slice(&value.to_le_bytes());
    scalar
}

fn generated_u64(seed: u64, lane: u64) -> u64 {
    let mut value = seed ^ lane.wrapping_mul(0xd6e8_feb8_6659_fd93);
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    value.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

fn generated_bytes(seed: u64, lane: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for chunk_index in 0..4 {
        let value = generated_u64(seed, lane.wrapping_mul(4) + chunk_index as u64);
        let start = chunk_index * 8;
        bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

struct ActivationResult {
    client: [u8; 32],
    worker: [u8; 32],
}

fn run_activation_case(session: [u8; 32], case: &ProtocolCase) -> CheckResult<ActivationResult> {
    let a_inputs = protocol::ActivationDeriverAInputs::new(
        case.a_y_client,
        case.a_y_server,
        case.a_tau_client,
        case.a_tau_server,
    )
    .map_err(|_| "activation A input construction failed".to_owned())?;
    let b_inputs = protocol::ActivationDeriverBInputs::new(
        case.b_y_client,
        case.b_y_server,
        case.b_tau_client,
        case.b_tau_server,
    )
    .map_err(|_| "activation B input construction failed".to_owned())?;
    let relay = run_relay(
        session,
        protocol::Activation128KiBDeriverA::with_inputs(session, a_inputs)
            .map_err(|_| "activation A role construction failed".to_owned())?,
        protocol::Activation128KiBDeriverB::with_inputs(session, b_inputs)
            .map_err(|_| "activation B role construction failed".to_owned())?,
        protocol::Activation128KiBDeriverA::handle,
        protocol::Activation128KiBDeriverB::handle,
    )?;
    let final_transcript = relay.a.final_transcript();
    let client = protocol::combine_client_activation_packages(
        session,
        final_transcript,
        relay.a.client_package(),
        relay.b.client_package(),
    )
    .map_err(|_| "activation client package combination failed".to_owned())?
    .into_bytes();
    let worker = protocol::combine_signing_worker_activation_packages(
        session,
        final_transcript,
        relay.a.signing_worker_package(),
        relay.b.signing_worker_package(),
    )
    .map_err(|_| "activation worker package combination failed".to_owned())?
    .into_bytes();
    Ok(ActivationResult { client, worker })
}

fn run_export_case(session: [u8; 32], case: &ProtocolCase) -> CheckResult<[u8; 32]> {
    let a_inputs = protocol::ExportDeriverAInputs::new(case.a_y_client, case.a_y_server)
        .map_err(|_| "export A input construction failed".to_owned())?;
    let b_inputs = protocol::ExportDeriverBInputs::new(case.b_y_client, case.b_y_server)
        .map_err(|_| "export B input construction failed".to_owned())?;
    let relay = run_relay(
        session,
        protocol::Export128KiBDeriverA::with_inputs(session, a_inputs)
            .map_err(|_| "export A role construction failed".to_owned())?,
        protocol::Export128KiBDeriverB::with_inputs(session, b_inputs)
            .map_err(|_| "export B role construction failed".to_owned())?,
        protocol::Export128KiBDeriverA::handle,
        protocol::Export128KiBDeriverB::handle,
    )?;
    let seed = protocol::combine_export_packages(
        session,
        relay.a.final_transcript(),
        relay.a.export_package(),
        relay.b.export_package(),
    )
    .map_err(|_| "export package combination failed".to_owned())?
    .into_bytes();
    Ok(seed)
}

fn run_relay<A, B, AC, BC>(
    session: [u8; 32],
    mut a: A,
    mut b: B,
    handle_a: fn(
        A,
        protocol::RelayEvent,
    ) -> Result<protocol::RelayStep<A, AC>, protocol::BenchmarkRoleError>,
    handle_b: fn(
        B,
        protocol::RelayEvent,
    ) -> Result<protocol::RelayStep<B, BC>, protocol::BenchmarkRoleError>,
) -> CheckResult<RelayResult<AC, BC>> {
    let mut a_to_b_encoder =
        protocol::DirectionalWireEncoder::new(protocol::WireDirection::DeriverAToDeriverB, session)
            .map_err(|_| "A→B encoder construction failed".to_owned())?;
    let mut a_to_b_decoder =
        protocol::DirectionalWireDecoder::new(protocol::WireDirection::DeriverAToDeriverB, session)
            .map_err(|_| "A→B decoder construction failed".to_owned())?;
    let mut b_to_a_encoder =
        protocol::DirectionalWireEncoder::new(protocol::WireDirection::DeriverBToDeriverA, session)
            .map_err(|_| "B→A encoder construction failed".to_owned())?;
    let mut b_to_a_decoder =
        protocol::DirectionalWireDecoder::new(protocol::WireDirection::DeriverBToDeriverA, session)
            .map_err(|_| "B→A decoder construction failed".to_owned())?;
    let mut trace = RelayTrace::default();

    let (next_b, offer) = expect_send(handle_b(b, protocol::RelayEvent::Advance))?;
    b = next_b;
    let offer = route_message(
        offer,
        protocol::WireDirection::DeriverBToDeriverA,
        &mut b_to_a_encoder,
        &mut b_to_a_decoder,
        &mut trace,
    )?;
    a = expect_continue(handle_a(a, protocol::RelayEvent::Inbound(offer)))?;

    let (next_a, base_choices) = expect_send(handle_a(a, protocol::RelayEvent::Advance))?;
    a = next_a;
    let base_choices = route_message(
        base_choices,
        protocol::WireDirection::DeriverAToDeriverB,
        &mut a_to_b_encoder,
        &mut a_to_b_decoder,
        &mut trace,
    )?;
    b = expect_continue(handle_b(b, protocol::RelayEvent::Inbound(base_choices)))?;

    let (next_a, direct) = expect_send(handle_a(a, protocol::RelayEvent::Advance))?;
    a = next_a;
    let direct = route_message(
        direct,
        protocol::WireDirection::DeriverAToDeriverB,
        &mut a_to_b_encoder,
        &mut a_to_b_decoder,
        &mut trace,
    )?;
    let (next_b, extension) = expect_send(handle_b(b, protocol::RelayEvent::Inbound(direct)))?;
    b = next_b;
    let extension = route_message(
        extension,
        protocol::WireDirection::DeriverBToDeriverA,
        &mut b_to_a_encoder,
        &mut b_to_a_decoder,
        &mut trace,
    )?;
    a = expect_continue(handle_a(a, protocol::RelayEvent::Inbound(extension)))?;

    let (next_a, masked) = expect_send(handle_a(a, protocol::RelayEvent::Advance))?;
    a = next_a;
    let masked = route_message(
        masked,
        protocol::WireDirection::DeriverAToDeriverB,
        &mut a_to_b_encoder,
        &mut a_to_b_decoder,
        &mut trace,
    )?;
    b = expect_continue(handle_b(b, protocol::RelayEvent::Inbound(masked)))?;

    let (next_a, manifest) = expect_send(handle_a(a, protocol::RelayEvent::Advance))?;
    a = next_a;
    let manifest = route_message(
        manifest,
        protocol::WireDirection::DeriverAToDeriverB,
        &mut a_to_b_encoder,
        &mut a_to_b_decoder,
        &mut trace,
    )?;
    b = expect_continue(handle_b(b, protocol::RelayEvent::Inbound(manifest)))?;

    let translation = loop {
        let (next_a, message) = expect_send(handle_a(a, protocol::RelayEvent::Advance))?;
        a = next_a;
        match message.kind() {
            protocol::WireMessageKind::TableFrame => {
                let frame = route_message(
                    message,
                    protocol::WireDirection::DeriverAToDeriverB,
                    &mut a_to_b_encoder,
                    &mut a_to_b_decoder,
                    &mut trace,
                )?;
                b = expect_continue(handle_b(b, protocol::RelayEvent::Inbound(frame)))?;
            }
            protocol::WireMessageKind::OutputTranslation => break message,
            kind => return Err(format!("unexpected A stream message: {kind:?}")),
        }
    };
    let translation = route_message(
        translation,
        protocol::WireDirection::DeriverAToDeriverB,
        &mut a_to_b_encoder,
        &mut a_to_b_decoder,
        &mut trace,
    )?;
    b = expect_continue(handle_b(b, protocol::RelayEvent::Inbound(translation)))?;
    let a_local_eof = a_to_b_encoder
        .finish_after_transport_close()
        .map_err(|_| "A→B encoder EOF failed".to_owned())?;
    a = expect_continue(handle_a(
        a,
        protocol::RelayEvent::LocalDirectionalEof(a_local_eof),
    ))?;
    let b_peer_eof = a_to_b_decoder
        .finish_at_transport_eof()
        .map_err(|_| "B A→B decoder EOF failed".to_owned())?;
    b = expect_continue(handle_b(
        b,
        protocol::RelayEvent::InboundDirectionalEof(b_peer_eof),
    ))?;

    let (next_b, returned) = expect_send(handle_b(b, protocol::RelayEvent::Advance))?;
    b = next_b;
    let returned = route_message(
        returned,
        protocol::WireDirection::DeriverBToDeriverA,
        &mut b_to_a_encoder,
        &mut b_to_a_decoder,
        &mut trace,
    )?;
    a = expect_continue(handle_a(a, protocol::RelayEvent::Inbound(returned)))?;
    let b_local_eof = b_to_a_encoder
        .finish_after_transport_close()
        .map_err(|_| "B→A encoder EOF failed".to_owned())?;
    let b = expect_complete(handle_b(
        b,
        protocol::RelayEvent::LocalDirectionalEof(b_local_eof),
    ))?;
    let a_peer_eof = b_to_a_decoder
        .finish_at_transport_eof()
        .map_err(|_| "A B→A decoder EOF failed".to_owned())?;
    let a = expect_complete(handle_a(
        a,
        protocol::RelayEvent::InboundDirectionalEof(a_peer_eof),
    ))?;
    Ok(RelayResult { a, b, trace })
}

fn route_message(
    message: protocol::WireMessage,
    direction: protocol::WireDirection,
    encoder: &mut protocol::DirectionalWireEncoder,
    decoder: &mut protocol::DirectionalWireDecoder,
    trace: &mut RelayTrace,
) -> CheckResult<protocol::WireMessage> {
    let shape = PublicMessageShape {
        direction,
        kind: message.kind(),
        payload_bytes: message.as_bytes().len(),
    };
    match direction {
        protocol::WireDirection::DeriverAToDeriverB => {
            trace.deriver_a_sent.push(shape);
            trace.deriver_b_received.push(shape);
        }
        protocol::WireDirection::DeriverBToDeriverA => {
            trace.deriver_b_sent.push(shape);
            trace.deriver_a_received.push(shape);
        }
    }
    let encoded = encoder
        .encode(message)
        .map_err(|_| "wire envelope encoding failed".to_owned())?;
    let mut offset = 0_usize;
    while offset < encoded.len() {
        let end = (offset + 17).min(encoded.len());
        let consumed = decoder
            .push(&encoded[offset..end])
            .map_err(|_| "wire envelope decoding failed".to_owned())?;
        if consumed == 0 {
            return Err("wire decoder made no progress".to_owned());
        }
        offset += consumed;
    }
    decoder
        .take_message()
        .map_err(|_| "wire message extraction failed".to_owned())?
        .ok_or_else(|| "wire message was incomplete after routing".to_owned())
}

fn expect_continue<R, C>(
    step: Result<protocol::RelayStep<R, C>, protocol::BenchmarkRoleError>,
) -> CheckResult<R> {
    match step.map_err(|_| "role transition failed".to_owned())? {
        protocol::RelayStep::Continue(role) => Ok(role),
        protocol::RelayStep::Send { .. } => Err("role emitted an unexpected message".to_owned()),
        protocol::RelayStep::Complete(_) => Err("role completed too early".to_owned()),
    }
}

fn expect_send<R, C>(
    step: Result<protocol::RelayStep<R, C>, protocol::BenchmarkRoleError>,
) -> CheckResult<(R, protocol::WireMessage)> {
    match step.map_err(|_| "role transition failed".to_owned())? {
        protocol::RelayStep::Send { role, message } => Ok((role, message)),
        protocol::RelayStep::Continue(_) => Err("role did not emit a message".to_owned()),
        protocol::RelayStep::Complete(_) => {
            Err("role completed before emitting a message".to_owned())
        }
    }
}

fn expect_complete<R, C>(
    step: Result<protocol::RelayStep<R, C>, protocol::BenchmarkRoleError>,
) -> CheckResult<C> {
    match step.map_err(|_| "role transition failed".to_owned())? {
        protocol::RelayStep::Complete(completed) => Ok(completed),
        protocol::RelayStep::Continue(_) => Err("role remained live after terminal EOF".to_owned()),
        protocol::RelayStep::Send { .. } => Err("role emitted after terminal EOF".to_owned()),
    }
}

fn project_view(
    family: Family,
    role: Role,
    trace: &RelayTrace,
    frame_count: u32,
) -> CheckResult<PassiveDeriverView> {
    let (sent, received) = match role {
        Role::DeriverA => (
            trace.deriver_a_sent.clone(),
            trace.deriver_a_received.clone(),
        ),
        Role::DeriverB => (
            trace.deriver_b_sent.clone(),
            trace.deriver_b_received.clone(),
        ),
    };
    if sent.is_empty() || received.is_empty() {
        return Err("passive view has no protocol messages".to_owned());
    }
    validate_view_shapes(family, &sent)?;
    validate_view_shapes(family, &received)?;
    Ok(PassiveDeriverView {
        family,
        role,
        sent,
        received,
        frame_count,
    })
}

fn validate_view_shapes(_family: Family, messages: &[PublicMessageShape]) -> CheckResult<()> {
    for message in messages {
        let expected_direction = match message.kind {
            protocol::WireMessageKind::BaseOtOffer
            | protocol::WireMessageKind::OtExtensionMatrix
            | protocol::WireMessageKind::ReturnedOutputLabels => {
                protocol::WireDirection::DeriverBToDeriverA
            }
            protocol::WireMessageKind::BaseOtChoices
            | protocol::WireMessageKind::DirectInputLabels
            | protocol::WireMessageKind::MaskedInputLabels
            | protocol::WireMessageKind::StreamManifest
            | protocol::WireMessageKind::TableFrame
            | protocol::WireMessageKind::OutputTranslation => {
                protocol::WireDirection::DeriverAToDeriverB
            }
        };
        if message.direction != expected_direction || message.payload_bytes == 0 {
            return Err("passive view contains an invalid public message shape".to_owned());
        }
    }
    Ok(())
}

fn assert_expected_view(view: &PassiveDeriverView) -> CheckResult<()> {
    let observed = PublicShape {
        family: view.family,
        role: view.role,
        sent: view.sent.clone(),
        received: view.received.clone(),
        frame_count: view.frame_count,
    };
    let expected = expected_public_view(view.family, view.role);
    if observed != expected {
        return Err("passive view did not match its fixed public shape".to_owned());
    }
    Ok(())
}

fn expected_public_view(family: Family, role: Role) -> PublicShape {
    let messages = expected_public_trace(family);
    let sent = messages
        .iter()
        .copied()
        .filter(|message| role_sends(role, message.direction))
        .collect();
    let received = messages
        .iter()
        .copied()
        .filter(|message| !role_sends(role, message.direction))
        .collect();
    let frame_count = messages
        .iter()
        .filter(|message| message.kind == protocol::WireMessageKind::TableFrame)
        .count() as u32;
    PublicShape {
        family,
        role,
        sent,
        received,
        frame_count,
    }
}

fn role_sends(role: Role, direction: protocol::WireDirection) -> bool {
    matches!(
        (role, direction),
        (Role::DeriverA, protocol::WireDirection::DeriverAToDeriverB)
            | (Role::DeriverB, protocol::WireDirection::DeriverBToDeriverA)
    )
}

fn expected_public_trace(family: Family) -> Vec<PublicMessageShape> {
    let (
        direct_bytes,
        extension_bytes,
        masked_bytes,
        frame_payload_bytes,
        frame_count,
        final_frame_payload_bytes,
        translation_bytes,
        returned_bytes,
    ) = match family {
        Family::Activation => (24_732, 24_624, 49_200, 131_072, 17, 7_808, 220, 8_348),
        Family::Export => (12_444, 12_336, 24_624, 40_800, 1, 40_800, 188, 4_252),
    };
    let mut messages = vec![
        public_shape(
            protocol::WireDirection::DeriverBToDeriverA,
            protocol::WireMessageKind::BaseOtOffer,
            4_144,
        ),
        public_shape(
            protocol::WireDirection::DeriverAToDeriverB,
            protocol::WireMessageKind::BaseOtChoices,
            4_144,
        ),
        public_shape(
            protocol::WireDirection::DeriverAToDeriverB,
            protocol::WireMessageKind::DirectInputLabels,
            direct_bytes,
        ),
        public_shape(
            protocol::WireDirection::DeriverBToDeriverA,
            protocol::WireMessageKind::OtExtensionMatrix,
            extension_bytes,
        ),
        public_shape(
            protocol::WireDirection::DeriverAToDeriverB,
            protocol::WireMessageKind::MaskedInputLabels,
            masked_bytes,
        ),
        public_shape(
            protocol::WireDirection::DeriverAToDeriverB,
            protocol::WireMessageKind::StreamManifest,
            248,
        ),
    ];
    for frame_index in 0..frame_count {
        let payload_bytes = if frame_index + 1 == frame_count {
            final_frame_payload_bytes
        } else {
            frame_payload_bytes
        };
        messages.push(public_shape(
            protocol::WireDirection::DeriverAToDeriverB,
            protocol::WireMessageKind::TableFrame,
            92 + payload_bytes,
        ));
    }
    messages.extend([
        public_shape(
            protocol::WireDirection::DeriverAToDeriverB,
            protocol::WireMessageKind::OutputTranslation,
            translation_bytes,
        ),
        public_shape(
            protocol::WireDirection::DeriverBToDeriverA,
            protocol::WireMessageKind::ReturnedOutputLabels,
            returned_bytes,
        ),
    ]);
    messages
}

fn public_shape(
    direction: protocol::WireDirection,
    kind: protocol::WireMessageKind,
    payload_bytes: usize,
) -> PublicMessageShape {
    PublicMessageShape {
        direction,
        kind,
        payload_bytes,
    }
}

fn replayed_opening_messages_are_rejected() -> CheckResult<()> {
    activation_offer_replay_is_rejected()?;
    activation_choices_replay_is_rejected()?;
    export_offer_replay_is_rejected()?;
    export_choices_replay_is_rejected()
}

fn activation_offer_replay_is_rejected() -> CheckResult<()> {
    let target_session = [0x31; 32];
    let foreign_session = [0x32; 32];
    let target_a = protocol::Activation128KiBDeriverA::with_inputs(
        target_session,
        activation_a_replay_inputs()?,
    )
    .map_err(|_| "activation replay target A construction failed".to_owned())?;
    let foreign_b = protocol::Activation128KiBDeriverB::with_inputs(
        foreign_session,
        activation_b_replay_inputs()?,
    )
    .map_err(|_| "activation replay foreign B construction failed".to_owned())?;
    let (_, offer) = expect_send(protocol::Activation128KiBDeriverB::handle(
        foreign_b,
        protocol::RelayEvent::Advance,
    ))?;
    let replayed = replay_round_trip(
        offer,
        protocol::WireDirection::DeriverBToDeriverA,
        foreign_session,
    )?;
    reject_replay(
        protocol::Activation128KiBDeriverA::handle(
            target_a,
            protocol::RelayEvent::Inbound(replayed),
        ),
        "activation BaseOtOffer",
    )
}

fn activation_choices_replay_is_rejected() -> CheckResult<()> {
    let target_session = [0x33; 32];
    let foreign_session = [0x34; 32];
    let target_b = protocol::Activation128KiBDeriverB::with_inputs(
        target_session,
        activation_b_replay_inputs()?,
    )
    .map_err(|_| "activation replay target B construction failed".to_owned())?;
    let (target_b, _) = expect_send(protocol::Activation128KiBDeriverB::handle(
        target_b,
        protocol::RelayEvent::Advance,
    ))?;
    let foreign_a = protocol::Activation128KiBDeriverA::with_inputs(
        foreign_session,
        activation_a_replay_inputs()?,
    )
    .map_err(|_| "activation replay foreign A construction failed".to_owned())?;
    let foreign_b = protocol::Activation128KiBDeriverB::with_inputs(
        foreign_session,
        activation_b_replay_inputs()?,
    )
    .map_err(|_| "activation replay foreign B construction failed".to_owned())?;
    let (_, offer) = expect_send(protocol::Activation128KiBDeriverB::handle(
        foreign_b,
        protocol::RelayEvent::Advance,
    ))?;
    let offer = replay_round_trip(
        offer,
        protocol::WireDirection::DeriverBToDeriverA,
        foreign_session,
    )?;
    let foreign_a = expect_continue(protocol::Activation128KiBDeriverA::handle(
        foreign_a,
        protocol::RelayEvent::Inbound(offer),
    ))?;
    let (_, choices) = expect_send(protocol::Activation128KiBDeriverA::handle(
        foreign_a,
        protocol::RelayEvent::Advance,
    ))?;
    let replayed = replay_round_trip(
        choices,
        protocol::WireDirection::DeriverAToDeriverB,
        foreign_session,
    )?;
    reject_replay(
        protocol::Activation128KiBDeriverB::handle(
            target_b,
            protocol::RelayEvent::Inbound(replayed),
        ),
        "activation BaseOtChoices",
    )
}

fn export_offer_replay_is_rejected() -> CheckResult<()> {
    let target_session = [0x35; 32];
    let foreign_session = [0x36; 32];
    let target_a =
        protocol::Export128KiBDeriverA::with_inputs(target_session, export_a_replay_inputs()?)
            .map_err(|_| "export replay target A construction failed".to_owned())?;
    let foreign_b =
        protocol::Export128KiBDeriverB::with_inputs(foreign_session, export_b_replay_inputs()?)
            .map_err(|_| "export replay foreign B construction failed".to_owned())?;
    let (_, offer) = expect_send(protocol::Export128KiBDeriverB::handle(
        foreign_b,
        protocol::RelayEvent::Advance,
    ))?;
    let replayed = replay_round_trip(
        offer,
        protocol::WireDirection::DeriverBToDeriverA,
        foreign_session,
    )?;
    reject_replay(
        protocol::Export128KiBDeriverA::handle(target_a, protocol::RelayEvent::Inbound(replayed)),
        "export BaseOtOffer",
    )
}

fn export_choices_replay_is_rejected() -> CheckResult<()> {
    let target_session = [0x37; 32];
    let foreign_session = [0x38; 32];
    let target_b =
        protocol::Export128KiBDeriverB::with_inputs(target_session, export_b_replay_inputs()?)
            .map_err(|_| "export replay target B construction failed".to_owned())?;
    let (target_b, _) = expect_send(protocol::Export128KiBDeriverB::handle(
        target_b,
        protocol::RelayEvent::Advance,
    ))?;
    let foreign_a =
        protocol::Export128KiBDeriverA::with_inputs(foreign_session, export_a_replay_inputs()?)
            .map_err(|_| "export replay foreign A construction failed".to_owned())?;
    let foreign_b =
        protocol::Export128KiBDeriverB::with_inputs(foreign_session, export_b_replay_inputs()?)
            .map_err(|_| "export replay foreign B construction failed".to_owned())?;
    let (_, offer) = expect_send(protocol::Export128KiBDeriverB::handle(
        foreign_b,
        protocol::RelayEvent::Advance,
    ))?;
    let offer = replay_round_trip(
        offer,
        protocol::WireDirection::DeriverBToDeriverA,
        foreign_session,
    )?;
    let foreign_a = expect_continue(protocol::Export128KiBDeriverA::handle(
        foreign_a,
        protocol::RelayEvent::Inbound(offer),
    ))?;
    let (_, choices) = expect_send(protocol::Export128KiBDeriverA::handle(
        foreign_a,
        protocol::RelayEvent::Advance,
    ))?;
    let replayed = replay_round_trip(
        choices,
        protocol::WireDirection::DeriverAToDeriverB,
        foreign_session,
    )?;
    reject_replay(
        protocol::Export128KiBDeriverB::handle(target_b, protocol::RelayEvent::Inbound(replayed)),
        "export BaseOtChoices",
    )
}

fn activation_a_replay_inputs() -> CheckResult<protocol::ActivationDeriverAInputs> {
    protocol::ActivationDeriverAInputs::new(
        [1; 32],
        [2; 32],
        scalar_from_u64(3),
        scalar_from_u64(4),
    )
    .map_err(|_| "activation replay A input construction failed".to_owned())
}

fn activation_b_replay_inputs() -> CheckResult<protocol::ActivationDeriverBInputs> {
    protocol::ActivationDeriverBInputs::new(
        [5; 32],
        [6; 32],
        scalar_from_u64(7),
        scalar_from_u64(8),
    )
    .map_err(|_| "activation replay B input construction failed".to_owned())
}

fn export_a_replay_inputs() -> CheckResult<protocol::ExportDeriverAInputs> {
    protocol::ExportDeriverAInputs::new([1; 32], [2; 32])
        .map_err(|_| "export replay A input construction failed".to_owned())
}

fn export_b_replay_inputs() -> CheckResult<protocol::ExportDeriverBInputs> {
    protocol::ExportDeriverBInputs::new([3; 32], [4; 32])
        .map_err(|_| "export replay B input construction failed".to_owned())
}

fn replay_round_trip(
    message: protocol::WireMessage,
    direction: protocol::WireDirection,
    session: [u8; 32],
) -> CheckResult<protocol::WireMessage> {
    let mut encoder = protocol::DirectionalWireEncoder::new(direction, session)
        .map_err(|_| "replay encoder construction failed".to_owned())?;
    let mut decoder = protocol::DirectionalWireDecoder::new(direction, session)
        .map_err(|_| "replay decoder construction failed".to_owned())?;
    let mut trace = RelayTrace::default();
    route_message(message, direction, &mut encoder, &mut decoder, &mut trace)
}

fn reject_replay<R, C>(
    result: Result<protocol::RelayStep<R, C>, protocol::BenchmarkRoleError>,
    label: &str,
) -> CheckResult<()> {
    if result.is_ok() {
        return Err(format!("cross-session {label} replay was accepted"));
    }
    Ok(())
}
