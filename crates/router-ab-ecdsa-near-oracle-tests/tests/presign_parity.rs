use k256::{
    elliptic_curve::{ff::PrimeField, sec1::ToEncodedPoint},
    AffinePoint, ProjectivePoint, Scalar,
};
use router_ab_ecdsa_presign::{
    start_client, start_signing_worker, AdditiveKeyShare, ClientPresignInput, PresignOutput,
    SigningWorkerPresignInput, TriplePublic, ValidatedTriple,
};
use router_ab_ecdsa_wire::{
    ClientAlphaBetaMessage, ClientEShareMessage, CompressedPointBytes, PairContextDigest,
    PresignPairContext, ScalarBytes, SigningScopeDigest, SigningWorkerAlphaBetaMessage,
    SigningWorkerEShareMessage,
};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use threshold_signatures::{
    ecdsa::{
        ot_based_ecdsa::{
            presign::presign,
            triples::{TriplePub as NearTriplePublic, TripleShare as NearTripleShare},
            PresignArguments, PresignOutput as NearPresignOutput,
        },
        KeygenOutput,
    },
    frost_secp256k1::{keys::SigningShare, VerifyingKey},
    participants::Participant,
    protocol::{Action, Protocol},
};

const CLIENT_PARTICIPANT_ID: u32 = 1;
const SIGNING_WORKER_PARTICIPANT_ID: u32 = 2;
const CLIENT_COORDINATE: u64 = 2;
const SIGNING_WORKER_COORDINATE: u64 = 3;
const CLIENT_LAGRANGE: u64 = 3;
const SIGNING_WORKER_LAGRANGE_MAGNITUDE: u64 = 2;
const NEAR_MESSAGE_HEADER_LENGTH: usize = 40;
const EXPECTED_BIG_R: [u8; 33] = [
    3, 97, 26, 55, 117, 255, 79, 62, 90, 207, 12, 55, 27, 90, 190, 23, 216, 213, 123, 57, 135, 16,
    189, 139, 16, 37, 151, 245, 115, 43, 105, 212, 133,
];
const EXPECTED_CLIENT_K: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17,
];
const EXPECTED_CLIENT_SIGMA: [u8; 32] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220,
    230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 59, 76,
];
const EXPECTED_SIGNING_WORKER_K: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22,
];
const EXPECTED_SIGNING_WORKER_SIGMA: [u8; 32] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220,
    230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 56, 15,
];

struct Fixture {
    context: PresignPairContext,
    wallet_secret: Scalar,
    wallet_slope: Scalar,
    triple0_secrets: [Scalar; 3],
    triple0_slopes: [Scalar; 3],
    triple1_secrets: [Scalar; 3],
    triple1_slopes: [Scalar; 3],
}

#[derive(Default)]
struct NearRoleSemanticTrace {
    e: Option<Scalar>,
    alpha_beta: Option<(Scalar, Scalar)>,
}

#[derive(Default)]
struct NearSemanticTrace {
    client: NearRoleSemanticTrace,
    signing_worker: NearRoleSemanticTrace,
}

impl Fixture {
    fn new() -> Self {
        let k = Scalar::from(7u64);
        let d = Scalar::from(11u64);
        let a = Scalar::from(13u64);
        let b = Scalar::from(17u64);

        Self {
            context: PresignPairContext::new(
                SigningScopeDigest::new([0x24; 32]),
                PairContextDigest::new([0x42; 32]),
            ),
            wallet_secret: Scalar::from(19u64),
            wallet_slope: Scalar::from(23u64),
            triple0_secrets: [k, d, k * d],
            triple0_slopes: [Scalar::from(5u64), Scalar::from(29u64), Scalar::from(31u64)],
            triple1_secrets: [a, b, a * b],
            triple1_slopes: [
                Scalar::from(37u64),
                Scalar::from(41u64),
                Scalar::from(43u64),
            ],
        }
    }

    fn new_client_input(&self) -> ClientPresignInput {
        let coordinate = Scalar::from(CLIENT_COORDINATE);
        let key_evaluation = evaluate(self.wallet_secret, self.wallet_slope, coordinate);
        let additive_share = Scalar::from(CLIENT_LAGRANGE) * key_evaluation;

        ClientPresignInput::new(
            new_key_share(additive_share),
            generator_multiple(self.wallet_secret),
            new_validated_triple(
                self.context,
                self.triple0_secrets,
                self.triple0_slopes,
                coordinate,
            ),
            new_validated_triple(
                self.context,
                self.triple1_secrets,
                self.triple1_slopes,
                coordinate,
            ),
        )
        .expect("valid new client input")
    }

    fn new_signing_worker_input(&self) -> SigningWorkerPresignInput {
        let coordinate = Scalar::from(SIGNING_WORKER_COORDINATE);
        let key_evaluation = evaluate(self.wallet_secret, self.wallet_slope, coordinate);
        let additive_share = -Scalar::from(SIGNING_WORKER_LAGRANGE_MAGNITUDE) * key_evaluation;

        SigningWorkerPresignInput::new(
            new_key_share(additive_share),
            generator_multiple(self.wallet_secret),
            new_validated_triple(
                self.context,
                self.triple0_secrets,
                self.triple0_slopes,
                coordinate,
            ),
            new_validated_triple(
                self.context,
                self.triple1_secrets,
                self.triple1_slopes,
                coordinate,
            ),
        )
        .expect("valid new signing worker input")
    }

    fn near_protocol(
        &self,
        participant: Participant,
        coordinate: Scalar,
    ) -> Box<dyn Protocol<Output = NearPresignOutput>> {
        let participants = near_participants();
        let key_evaluation = evaluate(self.wallet_secret, self.wallet_slope, coordinate);
        let args = PresignArguments {
            triple0: (
                near_triple_share(self.triple0_secrets, self.triple0_slopes, coordinate),
                near_triple_public(&participants, self.triple0_secrets),
            ),
            triple1: (
                near_triple_share(self.triple1_secrets, self.triple1_slopes, coordinate),
                near_triple_public(&participants, self.triple1_secrets),
            ),
            keygen_out: KeygenOutput {
                private_share: SigningShare::new(key_evaluation),
                public_key: VerifyingKey::new(ProjectivePoint::GENERATOR * self.wallet_secret),
            },
            threshold: 2,
        };

        Box::new(presign(&participants, participant, args).expect("valid NEAR presign input"))
    }
}

fn evaluate(secret: Scalar, slope: Scalar, coordinate: Scalar) -> Scalar {
    secret + slope * coordinate
}

fn scalar_bytes(scalar: Scalar) -> ScalarBytes {
    ScalarBytes::new(scalar.to_bytes().into())
}

fn generator_multiple(scalar: Scalar) -> CompressedPointBytes {
    point_bytes((ProjectivePoint::GENERATOR * scalar).to_affine())
}

fn point_bytes(point: AffinePoint) -> CompressedPointBytes {
    let encoded = point.to_encoded_point(true);
    let bytes: [u8; 33] = encoded
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 points have fixed width");
    CompressedPointBytes::new(bytes)
}

fn new_key_share(scalar: Scalar) -> AdditiveKeyShare {
    AdditiveKeyShare::from_bytes(scalar_bytes(scalar)).expect("valid additive key share")
}

fn new_validated_triple(
    context: PresignPairContext,
    secrets: [Scalar; 3],
    slopes: [Scalar; 3],
    coordinate: Scalar,
) -> ValidatedTriple {
    ValidatedTriple::from_test_parts(
        scalar_bytes(evaluate(secrets[0], slopes[0], coordinate)),
        scalar_bytes(evaluate(secrets[1], slopes[1], coordinate)),
        scalar_bytes(evaluate(secrets[2], slopes[2], coordinate)),
        new_triple_public(context, secrets),
    )
    .expect("valid test triple")
}

fn new_triple_public(context: PresignPairContext, secrets: [Scalar; 3]) -> TriplePublic {
    TriplePublic::from_bytes(
        context,
        generator_multiple(secrets[0]),
        generator_multiple(secrets[1]),
        generator_multiple(secrets[2]),
    )
    .expect("valid new triple public values")
}

fn near_triple_share(
    secrets: [Scalar; 3],
    slopes: [Scalar; 3],
    coordinate: Scalar,
) -> NearTripleShare {
    NearTripleShare {
        a: evaluate(secrets[0], slopes[0], coordinate),
        b: evaluate(secrets[1], slopes[1], coordinate),
        c: evaluate(secrets[2], slopes[2], coordinate),
    }
}

fn near_triple_public(participants: &[Participant], secrets: [Scalar; 3]) -> NearTriplePublic {
    NearTriplePublic {
        big_a: (ProjectivePoint::GENERATOR * secrets[0]).to_affine(),
        big_b: (ProjectivePoint::GENERATOR * secrets[1]).to_affine(),
        big_c: (ProjectivePoint::GENERATOR * secrets[2]).to_affine(),
        participants: participants.to_vec(),
        threshold: 2,
    }
}

fn near_participants() -> Vec<Participant> {
    vec![
        Participant::from(CLIENT_PARTICIPANT_ID),
        Participant::from(SIGNING_WORKER_PARTICIPANT_ID),
    ]
}

fn step_protocol(
    sender: Participant,
    protocol: &mut Option<Box<dyn Protocol<Output = NearPresignOutput>>>,
    peer: &mut Option<Box<dyn Protocol<Output = NearPresignOutput>>>,
    output: &mut Option<NearPresignOutput>,
    trace: &mut NearSemanticTrace,
) -> Result<bool, String> {
    let Some(active_protocol) = protocol.as_mut() else {
        return Ok(false);
    };
    let action = active_protocol
        .poke()
        .map_err(|error| format!("{error:?}"))?;

    match action {
        Action::Wait => Ok(false),
        Action::SendMany(message) => {
            record_near_semantic_message(sender, &message, trace)?;
            let peer = peer
                .as_mut()
                .ok_or_else(|| "NEAR peer completed before receiving a message".to_string())?;
            peer.message(sender, message);
            Ok(true)
        }
        Action::SendPrivate(_, _) => Err("NEAR presign unexpectedly sent a private message".into()),
        Action::Return(value) => {
            *output = Some(value);
            *protocol = None;
            Ok(true)
        }
    }
}

fn decode_near_payload<T: DeserializeOwned>(message: &[u8]) -> Result<T, String> {
    let payload = message
        .get(NEAR_MESSAGE_HEADER_LENGTH..)
        .ok_or_else(|| "NEAR message omitted its 40-byte channel header".to_string())?;
    rmp_serde::from_slice(payload)
        .map_err(|error| format!("invalid NEAR semantic payload: {error}"))
}

fn record_near_role_message(
    message: &[u8],
    trace: &mut NearRoleSemanticTrace,
) -> Result<(), String> {
    if trace.e.is_none() {
        trace.e = Some(decode_near_payload(message)?);
        return Ok(());
    }
    if trace.alpha_beta.is_none() {
        trace.alpha_beta = Some(decode_near_payload(message)?);
        return Ok(());
    }
    Err("NEAR presign emitted more than two shared messages for one role".to_string())
}

fn record_near_semantic_message(
    sender: Participant,
    message: &[u8],
    trace: &mut NearSemanticTrace,
) -> Result<(), String> {
    match u32::from(sender) {
        CLIENT_PARTICIPANT_ID => record_near_role_message(message, &mut trace.client),
        SIGNING_WORKER_PARTICIPANT_ID => {
            record_near_role_message(message, &mut trace.signing_worker)
        }
        _ => Err("NEAR presign emitted a message from an unknown role".to_string()),
    }
}

fn drive_near_pair(
    client: Box<dyn Protocol<Output = NearPresignOutput>>,
    signing_worker: Box<dyn Protocol<Output = NearPresignOutput>>,
) -> Result<(NearPresignOutput, NearPresignOutput, NearSemanticTrace), String> {
    let participants = near_participants();
    let mut client_protocol = Some(client);
    let mut worker_protocol = Some(signing_worker);
    let mut client_output = None;
    let mut worker_output = None;
    let mut trace = NearSemanticTrace::default();

    for _ in 0..64 {
        let client_progress = step_protocol(
            participants[0],
            &mut client_protocol,
            &mut worker_protocol,
            &mut client_output,
            &mut trace,
        )?;
        let worker_progress = step_protocol(
            participants[1],
            &mut worker_protocol,
            &mut client_protocol,
            &mut worker_output,
            &mut trace,
        )?;

        if client_output.is_some() && worker_output.is_some() {
            return Ok((
                client_output.take().expect("checked client output"),
                worker_output.take().expect("checked worker output"),
                trace,
            ));
        }
        if !client_progress && !worker_progress {
            return Err("NEAR presign reached a deadlock".into());
        }
    }

    Err("NEAR presign exceeded the fixed step bound".into())
}

fn run_new_pair(fixture: &Fixture) -> (PresignOutput, PresignOutput) {
    let (client_e_state, client_e) =
        start_client(fixture.new_client_input()).expect("client start");
    let (worker_e_state, worker_e) =
        start_signing_worker(fixture.new_signing_worker_input()).expect("worker start");
    let (client_alpha_state, client_alpha) =
        client_e_state.receive(worker_e).expect("client round two");
    let (worker_alpha_state, worker_alpha) =
        worker_e_state.receive(client_e).expect("worker round two");

    (
        client_alpha_state
            .receive(worker_alpha)
            .expect("client output"),
        worker_alpha_state
            .receive(client_alpha)
            .expect("worker output"),
    )
}

fn near_scalar_bytes(scalar: Scalar) -> [u8; 32] {
    scalar.to_repr().into()
}

fn near_point_bytes(point: AffinePoint) -> [u8; 33] {
    point
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 points have fixed width")
}

fn assert_role_parity(new: PresignOutput, near: &NearPresignOutput) {
    let (big_r, k, sigma) = new.into_parts();
    assert_eq!(big_r.as_bytes(), &near_point_bytes(near.big_r));
    assert_eq!(k.into_bytes(), near_scalar_bytes(near.k));
    assert_eq!(sigma.into_bytes(), near_scalar_bytes(near.sigma));
}

fn run_near_pair(fixture: &Fixture) -> (NearPresignOutput, NearPresignOutput, NearSemanticTrace) {
    let participants = near_participants();
    let near_client = fixture.near_protocol(participants[0], Scalar::from(CLIENT_COORDINATE));
    let near_worker =
        fixture.near_protocol(participants[1], Scalar::from(SIGNING_WORKER_COORDINATE));
    drive_near_pair(near_client, near_worker).expect("NEAR oracle completes")
}

fn required_trace_e(trace: &NearRoleSemanticTrace) -> Scalar {
    trace.e.expect("NEAR role emitted e")
}

fn required_trace_alpha_beta(trace: &NearRoleSemanticTrace) -> (Scalar, Scalar) {
    trace.alpha_beta.expect("NEAR role emitted alpha and beta")
}

fn semantic_trace_digest(trace: &NearSemanticTrace) -> [u8; 32] {
    let mut digest = Sha256::new();
    for (role, role_trace) in [(1u8, &trace.client), (2u8, &trace.signing_worker)] {
        let (alpha, beta) = required_trace_alpha_beta(role_trace);
        digest.update([role]);
        digest.update(required_trace_e(role_trace).to_bytes());
        digest.update(alpha.to_bytes());
        digest.update(beta.to_bytes());
    }
    digest.finalize().into()
}

#[test]
fn purpose_built_presign_matches_pinned_near_oracle_exactly() {
    let fixture = Fixture::new();
    let (new_client, new_worker) = run_new_pair(&fixture);
    let (near_client, near_worker, trace) = run_near_pair(&fixture);

    assert_eq!(
        hex::encode(semantic_trace_digest(&trace)),
        "2d6d2691b277b65ebd66fe81d66d0c875412747265d18c7131963f1b8ab72d06"
    );

    assert_eq!(near_point_bytes(near_client.big_r), EXPECTED_BIG_R);
    assert_eq!(near_scalar_bytes(near_client.k), EXPECTED_CLIENT_K);
    assert_eq!(near_scalar_bytes(near_client.sigma), EXPECTED_CLIENT_SIGMA);
    assert_eq!(near_point_bytes(near_worker.big_r), EXPECTED_BIG_R);
    assert_eq!(near_scalar_bytes(near_worker.k), EXPECTED_SIGNING_WORKER_K);
    assert_eq!(
        near_scalar_bytes(near_worker.sigma),
        EXPECTED_SIGNING_WORKER_SIGMA
    );

    assert_role_parity(new_client, &near_client);
    assert_role_parity(new_worker, &near_worker);
}

#[test]
fn purpose_built_client_replays_pinned_near_signing_worker_semantics() {
    let fixture = Fixture::new();
    let (near_client, _, trace) = run_near_pair(&fixture);
    let (state, _) = start_client(fixture.new_client_input()).expect("client start");
    let worker_e = SigningWorkerEShareMessage::new(
        fixture.context,
        scalar_bytes(required_trace_e(&trace.signing_worker)),
    );
    let (state, _) = state.receive(worker_e).expect("client receives NEAR e");
    let (alpha, beta) = required_trace_alpha_beta(&trace.signing_worker);
    let worker_alpha_beta = SigningWorkerAlphaBetaMessage::new(
        fixture.context,
        scalar_bytes(alpha),
        scalar_bytes(beta),
    );
    let output = state
        .receive(worker_alpha_beta)
        .expect("client receives NEAR alpha and beta");

    assert_role_parity(output, &near_client);
}

#[test]
fn purpose_built_signing_worker_replays_pinned_near_client_semantics() {
    let fixture = Fixture::new();
    let (_, near_worker, trace) = run_near_pair(&fixture);
    let (state, _) =
        start_signing_worker(fixture.new_signing_worker_input()).expect("worker start");
    let client_e = ClientEShareMessage::new(
        fixture.context,
        scalar_bytes(required_trace_e(&trace.client)),
    );
    let (state, _) = state.receive(client_e).expect("worker receives NEAR e");
    let (alpha, beta) = required_trace_alpha_beta(&trace.client);
    let client_alpha_beta =
        ClientAlphaBetaMessage::new(fixture.context, scalar_bytes(alpha), scalar_bytes(beta));
    let output = state
        .receive(client_alpha_beta)
        .expect("worker receives NEAR alpha and beta");

    assert_role_parity(output, &near_worker);
}
