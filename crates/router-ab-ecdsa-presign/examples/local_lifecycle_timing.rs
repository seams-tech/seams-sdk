use std::time::Instant;

use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use router_ab_ecdsa_online::{
    compute_client_signature_share, finalize_signing_worker_signature, ClientPresignMaterial,
    OnlineClientInput, SigningWorkerOnlineInput, SigningWorkerPresignMaterial,
};
use router_ab_ecdsa_presign::{
    session::{
        derive_presign_pair_context, ClientPresignSession, PresignSessionStage,
        SigningWorkerPresignSession,
    },
    AdditiveKeyShare,
};
use router_ab_ecdsa_wire::{CompressedPointBytes, ScalarBytes};

const ITERATIONS: usize = 25;

struct PresignOutputs {
    group_public_key33: [u8; 33],
    client: [u8; 97],
    worker: [u8; 97],
    initialize_ms: f64,
    triples_ms: f64,
    presign_ms: f64,
    total_ms: f64,
}

fn scalar_bytes(value: u64) -> ScalarBytes {
    ScalarBytes::new(Scalar::from(value).to_bytes().into())
}

fn key_share(value: u64) -> AdditiveKeyShare {
    AdditiveKeyShare::from_bytes(scalar_bytes(value)).expect("nonzero key share")
}

fn group_public_key33() -> [u8; 33] {
    let point = (ProjectivePoint::GENERATOR * Scalar::from(18u64)).to_affine();
    point
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed point width")
}

fn exchange(
    client: &mut ClientPresignSession,
    worker: &mut SigningWorkerPresignSession,
    client_rng: &mut ChaCha20Rng,
    worker_rng: &mut ChaCha20Rng,
) {
    let client_messages = client.poll().outgoing;
    let worker_messages = worker.poll().outgoing;
    assert_eq!(client_messages.len(), 1);
    assert_eq!(worker_messages.len(), 1);
    client
        .message(&worker_messages[0], client_rng)
        .expect("client round");
    worker
        .message(&client_messages[0], worker_rng)
        .expect("worker round");
}

fn timed_presign(iteration: usize) -> PresignOutputs {
    let mut client_seed = [0x71; 32];
    let mut worker_seed = [0x72; 32];
    client_seed[24..].copy_from_slice(&(iteration as u64).to_be_bytes());
    worker_seed[24..].copy_from_slice(&(iteration as u64).to_be_bytes());
    let mut client_rng = ChaCha20Rng::from_seed(client_seed);
    let mut worker_rng = ChaCha20Rng::from_seed(worker_seed);
    let group_public_key33 = group_public_key33();
    let public_key = CompressedPointBytes::new(group_public_key33);
    let context = derive_presign_pair_context(public_key, &format!("timing-{iteration}"))
        .expect("pair context");

    let total_started = Instant::now();
    let initialize_started = Instant::now();
    let mut client = ClientPresignSession::new(context, key_share(7), public_key, &mut client_rng)
        .expect("client session");
    let mut worker =
        SigningWorkerPresignSession::new(context, key_share(11), public_key, &mut worker_rng)
            .expect("worker session");
    let initialize_ms = initialize_started.elapsed().as_secs_f64() * 1_000.0;

    let triples_started = Instant::now();
    for _ in 0..9 {
        exchange(&mut client, &mut worker, &mut client_rng, &mut worker_rng);
    }
    assert_eq!(client.stage(), PresignSessionStage::TriplesDone);
    assert_eq!(worker.stage(), PresignSessionStage::TriplesDone);
    let triples_ms = triples_started.elapsed().as_secs_f64() * 1_000.0;

    let presign_started = Instant::now();
    client.start_presign().expect("client presign start");
    worker.start_presign().expect("worker presign start");
    exchange(&mut client, &mut worker, &mut client_rng, &mut worker_rng);
    exchange(&mut client, &mut worker, &mut client_rng, &mut worker_rng);
    let client: [u8; 97] = client
        .take_presignature_97()
        .expect("client output")
        .try_into()
        .expect("client output width");
    let worker: [u8; 97] = worker
        .take_presignature_97()
        .expect("worker output")
        .try_into()
        .expect("worker output width");
    let presign_ms = presign_started.elapsed().as_secs_f64() * 1_000.0;
    let total_ms = total_started.elapsed().as_secs_f64() * 1_000.0;

    PresignOutputs {
        group_public_key33,
        client,
        worker,
        initialize_ms,
        triples_ms,
        presign_ms,
        total_ms,
    }
}

fn parse_presign(bytes: &[u8; 97]) -> ([u8; 33], [u8; 32], [u8; 32]) {
    (
        bytes[..33].try_into().expect("big R width"),
        bytes[33..65].try_into().expect("k width"),
        bytes[65..].try_into().expect("sigma width"),
    )
}

fn timed_online(outputs: PresignOutputs, iteration: usize) -> (f64, f64, [u8; 65]) {
    let (client_big_r, client_k, client_sigma) = parse_presign(&outputs.client);
    let (worker_big_r, worker_k, worker_sigma) = parse_presign(&outputs.worker);
    assert_eq!(client_big_r, worker_big_r);
    let digest32 = [0x42; 32];
    let mut entropy32 = [0x24; 32];
    entropy32[24..].copy_from_slice(&(iteration as u64).to_be_bytes());

    let client_started = Instant::now();
    let client_committed = ClientPresignMaterial::from_bytes(client_big_r, client_k, client_sigma)
        .expect("client material")
        .reserve()
        .commit(
            OnlineClientInput::new(
                outputs.group_public_key33,
                client_big_r,
                digest32,
                entropy32,
            )
            .expect("client input"),
        )
        .expect("client commit");
    let client_share = compute_client_signature_share(client_committed).expect("client share");
    let client_ms = client_started.elapsed().as_secs_f64() * 1_000.0;

    let worker_started = Instant::now();
    let worker_committed =
        SigningWorkerPresignMaterial::from_bytes(worker_big_r, worker_k, worker_sigma)
            .expect("worker material")
            .reserve()
            .commit(
                SigningWorkerOnlineInput::new(
                    outputs.group_public_key33,
                    worker_big_r,
                    digest32,
                    entropy32,
                )
                .expect("worker input"),
            )
            .expect("worker commit");
    let signature =
        finalize_signing_worker_signature(worker_committed, client_share).expect("signature");
    let worker_ms = worker_started.elapsed().as_secs_f64() * 1_000.0;
    (client_ms, worker_ms, signature)
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    if values.len() % 2 == 0 {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2.0
    } else {
        values[values.len() / 2]
    }
}

fn main() {
    let mut initialize = Vec::with_capacity(ITERATIONS);
    let mut triples = Vec::with_capacity(ITERATIONS);
    let mut presign = Vec::with_capacity(ITERATIONS);
    let mut total = Vec::with_capacity(ITERATIONS);
    let mut online_client = Vec::with_capacity(ITERATIONS);
    let mut online_worker = Vec::with_capacity(ITERATIONS);
    let mut last_signature = [0u8; 65];

    for iteration in 0..ITERATIONS {
        let outputs = timed_presign(iteration);
        initialize.push(outputs.initialize_ms);
        triples.push(outputs.triples_ms);
        presign.push(outputs.presign_ms);
        total.push(outputs.total_ms);
        let (client_ms, worker_ms, signature) = timed_online(outputs, iteration);
        online_client.push(client_ms);
        online_worker.push(worker_ms);
        last_signature = signature;
    }

    println!(
        "{{\n  \"schema\": \"seams.refactor89.local-ecdsa-lifecycle-timing.v1\",\n  \"profile\": \"release\",\n  \"iterations\": {ITERATIONS},\n  \"medianMs\": {{\n    \"presignSessionInitializeBothRoles\": {:.3},\n    \"presignTripleRounds\": {:.3},\n    \"presignFinalRounds\": {:.3},\n    \"presignTotal\": {:.3},\n    \"onlineClientShare\": {:.3},\n    \"onlineSigningWorkerFinalizeAndVerify\": {:.3}\n  }},\n  \"lastRecoveryId\": {}\n}}",
        median(&mut initialize),
        median(&mut triples),
        median(&mut presign),
        median(&mut total),
        median(&mut online_client),
        median(&mut online_worker),
        last_signature[64],
    );
}
