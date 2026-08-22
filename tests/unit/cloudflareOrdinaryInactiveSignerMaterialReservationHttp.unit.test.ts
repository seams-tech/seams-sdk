import { expect, test } from '@playwright/test';
import {
  createCloudflareOrdinaryInactiveSignerMaterialActivationEndpointV1,
  createCloudflareOrdinaryInactiveSignerMaterialReservationEndpointV1,
} from '../../packages/wallet-server/src/router/cloudflare/signingLanes/cloudflareOrdinaryInactiveSignerMaterialReservation';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  buildSourcePreservingEcdsaReservationRequestFixture,
  buildSourcePreservingEd25519ReservationRequestFixture,
} from './helpers/ordinarySourcePreservingReservation.fixtures';

type RecordedRequestV1 = {
  readonly url: string;
  readonly method: string;
  readonly auth: string | null;
  readonly body: unknown;
};

test('source-preserving reservation and activation endpoints emit exact worker wires', async () => {
  const calls: RecordedRequestV1[] = [];
  const ed25519 = buildSourcePreservingEd25519ReservationRequestFixture();
  const ecdsa = buildSourcePreservingEcdsaReservationRequestFixture();
  const responses: unknown[] = [
    {
      state: 'inactive',
      reservation_id: 'ed25519-http-reservation',
      participant_ids: ed25519.preparation.sourceContribution.participantIds,
      activation_receipt: {
        transcript: ed25519.preparation.sourceContribution.delivery.deriver_a.package.transcript,
        registered_public_key: ed25519.preparation.sourceContribution.delivery.deriver_a.package.transcript,
        joined_client_commitment:
          ed25519.preparation.sourceContribution.delivery.deriver_a.client_commitment,
        joined_signing_worker_commitment:
          ed25519.preparation.sourceContribution.delivery.deriver_a.signing_worker_commitment,
        signing_worker_verifying_share:
          ed25519.preparation.sourceContribution.delivery.deriver_a.package.transcript,
        state_epoch: 1,
        material_activation:
          ed25519.preparation.sourceContribution.delivery.deriver_a.binding.material_activation,
      },
      deriver_a_client_package: ed25519.preparation.sourceContribution.deriver_a_client_package,
      deriver_b_client_package: ed25519.preparation.sourceContribution.deriver_b_client_package,
    },
    { ok: true },
    {
      state: 'inactive',
      reservation_id: 'ecdsa-http-reservation',
      material_activation: routerAbMpcMaterialActivationRefToWire(
        ecdsa.preparation.sourceContribution.binding.target.activation,
      ),
      binding: ecdsa.preparation.sourceContribution.binding,
      source_derivation: {
        application_binding_digest_b64u:
          ecdsa.preparation.sourceDerivation.applicationBindingDigestB64u,
        client_share_retry_counter: ecdsa.preparation.sourceDerivation.clientShareRetryCounter,
      },
      target_relayer_public_key33_b64u:
        ecdsa.preparation.sourceContribution.binding.source.relayerPublicKey33B64u,
      threshold_public_key33_b64u: ecdsa.signer.thresholdPublicKey33B64u,
      threshold_ethereum_address20_b64u:
        ecdsa.preparation.sourceContribution.binding.source.thresholdEthereumAddress20B64u,
      encrypted_target_client_share:
        ecdsa.preparation.sourceContribution.encryptedTargetClientShare,
      encrypted_target_server_share:
        ecdsa.preparation.sourceContribution.encryptedDelta,
    },
    { ok: true },
  ];
  const responseFetch = createRecordingFetch(calls, responses);
  const responseReservationEndpoint = createCloudflareOrdinaryInactiveSignerMaterialReservationEndpointV1({
    fetch: responseFetch,
    internalServiceAuthSecret: 'internal-secret',
  });
  const responseActivationEndpoint = createCloudflareOrdinaryInactiveSignerMaterialActivationEndpointV1({
    fetch: responseFetch,
    internalServiceAuthSecret: 'internal-secret',
  });

  await responseReservationEndpoint.reserveInactiveEd25519SignerMaterialV1(ed25519);
  await responseActivationEndpoint.activateInactiveEd25519SignerMaterialV1({
    sourceContribution: ed25519.preparation.sourceContribution,
    reservationId: 'ed25519-reservation',
  });
  await responseReservationEndpoint.reserveInactiveEcdsaSignerMaterialV1(ecdsa);
  await responseActivationEndpoint.activateInactiveEcdsaSignerMaterialV1({
    preparation: ecdsa.preparation,
    reservationId: 'ecdsa-reservation',
  });

  expect(calls).toHaveLength(4);
  expect(calls.map((call) => call.url)).toEqual([
    'https://signing-worker.router-ab.internal/router-ab/signing-worker/ed25519-yao/reserve-inactive-source-preserving',
    'https://signing-worker.router-ab.internal/router-ab/signing-worker/ed25519-yao/activate-reservation',
    'https://signing-worker.router-ab.internal/router-ab/signing-worker/ecdsa-derivation/reserve-inactive-source-preserving',
    'https://signing-worker.router-ab.internal/router-ab/signing-worker/ecdsa-derivation/activate-reservation',
  ]);
  for (const call of calls) {
    expect(call.method).toBe('POST');
    expect(call.auth).toBe('internal-secret');
  }

  expect(calls[0]?.body).toEqual({
    source_binding: ed25519.preparation.sourceContribution.sourceBinding,
    delivery: ed25519.preparation.sourceContribution.delivery,
    participant_ids: ed25519.preparation.sourceContribution.participantIds,
    deriver_a_client_package: ed25519.preparation.sourceContribution.deriver_a_client_package,
    deriver_b_client_package: ed25519.preparation.sourceContribution.deriver_b_client_package,
  });
  expect(calls[1]?.body).toEqual({
    binding: ed25519.preparation.sourceContribution.delivery.deriver_a.binding,
    reservation_id: 'ed25519-reservation',
  });
  expect(calls[2]?.body).toEqual({
    source_derivation: {
      application_binding_digest_b64u: ecdsa.preparation.sourceDerivation.applicationBindingDigestB64u,
      client_share_retry_counter: ecdsa.preparation.sourceDerivation.clientShareRetryCounter,
    },
    source_contribution: ecdsa.preparation.sourceContribution,
  });
  expect(calls[3]?.body).toEqual({
    material_activation: routerAbMpcMaterialActivationRefToWire(
      ecdsa.preparation.sourceContribution.binding.target.activation,
    ),
    reservation_id: 'ecdsa-reservation',
  });
});

function createRecordingFetch(calls: RecordedRequestV1[], responses: readonly unknown[] = [{ ok: true }]): typeof fetch {
  let responseIndex = 0;
  return async (input, init) => {
    const request = new Request(input, init);
    calls.push({
      url: request.url,
      method: request.method,
      auth: request.headers.get('x-router-ab-internal-service-auth'),
      body: JSON.parse(await request.text()),
    });
    const responseBody = responses[responseIndex] ?? { ok: true };
    responseIndex += 1;
    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
}
