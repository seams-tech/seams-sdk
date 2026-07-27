import { base64UrlEncode } from '@shared/utils/base64';
import {
  parseRouterAbEcdsaRegistrationRequestFactsV1,
  type RouterAbEcdsaRegistrationRequestFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  buildRouterAbEcdsaRegistrationPendingFinalizationV1,
  encodeRouterAbEcdsaRegistrationPendingFinalizationV1,
  type RouterAbEcdsaRegistrationPendingFinalizationV1,
} from '@/core/signingEngine/routerAb/ecdsaDerivation/registrationPendingFinalization';
import type { EcdsaRoleLocalPendingStateBlob } from '@/core/platform/types';
import {
  buildFixtureRouterAbEcdsaStrictRegistrationRequest,
  fixtureRouterAbEcdsaActivationFacts,
} from '../../helpers/routerAbSigningRuntimeTestUtils';

const DIGEST32_B64U = base64UrlEncode(new Uint8Array(32).fill(31));

export type RouterAbEcdsaRegistrationPendingFinalizationFixture = {
  readonly payload: RouterAbEcdsaRegistrationPendingFinalizationV1;
  readonly encoded: string;
};

function fixtureRegistrationFacts(): RouterAbEcdsaRegistrationRequestFactsV1 {
  return parseRouterAbEcdsaRegistrationRequestFactsV1({
    registration_purpose: 'wallet_registration',
    context: {
      application_binding_digest_b64u: DIGEST32_B64U,
    },
    lifecycle: {
      lifecycle_id: 'registration-lifecycle-fixture',
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: 'root-share-epoch-fixture',
      account_id: 'wallet-fixture',
      session_id: 'registration-session-fixture',
      signer_set_id: 'signer-set-fixture',
      selected_server_id: 'signing-worker-fixture',
    },
    signer_set: {
      signer_set_id: 'signer-set-fixture',
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'deriver-a-fixture',
        key_epoch: 'deriver-epoch-fixture',
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'deriver-b-fixture',
        key_epoch: 'deriver-epoch-fixture',
      },
      selected_server: {
        server_id: 'signing-worker-fixture',
        key_epoch: 'worker-epoch-fixture',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
    },
    router_id: 'router-fixture',
    client_id: 'client-fixture',
    replay_nonce: 'registration-replay-fixture',
    expires_at_ms: 1_900_000_000_000,
    deriver_recipient_keys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'deriver-epoch-fixture',
        public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'deriver-epoch-fixture',
        public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
      },
    },
  });
}

function fixturePendingStateBlob(): EcdsaRoleLocalPendingStateBlob {
  return {
    kind: 'ecdsa_role_local_pending_state_blob_v1',
    curve: 'secp256k1',
    encoding: 'base64url',
    producer: 'signer_core',
    stateBlobB64u: base64UrlEncode(new TextEncoder().encode('worker-owned-pending-state')),
  };
}

export function routerAbEcdsaRegistrationPendingFinalizationFixture(): RouterAbEcdsaRegistrationPendingFinalizationFixture {
  const registrationFacts = fixtureRegistrationFacts();
  const payload = buildRouterAbEcdsaRegistrationPendingFinalizationV1({
    pendingStateBlob: fixturePendingStateBlob(),
    registrationFacts,
    registrationRequest: buildFixtureRouterAbEcdsaStrictRegistrationRequest(registrationFacts),
    clientActivation: fixtureRouterAbEcdsaActivationFacts(),
  });
  return {
    payload,
    encoded: encodeRouterAbEcdsaRegistrationPendingFinalizationV1(payload),
  };
}
