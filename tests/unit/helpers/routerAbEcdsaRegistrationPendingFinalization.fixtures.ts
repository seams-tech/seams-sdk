import {
  parseRouterAbEcdsaVerifiedClientActivationFactsV1,
  parseRouterAbEcdsaRegistrationRequestFactsV1,
  type RouterAbEcdsaRegistrationRequestFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  buildWalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1,
  encodeRouterAbEcdsaRegistrationPendingFinalizationV1,
  type RouterAbEcdsaRegistrationPendingFinalizationV1,
} from '@/core/signingEngine/routerAb/ecdsaDerivation/registrationPendingFinalization';
import { buildFixtureRouterAbEcdsaStrictRegistrationRequest } from '../../helpers/routerAbSigningRuntimeTestUtils';

const APPLICATION_BINDING_DIGEST_B64U = 'VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU';
const CONTEXT_BINDING_B64U = 'ga29uobW2Hvkz8FnDn3rLhxE_AIFuZDDdtIDnelsibc';
const CLIENT_PUBLIC_KEY_B64U = 'Atwt5jXVelj7TRZgVnmNBX0EQ2GY6bQrhRtfKfqOiuZq';
const PROOF_TRANSCRIPT_DIGEST_B64U = 'CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg';
const REGISTRATION_REQUEST_DIGEST_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

export type RouterAbEcdsaRegistrationPendingFinalizationFixture = {
  readonly payload: RouterAbEcdsaRegistrationPendingFinalizationV1;
  readonly encoded: string;
};

function fixtureRegistrationFacts(): RouterAbEcdsaRegistrationRequestFactsV1 {
  return parseRouterAbEcdsaRegistrationRequestFactsV1({
    registration_purpose: 'wallet_registration',
    context: {
      application_binding_digest_b64u: APPLICATION_BINDING_DIGEST_B64U,
    },
    lifecycle: {
      lifecycle_id: 'ecdsa-lifecycle-fixture',
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: 'activation-epoch-fixture',
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
        key_epoch: 'key-epoch-fixture',
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

export function routerAbEcdsaRegistrationPendingFinalizationFixture(): RouterAbEcdsaRegistrationPendingFinalizationFixture {
  const registrationFacts = fixtureRegistrationFacts();
  const payload = buildWalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1({
    runtimePolicyScope: {
      orgId: 'fixture-org',
      projectId: 'fixture',
      envId: 'dev',
      signingRootVersion: 'v1',
    },
    registrationFacts,
    registrationRequest: buildFixtureRouterAbEcdsaStrictRegistrationRequest(registrationFacts),
    clientActivation: parseRouterAbEcdsaVerifiedClientActivationFactsV1({
      registrationRequestDigestB64u: REGISTRATION_REQUEST_DIGEST_B64U,
      proofTranscriptDigestB64u: PROOF_TRANSCRIPT_DIGEST_B64U,
      contextBinding32B64u: CONTEXT_BINDING_B64U,
      derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
      clientShareRetryCounter: 0,
      participantId: 1,
    }),
  });
  return {
    payload,
    encoded: encodeRouterAbEcdsaRegistrationPendingFinalizationV1(payload),
  };
}
