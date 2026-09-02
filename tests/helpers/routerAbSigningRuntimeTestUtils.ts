import { base64UrlDecode } from '@shared/utils/encoders';
import { normalizeLogger, type Logger } from '@server/core/logger';
import {
  createEcdsaWalletSessionStore,
  createEd25519WalletSessionStore,
  type Ed25519WalletSessionStore,
} from '@server/core/ThresholdService/stores/WalletSessionStore';
import type { RouterAbSigningRuntimeBundle } from '@server/core/routerAbSigning/createRouterAbSigningRuntimes';
import {
  parseRouterAbEcdsaPresignRuntimeConfig,
  RouterAbEcdsaPresignRuntime,
} from '@server/core/routerAbSigning/RouterAbEcdsaPresignRuntime';
import {
  parseRouterAbNormalSigningRuntimeConfig,
  requireRouterAbConfiguredSigningWorkerPrivateTransport,
  RouterAbNormalSigningRuntime,
} from '@server/core/routerAbSigning/RouterAbNormalSigningRuntime';
import {
  parseStoredRouterAbEcdsaPendingActivationV1,
  type RouterAbEcdsaStrictRegistrationPort,
  type RouterAbEcdsaStrictRegistrationTopology,
} from '@server/router/domains/ecdsa/routerAbEcdsaStrictRegistration';
import type { ThresholdStoreConfigInput } from '@server/core/types';
import type { TenantRootCustodyLineageResolverV1 } from '@server/router/domains/tenantRoot/tenantRootCustodyLineage';
import {
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  parseRouterAbEcdsaRegistrationRequestV1,
  parseRouterAbEcdsaStrictForwardedRegistrationResponseV1,
  parseRouterAbEcdsaVerifiedClientActivationFactsV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaRegistrationRequestFactsV1,
  type RouterAbEcdsaRegistrationRequestV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  parseRouterAbMpcMaterialActivationRef,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';

const FIXTURE_ECDSA_STRICT_REGISTRATION_TOPOLOGY: RouterAbEcdsaStrictRegistrationTopology = {
  routerId: 'router-unit-fixture',
  signerSet: {
    signer_set_id: 'signer-set-unit-fixture',
    policy: 'all_2',
    signer_a: {
      role: 'signer_a',
      signer_id: 'deriver-a-unit-fixture',
      key_epoch: 'epoch-unit-fixture',
    },
    signer_b: {
      role: 'signer_b',
      signer_id: 'deriver-b-unit-fixture',
      key_epoch: 'epoch-unit-fixture',
    },
    selected_server: {
      server_id: 'signing-worker-unit-fixture',
      key_epoch: 'epoch-unit-fixture',
      recipient_encryption_key:
        'x25519:1111111111111111111111111111111111111111111111111111111111111111',
    },
  },
  deriverRecipientKeys: {
    deriver_a: {
      role: 'signer_a',
      key_epoch: 'epoch-unit-fixture',
      public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
    },
    deriver_b: {
      role: 'signer_b',
      key_epoch: 'epoch-unit-fixture',
      public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
    },
  },
};

const FIXTURE_ECDSA_DIGEST32_B64U = Buffer.alloc(32).toString('base64url');
const FIXTURE_ECDSA_CLIENT_PUBLIC_KEY33_B64U = Buffer.from([
  2,
  ...new Array<number>(32).fill(0),
]).toString('base64url');
const FIXTURE_ECDSA_SERVER_PUBLIC_KEY33_B64U = Buffer.from([
  3,
  ...new Array<number>(32).fill(0),
]).toString('base64url');
const FIXTURE_ECDSA_ADDRESS20_B64U = Buffer.alloc(20, 1).toString('base64url');

export const FIXTURE_TENANT_ROOT_CUSTODY_LINEAGE: TenantRootCustodyLineageResolverV1 = {
  async resolveActiveLineage() {
    return {
      identityDigestB64u: FIXTURE_ECDSA_DIGEST32_B64U,
      custodyLineageB64u: Buffer.alloc(16).toString('base64url'),
    };
  },
};

export function fixtureRouterAbEcdsaActivationFacts(): RouterAbEcdsaVerifiedClientActivationFactsV1 {
  return parseRouterAbEcdsaVerifiedClientActivationFactsV1({
    registrationRequestDigestB64u: FIXTURE_ECDSA_DIGEST32_B64U,
    proofTranscriptDigestB64u: FIXTURE_ECDSA_DIGEST32_B64U,
    contextBinding32B64u: FIXTURE_ECDSA_DIGEST32_B64U,
    derivationClientSharePublicKey33B64u: FIXTURE_ECDSA_CLIENT_PUBLIC_KEY33_B64U,
    clientShareRetryCounter: 0,
    participantId: 1,
  });
}

export function fixtureRouterAbEcdsaMaterialActivation(
  lifecycleBinding: string,
): RouterAbMpcMaterialActivationRefWire {
  return parseRouterAbMpcMaterialActivationRef({
    kind: 'mpc_material_activation_ref',
    activation_id: `ecdsa-activation:${lifecycleBinding}`,
    capability: `ecdsa-capability:${lifecycleBinding}`,
    material_owner: lifecycleBinding,
    key_binding: 'ecdsa-key-binding-unit-fixture',
    lifecycle_binding: lifecycleBinding,
    signing_worker: FIXTURE_ECDSA_STRICT_REGISTRATION_TOPOLOGY.signerSet.selected_server.server_id,
  });
}

export function buildFixtureRouterAbEcdsaStrictRegistrationRequest(
  facts: RouterAbEcdsaRegistrationRequestFactsV1,
): RouterAbEcdsaRegistrationRequestV1 {
  const digest = { bytes: new Array<number>(32).fill(0) };
  return parseRouterAbEcdsaRegistrationRequestV1({
    registration_purpose: facts.registration_purpose,
    context: facts.context,
    lifecycle: facts.lifecycle,
    signer_set: facts.signer_set,
    router_id: facts.router_id,
    client_id: facts.client_id,
    replay_nonce: facts.replay_nonce,
    expires_at_ms: facts.expires_at_ms,
    client_ephemeral_public_key:
      'x25519:4444444444444444444444444444444444444444444444444444444444444444',
    deriver_a_envelope: {
      recipient_role: 'signer_a',
      header_digest: digest,
      aad_digest: digest,
      ciphertext: { bytes: [1] },
    },
    deriver_b_envelope: {
      recipient_role: 'signer_b',
      header_digest: digest,
      aad_digest: digest,
      ciphertext: { bytes: [2] },
    },
  });
}

export class FixtureRouterAbEcdsaStrictRegistrationPort implements RouterAbEcdsaStrictRegistrationPort {
  topology(): RouterAbEcdsaStrictRegistrationTopology {
    return FIXTURE_ECDSA_STRICT_REGISTRATION_TOPOLOGY;
  }

  async register(): Promise<never> {
    throw new Error('Strict ECDSA registration is outside this fixture');
  }

  async registerInitialWithTenantRoot(
    _input: Parameters<RouterAbEcdsaStrictRegistrationPort['registerInitialWithTenantRoot']>[0],
  ): ReturnType<RouterAbEcdsaStrictRegistrationPort['registerInitialWithTenantRoot']> {
    return this.register();
  }

  async activate(): Promise<never> {
    throw new Error('Strict ECDSA activation is outside this fixture');
  }
}

export class SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort implements RouterAbEcdsaStrictRegistrationPort {
  registrationRequest: RouterAbEcdsaRegistrationRequestV1 | null = null;
  activatedReceipt: RouterAbEcdsaRegistrationActivationReceiptV1 | null = null;
  /**
   * Models a caller that dies once the Router has already committed custody:
   * the receipt is retained, so the next activate replays it, but this call
   * never returns one. Cleared after it fires.
   */
  failAfterNextActivationCommit = false;

  topology(): RouterAbEcdsaStrictRegistrationTopology {
    return FIXTURE_ECDSA_STRICT_REGISTRATION_TOPOLOGY;
  }

  async register(
    input: Parameters<RouterAbEcdsaStrictRegistrationPort['register']>[0],
  ): ReturnType<RouterAbEcdsaStrictRegistrationPort['register']> {
    const request = parseRouterAbEcdsaRegistrationRequestV1(input.request);
    this.registrationRequest = request;
    const bundle = {
      kind: 'recipient_proof_bundle',
      transcriptDigestB64u: FIXTURE_ECDSA_DIGEST32_B64U,
      payloadB64u: 'AQ',
    } as const;
    return {
      ok: true,
      value: {
        publicResponse: parseRouterAbEcdsaStrictForwardedRegistrationResponseV1({
          result: 'forwarded',
          response: {
            bundles: { signerA: bundle, signerB: bundle },
          },
        }),
        pendingActivation: parseStoredRouterAbEcdsaPendingActivationV1({
          kind: 'router_ab_ecdsa_pending_activation_v1',
          canonicalPayloadJson: '{"activation":{},"activation_context":{},"registration":{}}',
        }),
      },
    };
  }

  async registerInitialWithTenantRoot(
    input: Parameters<RouterAbEcdsaStrictRegistrationPort['registerInitialWithTenantRoot']>[0],
  ): ReturnType<RouterAbEcdsaStrictRegistrationPort['registerInitialWithTenantRoot']> {
    return this.register(input);
  }

  async activate(
    input: Parameters<RouterAbEcdsaStrictRegistrationPort['activate']>[0],
  ): ReturnType<RouterAbEcdsaStrictRegistrationPort['activate']> {
    const registration = this.registrationRequest;
    if (!registration) throw new Error('Strict ECDSA activation preceded registration');
    const publicFacts = parseRouterAbEcdsaVerifiedClientActivationFactsV1(input.clientActivation);
    const expectedDigest = fixtureActivationRequestDigest(input.requestPolicy.requestDigestB64u);
    if (this.activatedReceipt) {
      if (this.activatedReceipt.activation_correlation_id !== input.activationCorrelationId) {
        return {
          ok: false,
          code: 'fixture_activation_correlation_conflict',
          message: 'Fixture activation correlation conflict',
          retryable: false,
        };
      }
      if (
        this.activatedReceipt.activation_request_digest.bytes.some(
          (value, index) => value !== expectedDigest.bytes[index],
        )
      ) {
        return {
          ok: false,
          code: 'fixture_activation_digest_mismatch',
          message: 'Fixture activation digest mismatch',
          retryable: false,
        };
      }
      return { ok: true, value: this.activatedReceipt };
    }
    const receipt = parseRouterAbEcdsaRegistrationActivationReceiptV1({
      activation_correlation_id: input.activationCorrelationId,
      activation_request_digest: expectedDigest,
      server_generation: `ecdsa-server-generation-v1:${FIXTURE_ECDSA_DIGEST32_B64U}`,
      ecdsa_activation: {
        context: registration.context,
        public_identity: {
          context_binding_b64u: publicFacts.contextBinding32B64u,
          derivation_client_share_public_key33_b64u:
            publicFacts.derivationClientSharePublicKey33B64u,
          server_public_key33_b64u: FIXTURE_ECDSA_SERVER_PUBLIC_KEY33_B64U,
          threshold_public_key33_b64u: FIXTURE_ECDSA_CLIENT_PUBLIC_KEY33_B64U,
          ethereum_address20_b64u: FIXTURE_ECDSA_ADDRESS20_B64U,
          client_share_retry_counter: publicFacts.clientShareRetryCounter,
          server_share_retry_counter: 0,
        },
        signing_worker: registration.signer_set.selected_server,
        material_activation: parseRouterAbMpcMaterialActivationRef({
          kind: 'mpc_material_activation_ref',
          activation_id: `ecdsa-activation-v1-${input.activationCorrelationId}`,
          capability: `ecdsa-capability-v1-${input.activationCorrelationId}`,
          material_owner: registration.lifecycle.account_id,
          key_binding: publicFacts.contextBinding32B64u,
          lifecycle_binding: registration.lifecycle.lifecycle_id,
          signing_worker: registration.signer_set.selected_server.server_id,
        }),
        activation_epoch: registration.lifecycle.root_share_epoch,
        activation_digest_b64u: FIXTURE_ECDSA_DIGEST32_B64U,
        activated_at_ms: Date.now(),
      },
      lifecycle_id: registration.lifecycle.lifecycle_id,
      transcript_digest: { bytes: new Array<number>(32).fill(0) },
    });
    this.activatedReceipt = receipt;
    if (this.failAfterNextActivationCommit) {
      this.failAfterNextActivationCommit = false;
      throw new Error('Fixture Router committed the activation and then lost its caller');
    }
    return {
      ok: true,
      value: receipt,
    };
  }
}

function fixtureActivationRequestDigest(requestDigestB64u: string): { bytes: number[] } {
  const bytes = base64UrlDecode(requestDigestB64u);
  if (bytes.length !== 32) {
    throw new Error('Strict ECDSA activation fixture requires a 32-byte request digest');
  }
  return { bytes: Array.from(bytes) };
}

export function silentLogger(): Logger {
  return { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
}

export function createRouterAbSigningRuntimesForUnitTests(input: {
  readonly config?: ThresholdStoreConfigInput | null;
  readonly logger?: Logger | null;
  readonly walletSessionStore?: Ed25519WalletSessionStore | null;
}): {
  readonly runtimes: RouterAbSigningRuntimeBundle;
  readonly normalSigning: RouterAbNormalSigningRuntime;
  readonly ecdsaPresign: RouterAbEcdsaPresignRuntime;
  readonly routerAbNormalSigningRuntime: RouterAbNormalSigningRuntime;
  readonly walletSessionStore: Ed25519WalletSessionStore;
  readonly ecdsaWalletSessionStore: ReturnType<typeof createEcdsaWalletSessionStore>;
} {
  const logger = normalizeLogger(input.logger || silentLogger());
  const ecdsaWalletSessionStore = createEcdsaWalletSessionStore({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });
  const walletSessionStore =
    input.walletSessionStore ||
    createEd25519WalletSessionStore({ config: { kind: 'in-memory' }, logger, isNode: true });
  const config = {
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker.local',
    ROUTER_AB_SIGNING_WORKER_URL: 'https://signing-worker.example.test',
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'test-router-ab-internal-service-auth',
    ...input.config,
  };
  const normalSigning = new RouterAbNormalSigningRuntime({
    walletSessionStore,
    ecdsaWalletSessionStore,
    config: parseRouterAbNormalSigningRuntimeConfig(config),
  });
  const normalSigningConfig = parseRouterAbNormalSigningRuntimeConfig(config);
  const ecdsaPresign = new RouterAbEcdsaPresignRuntime({
    config: parseRouterAbEcdsaPresignRuntimeConfig(config),
    signingWorkerTransport: requireRouterAbConfiguredSigningWorkerPrivateTransport(
      normalSigningConfig.signingWorkerTransport,
    ),
    ensureReady: async () => {},
  });

  return {
    runtimes: {
      normalSigning,
      ecdsaPresign,
    },
    normalSigning,
    ecdsaPresign,
    routerAbNormalSigningRuntime: normalSigning,
    walletSessionStore,
    ecdsaWalletSessionStore,
  };
}
