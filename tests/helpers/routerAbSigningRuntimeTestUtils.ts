import { base64UrlDecode } from '@shared/utils/encoders';
import { normalizeLogger, type Logger } from '@server/core/logger';
import {
  createHostedSigningRootShareResolver,
  type SealedSigningRootShare,
  type SigningRootShareResolver,
} from '@server/core/ThresholdService/signingRootShareResolver';
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
} from '@server/router/routerAbEcdsaStrictRegistration';
import type { ThresholdStoreConfigInput } from '@server/core/types';
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
import { readFileSync } from 'node:fs';

let fixtureSigningRootShareWires: Map<number, Uint8Array> | null = null;
const FIXTURE_THRESHOLD_PRF_POLICY = {
  protocol: 'threshold-prf',
  threshold: 2,
  shareCount: 3,
} as const;

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

  async activate(): Promise<never> {
    throw new Error('Strict ECDSA activation is outside this fixture');
  }
}

export class SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort implements RouterAbEcdsaStrictRegistrationPort {
  registrationRequest: RouterAbEcdsaRegistrationRequestV1 | null = null;
  activatedReceipt: RouterAbEcdsaRegistrationActivationReceiptV1 | null = null;

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
        material_activation: input.materialActivation,
        activation_epoch: registration.lifecycle.root_share_epoch,
        activation_digest_b64u: FIXTURE_ECDSA_DIGEST32_B64U,
        activated_at_ms: Date.now(),
      },
      lifecycle_id: registration.lifecycle.lifecycle_id,
      transcript_digest: { bytes: new Array<number>(32).fill(0) },
    });
    this.activatedReceipt = receipt;
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

function loadFixtureSigningRootShareWiresForUnitTests(): Map<number, Uint8Array> {
  if (fixtureSigningRootShareWires) return fixtureSigningRootShareWires;
  const corpus = JSON.parse(
    readFileSync(
      new URL('../../crates/threshold-prf/fixtures/protocol-t-of-n.json', import.meta.url),
      'utf8',
    ),
  ) as {
    vectors?: Array<{
      purpose?: string;
      policy?: { threshold?: number; share_count?: number };
      shares?: Array<{ id?: number; wire_hex?: string }>;
    }>;
  };
  const vector = corpus.vectors?.find(
    (entry) => entry.purpose === 'router-ab-ecdsa-derivation/y-server/v1',
  );
  if (
    vector?.policy?.threshold !== FIXTURE_THRESHOLD_PRF_POLICY.threshold ||
    vector.policy.share_count !== FIXTURE_THRESHOLD_PRF_POLICY.shareCount
  ) {
    throw new Error('Missing threshold-prf 2-of-3 signing-root fixture policy');
  }
  const shares = new Map<number, Uint8Array>();
  for (const share of vector.shares || []) {
    if (typeof share.id !== 'number' || share.id < 1 || share.id > 3) continue;
    const wireHex = String(share.wire_hex || '').trim();
    if (wireHex) shares.set(share.id, new Uint8Array(Buffer.from(wireHex, 'hex')));
  }
  if (shares.size < FIXTURE_THRESHOLD_PRF_POLICY.threshold) {
    throw new Error('Missing threshold-prf signing-root fixture shares');
  }
  fixtureSigningRootShareWires = shares;
  return shares;
}

export function createFixtureSigningRootShareResolverForUnitTests(): SigningRootShareResolver {
  const shares = loadFixtureSigningRootShareWiresForUnitTests();
  return createHostedSigningRootShareResolver({
    policy: FIXTURE_THRESHOLD_PRF_POLICY,
    storageAdapter: {
      listSealedSigningRootShares: async (input) =>
        Array.from(shares.keys())
          .sort((left, right) => left - right)
          .map(
            (shareId): SealedSigningRootShare => ({
              signingRootId: input.signingRootId,
              signingRootVersion: input.signingRootVersion,
              shareId,
              sealedShare: new Uint8Array([shareId]),
              storageId: `fixture-share-${shareId}`,
              kekId: 'fixture-share-kek',
            }),
          ),
    },
    decryptAdapter: {
      decryptSigningRootShare: async (record) => {
        const wire = shares.get(record.shareId);
        if (!wire) throw new Error(`missing fixture signing-root share ${record.shareId}`);
        return new Uint8Array(wire);
      },
    },
  });
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
