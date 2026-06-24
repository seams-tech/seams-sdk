import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AuthService } from '../../packages/sdk-server-ts/src/core/AuthService';
import { createThresholdSigningService } from '../../packages/sdk-server-ts/src/core/ThresholdService';
import type { SealedSigningRootShare } from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootShareResolver';
import type {
  ThresholdEd25519RegistrationAccountScope,
  ThresholdStoreConfigInput,
} from '../../packages/sdk-server-ts/src/core/types';
import {
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
} from '../../packages/shared-ts/src/threshold/ecdsaHssRoleLocalBootstrap';
import { computeSdkEd25519HssApplicationBindingDigestB64u } from '../../packages/shared-ts/src/threshold/ed25519HssBinding';
import { ed25519KeyScopeIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';

type ThresholdPrfFixtureShare = {
  readonly id: number;
  readonly wire_hex: string;
};

type ThresholdPrfFixtureVector = {
  readonly purpose: string;
  readonly policy: {
    readonly threshold: number;
    readonly share_count: number;
  };
  readonly shares: readonly ThresholdPrfFixtureShare[];
};

type ThresholdPrfFixtureCorpus = {
  readonly vectors: readonly ThresholdPrfFixtureVector[];
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(__dirname, '../../crates/threshold-prf/fixtures/protocol-t-of-n.json');
const ORG_ID = 'org-alpha';
const PROJECT_ID = 'project-alpha';
const ENV_ID = 'dev';
const SIGNING_ROOT_ID = `${PROJECT_ID}:${ENV_ID}`;
const PARTICIPANT_IDS = [1, 2] as const;

function createRegistrationAccountScopeFixture(): ThresholdEd25519RegistrationAccountScope {
  return {
    kind: 'generated_implicit_registration_scope',
    walletId: 'alice.near',
    rpId: 'example.localhost',
    intentDigestB64u: 'intent-digest',
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: 'v1',
    ed25519KeyScopeId: 'alice.near',
    signerSlot: 1,
    keyPurpose: 'wallet',
    keyVersion: 'v1',
    derivationVersion: 1,
    participantIds: Array.from(PARTICIPANT_IDS),
  };
}

async function createEd25519HssContextFixture(input: {
  readonly ed25519KeyScopeId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly participantIds: readonly number[];
}) {
  return {
    applicationBindingDigestB64u: await computeSdkEd25519HssApplicationBindingDigestB64u({
      ed25519KeyScopeId: ed25519KeyScopeIdFromString(input.ed25519KeyScopeId),
      signingRootId: parseSdkEcdsaHssSigningRootId(input.signingRootId),
      signingRootVersion: parseSdkEcdsaHssSigningRootVersion(input.signingRootVersion),
    }),
    participantIds: [...input.participantIds],
  };
}

function createAuthServiceMock(): AuthService {
  return {
    getRelayerAccount: async () => 'relayer.testnet',
    verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
    viewAccessKeyList: async () => ({ keys: [] }),
  } as unknown as AuthService;
}

function vectorForPurpose(purpose: string): ThresholdPrfFixtureVector {
  const corpus = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as ThresholdPrfFixtureCorpus;
  const vector = corpus.vectors.find((candidate) => candidate.purpose === purpose);
  if (!vector) throw new Error(`missing threshold-prf fixture vector for ${purpose}`);
  return vector;
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function policyFromFixture(vector: ThresholdPrfFixtureVector) {
  return {
    protocol: 'threshold-prf',
    threshold: vector.policy.threshold,
    shareCount: vector.policy.share_count,
  } as const;
}

function hostedResolverConfigFromFixture(input: {
  readonly vector: ThresholdPrfFixtureVector;
  readonly decryptCalls: number[];
}) {
  const sharesById = new Map<number, ThresholdPrfFixtureShare>(
    input.vector.shares.map((share) => [share.id, share]),
  );
  return {
    policy: policyFromFixture(input.vector),
    storageAdapter: {
      listSealedSigningRootShares: async (request: {
        signingRootId: string;
        signingRootVersion?: string;
      }): Promise<readonly SealedSigningRootShare[]> =>
        input.vector.shares.map((share) => ({
          signingRootId: request.signingRootId,
          ...(request.signingRootVersion ? { signingRootVersion: request.signingRootVersion } : {}),
          shareId: share.id,
          sealedShare: new Uint8Array([share.id]),
          storageId: `fixture-share-${share.id}`,
          kekId: 'fixture-share-kek',
        })),
    },
    decryptAdapter: {
      decryptSigningRootShare: async (record: SealedSigningRootShare): Promise<Uint8Array> => {
        input.decryptCalls.push(record.shareId);
        const share = sharesById.get(record.shareId);
        if (!share) throw new Error(`missing share ${record.shareId}`);
        return hexToBytes(share.wire_hex);
      },
    },
  };
}

test('Ed25519 HSS prepare uses signing-root resolver when configured and preserves response shape', async () => {
  const decryptCalls: number[] = [];
  const vector = vectorForPurpose('ecdsa-hss/y_server');
  const thresholdConfig: ThresholdStoreConfigInput = {
    kind: 'in-memory',
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker.local',
    signingRootShareResolverAdapters: hostedResolverConfigFromFixture({
      vector,
      decryptCalls,
    }),
  };
  const service = createThresholdSigningService({
    authService: createAuthServiceMock(),
    thresholdStore: thresholdConfig,
    isNode: true,
  });

  expect(service.hasSigningRootShareResolver()).toBe(true);
  const registrationAccountScope = createRegistrationAccountScopeFixture();
  const context = await createEd25519HssContextFixture({
    ed25519KeyScopeId: registrationAccountScope.ed25519KeyScopeId,
    signingRootId: registrationAccountScope.signingRootId,
    signingRootVersion: registrationAccountScope.signingRootVersion,
    participantIds: registrationAccountScope.participantIds,
  });
  const prepared = await service.ed25519Hss.prepareForRegistration({
    orgId: ORG_ID,
    signingRootId: SIGNING_ROOT_ID,
    request: {
      registrationAccountScope,
      wallet_key_id: 'example.localhost',
      context,
    },
  });

  if (!prepared.ok) throw new Error(prepared.message);
  expect(prepared.ok).toBe(true);
  expect(prepared.ceremonyHandle).toBeTruthy();
  expect(prepared.preparedSession.contextBindingB64u).toBeTruthy();
  expect(prepared.preparedSession.evaluatorDriverStateB64u).toBeTruthy();
  expect(prepared.clientOtOfferMessageB64u).toBeTruthy();
  expect(decryptCalls).toEqual([1, 2]);

  const resolverCallCount = decryptCalls.length;
  const mismatchedPrepared = await service.ed25519Hss.prepareForRegistration({
    orgId: ORG_ID,
    signingRootId: `${PROJECT_ID}:staging`,
    request: {
      registrationAccountScope,
      wallet_key_id: 'example.localhost',
      context,
    },
  });

  expect(mismatchedPrepared.ok).toBe(false);
  if (mismatchedPrepared.ok) throw new Error('expected mismatched signing root to fail');
  expect(mismatchedPrepared.code).toBe('unauthorized');
  expect(mismatchedPrepared.message).toContain('signingRootId');
  expect(decryptCalls).toHaveLength(resolverCallCount);
});
