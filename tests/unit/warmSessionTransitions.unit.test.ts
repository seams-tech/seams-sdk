import { expect, test } from '@playwright/test';
import {
  emitWarmSessionTransition,
  summarizeWarmSessionTransition,
  type WarmSessionTransitionEvent,
} from '@/core/signingEngine/session/warmCapabilities/transitions';
import { selectedEcdsaLane } from '@/core/signingEngine/session/identity/laneIdentity';
import type { WarmSessionEnvelope } from '@/core/signingEngine/session/warmCapabilities/types';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { canonicalEcdsaSealedRuntimeFixture } from './helpers/ecdsaOperationStepUp.fixtures';
import { activeEvmFamilyWalletSessionAuthorizationFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import {
  buildPasskeyEd25519AuthorizationProjectionFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';

async function createEnvelope(): Promise<WarmSessionEnvelope> {
  const { fixture, runtime } = await canonicalEcdsaSealedRuntimeFixture('passkey');
  const authorization = activeEvmFamilyWalletSessionAuthorizationFixture({
    manifest: fixture.manifest,
  });
  const publicFacts = fixture.manifest.durableMaterial.roleLocalPublicFacts;
  if (
    runtime.authBinding.kind !== 'passkey' ||
    !runtime.authBinding.rpId ||
    !runtime.authBinding.credentialIdB64u
  ) {
    throw new Error('transition fixture requires an exact passkey runtime binding');
  }
  const credentialIdB64u = runtime.authBinding.credentialIdB64u;
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: runtime.walletId,
    ecdsaThresholdKeyId: runtime.ecdsaThresholdKeyId,
    signingRootId: String(publicFacts.signingRootId),
    signingRootVersion: String(publicFacts.signingRootVersion),
    participantIds: [...runtime.participantIds],
    thresholdOwnerAddress: String(publicFacts.ethereumAddress),
  });
  const lane = selectedEcdsaLane({
    key,
    materialActivation: runtime.materialActivation,
    keyHandle: runtime.keyHandle,
    walletId: runtime.walletId,
    auth: {
      kind: 'passkey',
      rpId: toRpId(runtime.authBinding.rpId),
      credentialIdB64u,
    },
    authorization,
    chainTarget: runtime.chainTarget,
  });
  const ed25519Record = buildPasskeyEd25519SealedSessionRecordFixture({
    walletId: runtime.walletId,
    expiresAtMs: 1_900_000_000_000,
  });
  const ed25519Runtime = parseExactEd25519SealedSessionRuntime(ed25519Record);
  if (!ed25519Runtime) {
    throw new Error('transition fixture requires exact Ed25519 sealed runtime');
  }
  const ed25519Authorization = buildPasskeyEd25519AuthorizationProjectionFixture(ed25519Record);
  return {
    walletId: ed25519Runtime.walletId,
    capabilities: {
      ed25519: {
        capability: 'ed25519',
        runtime: ed25519Runtime,
        auth: ed25519Authorization,
        prfClaim: {
          state: 'warm',
          thresholdSessionId: ed25519Runtime.thresholdSessionId,
          remainingUses: 4,
          expiresAtMs: ed25519Runtime.expiresAtMs,
        },
        state: 'ready',
      },
      ecdsa: {
        evm: {
          capability: 'ecdsa',
          manifest: null,
          runtime: null,
          key: null,
          lane: null,
          auth: null,
          prfClaim: null,
          state: 'missing',
        },
        tempo: {
          capability: 'ecdsa',
          manifest: fixture.manifest,
          runtime,
          key,
          lane,
          auth: authorization,
          prfClaim: {
            state: 'unavailable',
            thresholdSessionId: runtime.sealedRecord.thresholdSessionId,
            code: 'worker_error',
          },
          state: 'prf_unavailable',
        },
      },
    },
    updatedAtMs: 5678,
  };
}

test.describe('warmSessionTransitions', () => {
  test('summarizes warm-session envelopes into transition snapshots', async () => {
    const envelope = await createEnvelope();
    expect(summarizeWarmSessionTransition(envelope)).toMatchObject({
      walletId: envelope.walletId,
      updatedAtMs: 5678,
      capabilities: {
        ed25519: {
          state: 'ready',
          thresholdSessionId: 'ed25519-sealed-runtime-session',
          authState: 'present',
          prfClaimState: 'warm',
          remainingUses: 4,
          expiresAtMs: 1_900_000_000_000,
        },
        ecdsa: {
          tempo: {
            state: 'prf_unavailable',
            thresholdSessionId:
              envelope.capabilities.ecdsa.tempo.runtime?.sealedRecord.thresholdSessionId,
            authState: 'present',
            prfClaimState: 'unavailable',
          },
        },
      },
    });
  });

  test('swallows synchronous transition callback failures', async () => {
    const envelope = await createEnvelope();
    const warnings: unknown[][] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args);
    };
    try {
      emitWarmSessionTransition({
        onTransition: () => {
          throw new Error('sync transition failure');
        },
        event: {
          type: 'ed25519_capability_provisioned',
          walletId: 'transition-summary.testnet' as any,
          thresholdSessionId: 'ed25519-session',
          before: summarizeWarmSessionTransition(envelope),
          after: summarizeWarmSessionTransition(envelope),
        },
      });
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings).toHaveLength(1);
    expect(warnings[0][0]).toBe('[WarmSessionStore] warm-session transition callback failed');
  });

  test('swallows asynchronous transition callback failures', async () => {
    const envelope = await createEnvelope();
    const warnings: unknown[][] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args);
    };
    try {
      const event: WarmSessionTransitionEvent = {
        type: 'ed25519_capability_provisioned',
        walletId: 'transition-summary.testnet' as any,
        thresholdSessionId: 'ed25519-session',
        before: summarizeWarmSessionTransition(envelope),
        after: summarizeWarmSessionTransition(envelope),
      };
      emitWarmSessionTransition({
        onTransition: async () => {
          throw new Error('async transition failure');
        },
        event,
      });
      await Promise.resolve();
      await Promise.resolve();
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings).toHaveLength(1);
    expect(warnings[0][0]).toBe('[WarmSessionStore] warm-session transition callback failed');
  });
});
