import { expect, test } from '@playwright/test';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import type { WalletEd25519YaoActiveCapabilityRecord } from '../../packages/sdk-server-ts/src/core/WalletStore';
import {
  createRouterAbEd25519YaoProductRegistrationStatefulCompositionV1,
  createRouterAbEd25519YaoProductRegistrationStateV1,
  parseRouterAbEd25519YaoProductRegistrationStateV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistration';
import type { RouterAbEd25519YaoRegistrationBackend } from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRegistration';
import type {
  RouterAbEd25519YaoCapabilityPersistenceResultV1,
  RouterAbEd25519YaoCapabilityPersistenceV1,
  RouterAbEd25519YaoRecoveryBackend,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';
import type { RouterAbEd25519YaoExportBackend } from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoExport';
import { buildEd25519YaoCapabilityFixture } from '../helpers/ed25519YaoCapabilityFixtures';
import { UnusedSessionAdapter } from './helpers/routerAbEd25519YaoRegistrationBridge.fixtures';

async function rejectUnusedBackend(): Promise<never> {
  throw new Error('Protocol backend is outside the capability fallback test');
}

const UNUSED_BACKEND: RouterAbEd25519YaoRegistrationBackend &
  RouterAbEd25519YaoRecoveryBackend &
  RouterAbEd25519YaoExportBackend = {
  admit: rejectUnusedBackend,
  execute: rejectUnusedBackend,
  admitRecovery: rejectUnusedBackend,
  executeRecovery: rejectUnusedBackend,
  activateRecovery: rejectUnusedBackend,
  admitExport: rejectUnusedBackend,
  executeExport: rejectUnusedBackend,
};

const UNUSED_WEBAUTHN = {
  verifyWebAuthnAuthenticationLite: rejectUnusedBackend,
};

class AppliedCapabilityPersistence implements RouterAbEd25519YaoCapabilityPersistenceV1 {
  replaceActiveCapability(): RouterAbEd25519YaoCapabilityPersistenceResultV1 {
    return { ok: true, disposition: 'applied' };
  }
}

function capabilityFixture(input: {
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly seed: number;
}): WalletEd25519YaoActiveCapabilityRecord {
  return buildEd25519YaoCapabilityFixture({
    walletId: walletIdFromString(input.walletId),
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: 'near-ed25519-stateful-fallback',
    thresholdSessionId: 'threshold-stateful-fallback',
    signerSlot: 1,
    signingWorkerId: 'signing-worker-stateful-fallback',
    participantIds: [1, 2],
    runtimePolicyScope: {
      orgId: 'org-stateful-fallback',
      projectId: 'project-stateful-fallback',
      envId: 'test',
      signingRootVersion: 'root-stateful-fallback-v1',
    },
    seed: input.seed,
  }).capability;
}

function capabilityLookup(capability: WalletEd25519YaoActiveCapabilityRecord) {
  return {
    kind: 'router_ab_ed25519_yao_active_capability_lookup_v1' as const,
    walletId: capability.admissionRequest.application_binding.wallet_id,
    nearEd25519SigningKeyId:
      capability.admissionRequest.application_binding.near_ed25519_signing_key_id,
    signerSlot: capability.admissionRequest.application_binding.key_creation_signer_slot,
    signingWorkerId: capability.admissionRequest.scope.signing_worker_id,
    participantIds: capability.admissionRequest.participant_ids,
  };
}

function statefulRuntime(input: {
  readonly state: ReturnType<typeof createRouterAbEd25519YaoProductRegistrationStateV1>;
}) {
  return createRouterAbEd25519YaoProductRegistrationStatefulCompositionV1({
    signingWorkerId: 'signing-worker-stateful-fallback',
    backend: UNUSED_BACKEND,
    session: new UnusedSessionAdapter(),
    webAuthn: UNUSED_WEBAUTHN,
    state: input.state,
    capabilityPersistence: new AppliedCapabilityPersistence(),
  }).runtime;
}

test('Ed25519 Yao product state survives the Durable Object structured-clone boundary', () => {
  const state = createRouterAbEd25519YaoProductRegistrationStateV1();
  state.registration.lifecycleSessions.set('lifecycle-1', 'session-1');
  state.export.authorizationNonces.add('nonce-1');

  const parsed = parseRouterAbEd25519YaoProductRegistrationStateV1(structuredClone(state));

  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error(parsed.message);
  expect(parsed.value.registration.lifecycleSessions.get('lifecycle-1')).toBe('session-1');
  expect(parsed.value.export.authorizationNonces.has('nonce-1')).toBe(true);
});

test('Ed25519 Yao product state rejects JSON-shaped lifecycle collections', () => {
  const state = createRouterAbEd25519YaoProductRegistrationStateV1();
  const jsonShapedState = JSON.parse(JSON.stringify(state));

  expect(parseRouterAbEd25519YaoProductRegistrationStateV1(jsonShapedState)).toEqual({
    ok: false,
    message: 'persisted Ed25519 Yao product state has invalid lifecycle collections',
  });
});

test('stateful capability resolution leaves an empty legacy snapshot empty', async () => {
  const capability = capabilityFixture({
    walletId: 'wallet-stateful-fallback',
    nearAccountId: 'wallet-stateful-fallback.testnet',
    seed: 93,
  });
  const state = createRouterAbEd25519YaoProductRegistrationStateV1();
  const runtime = statefulRuntime({ state });

  await expect(
    runtime.resolveActiveCapability(capabilityLookup(capability)),
  ).resolves.toMatchObject({
    ok: false,
    code: 'unknown_capability',
  });
  expect(state.recovery.capabilities.size).toBe(0);
  expect(state.recovery.identityCapabilities.size).toBe(0);
});
