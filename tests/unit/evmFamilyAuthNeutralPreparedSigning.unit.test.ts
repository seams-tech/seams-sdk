import { expect, test } from '@playwright/test';
import {
  prepareEvmFamilyEcdsaSigningSession,
  type PrepareEvmFamilyEcdsaSigningDeps,
} from '@/core/signingEngine/flows/signEvmFamily/preparedSigning';
import { requireEvmFamilyEcdsaSigner } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { requireEvmFamilyStepUpAuth } from '@/core/signingEngine/flows/signEvmFamily/requireEvmFamilyStepUpAuth';
import type {
  EvmFamilyThresholdEcdsaOperation,
  EvmFamilyThresholdEcdsaStepUpRuntime,
} from '@/core/signingEngine/flows/signEvmFamily/requireEvmFamilyStepUpAuth';
import { prepareEvmFamilyEcdsaOperationStepUp } from '@/core/signingEngine/flows/signEvmFamily/thresholdAdmission';
import { SigningOperationIntent } from '@/core/signingEngine/session/operationState/types';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { laneCandidateAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import {
  AVAILABLE_LANES_ECDSA_TARGET,
  AVAILABLE_LANES_WALLET_ID,
  authorizationRequiredCanonicalEcdsaAvailableLane,
  canonicalEcdsaAvailableLane,
  canonicalEcdsaOwnerLaneScopeFixture,
  readAvailableLanesFixture,
} from './helpers/availableSigningLanes.fixtures';
import { walletSessionRefFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import {
  ecdsaOperationDigestSetFixture,
  hydratedEcdsaSigningMaterialFixture,
} from './helpers/ecdsaOperationStepUp.fixtures';

// The auth-required operating path: material selection recognizes an
// auth-neutral candidate before the reusable-session planner runs, hands
// confirmation the exact material identity instead of a selected lane, and the
// step-up that authorizes the operation is chosen by the capability's own
// factor rather than by the confirmation's preference.
//
// The reusable-session planner is deliberately never reached on this path, so
// the only dep the prepared session needs is the availability read.

const OPERATION_ID = SigningSessionIds.signingOperation('auth-neutral-operation-1');

function prepareDeps(
  availableLanes: Awaited<ReturnType<typeof readAvailableLanesFixture>>,
  record: ReturnType<typeof canonicalEcdsaAvailableLane>,
): PrepareEvmFamilyEcdsaSigningDeps {
  return {
    resolveOwnerLaneScope: async () => canonicalEcdsaOwnerLaneScopeFixture(record),
    readAvailableSigningLanesForSigning: async () => availableLanes,
  };
}

async function prepareForRecord(record: ReturnType<typeof canonicalEcdsaAvailableLane>) {
  const availableLanes = await readAvailableLanesFixture({
    walletId: AVAILABLE_LANES_WALLET_ID,
    ecdsaChainTargets: [AVAILABLE_LANES_ECDSA_TARGET],
    canonicalEcdsaLanes: [record],
  });
  return await prepareEvmFamilyEcdsaSigningSession({
    deps: prepareDeps(availableLanes, record),
    walletSession: walletSessionRefFixture(AVAILABLE_LANES_WALLET_ID),
    signingTarget: AVAILABLE_LANES_ECDSA_TARGET,
    signingOperation: {
      operationId: OPERATION_ID,
      intent: SigningOperationIntent.TransactionSign,
    },
    diagnostics: {},
    // Never consulted on the auth-required path: reaching it would mean the
    // reusable-session planner ran for material nothing authorizes.
    signingSessionCoordinator: new SigningSessionCoordinator({}),
  });
}

function authRequiredRecord(authMethod: 'passkey' | 'email_otp') {
  return authorizationRequiredCanonicalEcdsaAvailableLane({
    chainTarget: AVAILABLE_LANES_ECDSA_TARGET,
    thresholdOwnerAddress: `0x${'ab'.repeat(20)}`,
    authMethod,
    ecdsaThresholdKeyId: `auth-neutral-${authMethod}`,
  });
}

test.describe('EVM-family auth-neutral prepared signing', () => {
  test('prepares auth-neutral material without a selected lane or authorization', async () => {
    const record = authRequiredRecord('passkey');
    const prepared = await prepareForRecord(record);

    expect(prepared.kind).toBe('authorization_required');
    if (prepared.kind !== 'authorization_required') {
      throw new Error('expected an authorization-required prepared session');
    }
    // Nothing warm-session-shaped survives preparation.
    expect(prepared.signingLane).toBeUndefined();
    expect(prepared.transactionOperation).toBeUndefined();
    expect(prepared.preparedOperation).toBeUndefined();
    expect(prepared.selection).toBeUndefined();
    expect(prepared.candidate.authorizationState).toBe('authorization_required');
    expect(prepared.candidate.authorization).toBeUndefined();
  });

  test('carries the exact material identity the signing runtime resolves from', async () => {
    const record = authRequiredRecord('passkey');
    const prepared = await prepareForRecord(record);
    if (prepared.kind !== 'authorization_required') {
      throw new Error('expected an authorization-required prepared session');
    }

    // The runtime resolves the canonical capability from wallet, chain target
    // and material activation -- exactly what the carrier names.
    const signer = requireEvmFamilyEcdsaSigner(prepared.identity, 'auth-neutral operating path');
    expect(String(signer.walletId)).toBe(AVAILABLE_LANES_WALLET_ID);
    expect(signer.chainTarget).toEqual(AVAILABLE_LANES_ECDSA_TARGET);
    expect(String(signer.materialActivation.activationId)).toBe(
      String(record.materialActivation.activationId),
    );
  });

  test('binds the operation the step-up will authorize', async () => {
    const prepared = await prepareForRecord(authRequiredRecord('passkey'));
    if (prepared.kind !== 'authorization_required') {
      throw new Error('expected an authorization-required prepared session');
    }

    // Router A/B normal signing rejects an operation without an exact id, so
    // the intent handed to the step-up has to carry the one being signed.
    expect(prepared.intent.operationId).toBe(OPERATION_ID);
  });

  test('an authorized candidate still takes the reusable-session path', async () => {
    // The discriminant is real: identical availability shape, differing only in
    // whether a reusable Wallet Session authorizes the material, must not
    // return the auth-neutral branch.
    const record = canonicalEcdsaAvailableLane({
      chainTarget: AVAILABLE_LANES_ECDSA_TARGET,
      thresholdOwnerAddress: `0x${'cd'.repeat(20)}`,
      authMethod: 'passkey',
      ecdsaThresholdKeyId: 'authorized-material',
    });
    const availableLanes = await readAvailableLanesFixture({
      walletId: AVAILABLE_LANES_WALLET_ID,
      ecdsaChainTargets: [AVAILABLE_LANES_ECDSA_TARGET],
      canonicalEcdsaLanes: [record],
    });
    const outcome = await prepareEvmFamilyEcdsaSigningSession({
      deps: prepareDeps(availableLanes, record),
      walletSession: walletSessionRefFixture(AVAILABLE_LANES_WALLET_ID),
      signingTarget: AVAILABLE_LANES_ECDSA_TARGET,
      signingOperation: {
        operationId: OPERATION_ID,
        intent: SigningOperationIntent.TransactionSign,
      },
      diagnostics: {},
      signingSessionCoordinator: new SigningSessionCoordinator({}),
    }).then(
      (prepared) => prepared.kind,
      // Without a coordinator the reusable-session planner cannot complete --
      // which is itself the proof that this branch went to the planner.
      () => 'reached_reusable_session_planner' as const,
    );

    expect(outcome).not.toBe('authorization_required');
  });
});

test.describe('auth-neutral material escalates on its own factor', () => {
  function stepUpRuntime(
    requiredFactor: 'passkey' | 'email_otp',
  ): EvmFamilyThresholdEcdsaStepUpRuntime {
    return {
      reusableAuthorization: { kind: 'absent', requiredFactor },
      operationStepUp: {
        prepare: async () => {
          throw new Error('not exercised in step-up selection');
        },
        authorize: async () => {
          throw new Error('not exercised in step-up selection');
        },
      },
      ...(requiredFactor === 'email_otp'
        ? {
            emailOtpSigning: {
              prepare: async () => ({ challengeId: 'otp-auth-neutral' }),
            },
          }
        : {}),
    };
  }

  for (const factor of ['passkey', 'email_otp'] as const) {
    test(`${factor}-bound material requires a ${factor} step-up`, async () => {
      const record = authRequiredRecord(factor);
      const prepared = await prepareForRecord(record);
      if (prepared.kind !== 'authorization_required') {
        throw new Error('expected an authorization-required prepared session');
      }

      // The runtime derives the required factor from the capability's own
      // authority; the candidate's auth binding is that same factor.
      const requiredFactor = laneCandidateAuthMethod(prepared.candidate);
      expect(requiredFactor).toBe(factor);

      const stepUp = await requireEvmFamilyStepUpAuth({
        thresholdEcdsaStepUp: {
          kind: 'required',
          authPlan: {
            kind: 'planned',
            // A passkey-preferring plan on both branches: the escalation must
            // come from the capability, not from this preference.
            signingAuthPlan: { kind: 'passkeyReauth', method: 'passkey' },
          },
          operation: {
            intent: prepared.intent,
            authPlan: { kind: 'passkeyReauth', method: 'passkey' },
          } satisfies EvmFamilyThresholdEcdsaOperation,
          runtime: stepUpRuntime(requiredFactor),
        },
        hasThresholdEcdsaRequest: true,
        needsWebAuthn: factor === 'passkey',
        requiredSignatureUses: 1,
        explicitAuthErrorLabel: 'EVM',
      });

      expect(stepUp.kind).toBe(factor);
      expect(stepUp.confirmationAuthPayload.signingAuthPlan.method).toBe(factor);
    });
  }

  test('the operation step-up is prepared against the exact bound operation id', async () => {
    const prepared = await prepareForRecord(authRequiredRecord('passkey'));
    if (prepared.kind !== 'authorization_required') {
      throw new Error('expected an authorization-required prepared session');
    }

    const { fixture, material } = await hydratedEcdsaSigningMaterialFixture('passkey');
    const operationStepUp = await prepareEvmFamilyEcdsaOperationStepUp({
      operation: {
        intent: prepared.intent,
        authPlan: { kind: 'passkeyReauth', method: 'passkey' },
      },
      operationDigests: ecdsaOperationDigestSetFixture(),
      material,
    });
    expect(operationStepUp.operation.operation_id).toBe(OPERATION_ID);
    expect(prepared.intent.operationId).toBe(OPERATION_ID);
  });
});
