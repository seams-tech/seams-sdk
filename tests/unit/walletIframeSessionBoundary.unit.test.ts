import { expect, test } from '@playwright/test';
import type { WalletSession, WalletSessionCapabilityLaneReadiness } from '@/core/types/seams';
import {
  parseWalletIframeExactSessionState,
  parseWalletSessionFromBoundary,
} from '@/SeamsWeb/walletIframe/shared/exactSessionState';
import {
  activeWalletSessionFixture,
  activeWalletSessionWithNonceDiagnosticsFixture,
  authorizationRequiredEcdsaWalletSessionFixture,
  failedEcdsaWalletSessionFixture,
  readyEcdsaWalletSessionFixture,
  restorableEcdsaWalletSessionFixture,
  supersededEcdsaWalletSessionFixture,
} from './helpers/walletSessionReadProjection.fixtures';

function ecdsaCapabilityOutcomeFromBoundary(
  input: WalletSession,
): WalletSessionCapabilityLaneReadiness['kind'] {
  const parsed = parseWalletSessionFromBoundary(input, 'iframe-wallet');
  if (parsed.capabilityProjection.kind !== 'resolved') {
    throw new Error('Capability fixture must resolve at the iframe boundary');
  }
  const capability = parsed.capabilityProjection.capabilities[0];
  if (capability.kind !== 'evm_family_ecdsa') {
    throw new Error('Capability fixture must carry ECDSA readiness');
  }
  if (capability.targets.kind !== 'configured_targets') {
    throw new Error('Capability fixture must carry one configured target');
  }
  return capability.targets.lanes[0].readiness.kind;
}

test.describe('wallet iframe Wallet Session boundary', () => {
  test('parses and reconstructs the requested active Wallet Session', () => {
    const input = activeWalletSessionWithNonceDiagnosticsFixture({
      walletId: 'iframe-wallet',
    });

    expect(
      parseWalletSessionFromBoundary(
        {
          ...input,
          walletSessionJwt: 'must-not-cross',
        },
        'iframe-wallet',
      ),
    ).toEqual(input);
  });

  test('rejects a response for a different wallet', () => {
    const input = activeWalletSessionFixture({ walletId: 'returned-wallet' });

    expect(() => parseWalletSessionFromBoundary(input, 'requested-wallet')).toThrow(
      'does not match the requested wallet',
    );
  });

  test('rejects removed reusable-session boundary fields', () => {
    const input = activeWalletSessionFixture({ walletId: 'canonical-wallet' });
    expect(() =>
      parseWalletSessionFromBoundary({
        ...input,
        reusableWalletSession: { kind: 'active' },
      }),
    ).toThrow('removed reusable-session fields');
  });

  test('rejects disagreement between app and capability projection wallet identities', () => {
    const input = readyEcdsaWalletSessionFixture({ walletId: 'canonical-wallet' });
    if (input.capabilityProjection.kind !== 'resolved') {
      throw new Error('ECDSA fixture must resolve a capability projection');
    }
    const subject = input.capabilityProjection.subjectSet.subjects[0];
    const capability = input.capabilityProjection.capabilities[0];
    if (!subject || subject.kind !== 'evm_family_ecdsa_wallet') {
      throw new Error('ECDSA fixture must contain an ECDSA subject');
    }
    if (!capability || capability.kind !== 'evm_family_ecdsa') {
      throw new Error('ECDSA fixture must contain an ECDSA capability');
    }
    const corruptedSubject = {
      ...subject,
      walletId: 'different-wallet',
      authority: {
        ...subject.authority,
        walletId: 'different-wallet',
      },
    };
    const corrupted = {
      ...input,
      capabilityProjection: {
        ...input.capabilityProjection,
        subjectSet: {
          ...input.capabilityProjection.subjectSet,
          walletId: 'different-wallet',
          subjects: [corruptedSubject],
        },
        capabilities: [
          {
            ...capability,
            subject: corruptedSubject,
          },
        ],
      },
    };

    expect(() => parseWalletSessionFromBoundary(corrupted)).toThrow('wallet identities disagree');
  });

  test('keeps material restorable while rejecting reusable active_restorable', () => {
    expect(() =>
      parseWalletIframeExactSessionState({
        kind: 'active_session',
        status: 'active_restorable',
        walletId: 'iframe-wallet',
        authorizationId: 'iframe-wallet-authorization',
        walletSessionId: 'iframe-wallet-session',
        authMethod: 'passkey',
        expiresAtMs: Date.now() + 60_000,
      }),
    ).toThrow('active session status is invalid');

    const parsed = parseWalletSessionFromBoundary(
      restorableEcdsaWalletSessionFixture({
        walletId: 'iframe-wallet',
      }),
      'iframe-wallet',
    );
    expect(parsed.capabilityProjection.kind).toBe('resolved');
    if (parsed.capabilityProjection.kind !== 'resolved') return;
    const capability = parsed.capabilityProjection.capabilities[0];
    expect(capability.kind).toBe('evm_family_ecdsa');
    if (capability.kind !== 'evm_family_ecdsa') return;
    expect(capability.targets).toMatchObject({
      kind: 'configured_targets',
      lanes: [{ readiness: { kind: 'pending', resume: 'restore_material' } }],
    });
  });

  test('preserves authorization-required ECDSA material across the iframe boundary', () => {
    const parsed = parseWalletSessionFromBoundary(
      authorizationRequiredEcdsaWalletSessionFixture({ walletId: 'iframe-wallet' }),
      'iframe-wallet',
    );
    expect(parsed.capabilityProjection.kind).toBe('resolved');
    if (parsed.capabilityProjection.kind !== 'resolved') return;
    const capability = parsed.capabilityProjection.capabilities[0];
    expect(capability.kind).toBe('evm_family_ecdsa');
    if (capability.kind !== 'evm_family_ecdsa') return;
    expect(capability.targets).toMatchObject({
      kind: 'configured_targets',
      lanes: [
        {
          readiness: {
            kind: 'authorization_required',
            requirement: 'same_method_step_up',
          },
        },
      ],
    });
  });

  test('parses every capability preparation outcome at the iframe boundary', () => {
    const inputs = [
      readyEcdsaWalletSessionFixture({ walletId: 'iframe-wallet' }),
      restorableEcdsaWalletSessionFixture({ walletId: 'iframe-wallet' }),
      authorizationRequiredEcdsaWalletSessionFixture({ walletId: 'iframe-wallet' }),
      supersededEcdsaWalletSessionFixture({ walletId: 'iframe-wallet' }),
      failedEcdsaWalletSessionFixture({ walletId: 'iframe-wallet' }),
    ];
    const outcomes = inputs.map(ecdsaCapabilityOutcomeFromBoundary);

    expect(outcomes).toEqual([
      'ready',
      'pending',
      'authorization_required',
      'superseded',
      'failed',
    ]);
  });

  test('requires exact missing authorization identity at the iframe boundary', () => {
    expect(() =>
      parseWalletIframeExactSessionState({
        kind: 'wallet_unlocked_without_signing_session',
        walletId: 'iframe-wallet',
        reason: 'not_found',
      }),
    ).toThrow('missing authorization ID is invalid');
  });

  test('rejects aliased authorization and Wallet Session IDs at the iframe boundary', () => {
    expect(() =>
      parseWalletIframeExactSessionState({
        kind: 'active_session',
        status: 'active',
        walletId: 'iframe-wallet',
        authorizationId: 'same-id',
        walletSessionId: 'same-id',
        authMethod: 'passkey',
        expiresAtMs: Date.now() + 60_000,
      }),
    ).toThrow('authorization and Wallet Session IDs must be distinct');
  });
});
