import { expect, test } from '@playwright/test';
import type { WalletSession, WalletSessionCapabilityLaneReadiness } from '@/core/types/seams';
import {
  exactSessionStateFromWalletSession,
  parseWalletIframeExactSessionState,
  parseWalletSessionFromBoundary,
} from '@/SeamsWeb/walletIframe/shared/exactSessionState';
import {
  activeWalletSessionFixture,
  activeLinkedDeviceWalletSessionFixture,
  activeWalletSessionWithNonceDiagnosticsFixture,
  authorizationRequiredEcdsaWalletSessionFixture,
  failedEcdsaWalletSessionFixture,
  invalidWalletSessionFixture,
  missingWalletSessionFixture,
  readyEcdsaWalletSessionFixture,
  restorableEcdsaWalletSessionFixture,
  supersededEcdsaWalletSessionFixture,
  unavailableWalletSessionFixture,
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
      walletSessionId: 'iframe-wallet-session',
    });

    expect(
      parseWalletSessionFromBoundary(
        {
          ...input,
          walletSessionJwt: 'must-not-cross',
          reusableWalletSession: {
            ...input.reusableWalletSession,
            privateKey: 'must-not-cross',
          },
        },
        'iframe-wallet',
      ),
    ).toEqual(input);
  });

  test('preserves a distinct linked-device Wallet Session across the iframe boundary', () => {
    const input = activeLinkedDeviceWalletSessionFixture({
      walletId: 'linked-iframe-wallet',
      walletSessionId: 'linked-iframe-session',
    });

    expect(parseWalletSessionFromBoundary(input, 'linked-iframe-wallet')).toEqual(input);
    expect(exactSessionStateFromWalletSession(input)).toMatchObject({
      kind: 'active_session',
      status: 'active',
      walletId: 'linked-iframe-wallet',
      authMethod: 'linked_device',
    });
  });

  test('rejects a response for a different wallet', () => {
    const input = activeWalletSessionFixture({ walletId: 'returned-wallet' });

    expect(() => parseWalletSessionFromBoundary(input, 'requested-wallet')).toThrow(
      'does not match the requested wallet',
    );
  });

  test('rejects disagreement between app and reusable-session wallet identities', () => {
    const input = activeWalletSessionFixture({ walletId: 'canonical-wallet' });
    const corrupted = {
      ...input,
      reusableWalletSession: {
        ...input.reusableWalletSession,
        walletId: 'different-wallet',
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
        walletSessionId: 'iframe-wallet-session',
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

  test('preserves unavailable and invalid as distinct fail-closed exact states', () => {
    expect(exactSessionStateFromWalletSession(unavailableWalletSessionFixture())).toMatchObject({
      kind: 'wallet_unlocked_without_signing_session',
      reason: 'unavailable',
    });
    expect(exactSessionStateFromWalletSession(invalidWalletSessionFixture())).toMatchObject({
      kind: 'wallet_unlocked_without_signing_session',
      reason: 'invalid',
    });
    expect(exactSessionStateFromWalletSession(missingWalletSessionFixture())).toMatchObject({
      kind: 'wallet_unlocked_without_signing_session',
      walletId: 'wallet-session-fixture',
      authorizationId: 'wallet-session-authorization-fixture',
      walletSessionId: 'wallet-session-fixture',
      authMethod: 'passkey',
      reason: 'not_found',
    });
  });

  test('separates authenticated identity resolution failure from missing authorization', () => {
    const authenticated = activeWalletSessionFixture({ walletId: 'identity-wallet' });
    if (authenticated.authentication.kind !== 'authenticated') {
      throw new Error('Active Wallet Session fixture must be authenticated');
    }
    const unresolvedIdentity: WalletSession = {
      ...authenticated,
      appIdentity: {
        kind: 'unresolvable',
        walletId: authenticated.authentication.walletId,
        reason: 'missing_wallet_profile',
      },
      capabilityProjection: {
        kind: 'unresolvable',
        reason: 'missing_wallet_profile',
      },
    };

    expect(exactSessionStateFromWalletSession(unresolvedIdentity)).toEqual({
      kind: 'wallet_authenticated_identity_unresolvable',
      walletId: authenticated.authentication.walletId,
      reason: 'missing_wallet_profile',
    });
    expect(exactSessionStateFromWalletSession(missingWalletSessionFixture())).toMatchObject({
      kind: 'wallet_unlocked_without_signing_session',
      authorizationId: 'wallet-session-authorization-fixture',
      walletSessionId: 'wallet-session-fixture',
      authMethod: 'passkey',
      reason: 'not_found',
    });
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
