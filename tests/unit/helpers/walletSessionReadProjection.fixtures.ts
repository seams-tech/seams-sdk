import type { WalletSession, WalletSessionAppIdentity } from '@/core/types/seams';
import { toAccountId } from '@/core/types/accountIds';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  NonceLeaseState,
  type NonceCoordinatorDiagnostics,
} from '@/core/signingEngine/nonce/NonceCoordinator';
import { parseEcdsaThresholdKeyId } from '@/core/signingEngine/session/keyMaterialBrands';
import type { EvmFamilyEcdsaWalletUnlockSubject } from '@/core/signingEngine/session/identity/walletUnlockSubject';
import {
  parseCapabilityInstanceRef,
  parseWalletAuthorityBindingDigest,
} from '@shared/utils/domainIds';
import {
  parseWalletSessionId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { WalletAuthMethod } from '@shared/utils/signerDomain';
import {
  buildPasskeyAuthScope,
  buildPasskeyWalletAuthMethodBinding,
  buildWalletIdentity,
  parseRpId,
  type WalletAuthMethodBinding,
} from '@shared/utils/walletCapabilityBindings';
import { walletIdFromString, type WalletId } from '@shared/utils/registrationIntent';

type ResolvedWalletSessionAppIdentity = Extract<WalletSessionAppIdentity, { kind: 'resolved' }>;

export type ResolvedWalletSessionAppIdentityFixtureInput = {
  readonly walletId?: string;
  readonly nearAccountId?: string | null;
  readonly nearOperationalPublicKey?: string | null;
  readonly userData?: ResolvedWalletSessionAppIdentity['userData'];
  readonly authMethods?: readonly WalletAuthMethodBinding[];
  readonly thresholdEcdsaEthereumAddress?: string | null;
  readonly thresholdEcdsaPublicKeyB64u?: string | null;
};

export type ReusableWalletSessionFixtureInput = ResolvedWalletSessionAppIdentityFixtureInput & {
  readonly walletSessionId?: string;
  readonly authMethod?: WalletAuthMethod;
  readonly expiresAtMs?: number;
};

function defaultPasskeyBinding(walletId: WalletId): WalletAuthMethodBinding {
  const rpId = parseRpId('wallet.example.localhost');
  if (!rpId.ok) throw new Error('Wallet Session fixture rpId must be valid');
  return buildPasskeyWalletAuthMethodBinding({
    scope: buildPasskeyAuthScope({
      wallet: buildWalletIdentity({ walletId }),
      rpId: rpId.value,
    }),
    credentialIdB64u: 'wallet-session-fixture-credential',
  });
}

export function resolvedWalletSessionAppIdentityFixture(
  input: ResolvedWalletSessionAppIdentityFixtureInput = {},
): ResolvedWalletSessionAppIdentity {
  const walletId = fixtureWalletId(input.walletId);
  return {
    kind: 'resolved',
    walletId,
    nearAccountId:
      input.nearAccountId === null ? null : toAccountId(input.nearAccountId || 'alice.testnet'),
    nearOperationalPublicKey:
      input.nearOperationalPublicKey === undefined
        ? 'ed25519:wallet-session-fixture'
        : input.nearOperationalPublicKey,
    userData: input.userData ?? null,
    authMethods: input.authMethods ?? [defaultPasskeyBinding(walletId)],
    thresholdEcdsaEthereumAddress: input.thresholdEcdsaEthereumAddress ?? null,
    thresholdEcdsaPublicKeyB64u: input.thresholdEcdsaPublicKeyB64u ?? null,
  };
}

export function activeWalletSessionFixture(
  input: ReusableWalletSessionFixtureInput & {
    readonly remainingUses?: number;
  } = {},
): WalletSession {
  const appIdentity = resolvedWalletSessionAppIdentityFixture(input);
  return {
    appIdentity,
    reusableWalletSession: {
      kind: 'active',
      walletId: appIdentity.walletId,
      walletSessionId: fixtureWalletSessionId(input.walletSessionId),
      authMethod: input.authMethod ?? 'passkey',
      remainingUses: input.remainingUses ?? 3,
      expiresAtMs: input.expiresAtMs ?? Date.now() + 60_000,
    },
    capabilityProjection: { kind: 'not_requested' },
    nonceDiagnostics: null,
  };
}

export function activeWalletSessionWithNonceDiagnosticsFixture(
  input: ReusableWalletSessionFixtureInput = {},
): WalletSession {
  const active = activeWalletSessionFixture(input);
  return {
    appIdentity: active.appIdentity,
    reusableWalletSession: active.reusableWalletSession,
    capabilityProjection: active.capabilityProjection,
    nonceDiagnostics: walletSessionNonceDiagnosticsFixture(),
  };
}

export function exhaustedWalletSessionFixture(
  input: ReusableWalletSessionFixtureInput = {},
): WalletSession {
  const appIdentity = resolvedWalletSessionAppIdentityFixture(input);
  return {
    appIdentity,
    reusableWalletSession: {
      kind: 'exhausted',
      walletId: appIdentity.walletId,
      walletSessionId: fixtureWalletSessionId(input.walletSessionId),
      authMethod: input.authMethod ?? 'passkey',
      remainingUses: 0,
      expiresAtMs: input.expiresAtMs ?? Date.now() + 60_000,
    },
    capabilityProjection: { kind: 'not_requested' },
    nonceDiagnostics: null,
  };
}

export function expiredWalletSessionFixture(
  input: ReusableWalletSessionFixtureInput & {
    readonly detectedAtMs?: number;
  } = {},
): WalletSession {
  const appIdentity = resolvedWalletSessionAppIdentityFixture(input);
  const detectedAtMs = input.detectedAtMs ?? Date.now();
  return {
    appIdentity,
    reusableWalletSession: {
      kind: 'expired',
      walletId: appIdentity.walletId,
      walletSessionId: fixtureWalletSessionId(input.walletSessionId),
      authMethod: input.authMethod ?? 'passkey',
      expiresAtMs: input.expiresAtMs ?? detectedAtMs - 1,
      detectedAtMs,
    },
    capabilityProjection: { kind: 'not_requested' },
    nonceDiagnostics: null,
  };
}

export function missingWalletSessionFixture(
  input: ResolvedWalletSessionAppIdentityFixtureInput = {},
): WalletSession {
  const appIdentity = resolvedWalletSessionAppIdentityFixture(input);
  return {
    appIdentity,
    reusableWalletSession: {
      kind: 'missing',
      walletId: appIdentity.walletId,
    },
    capabilityProjection: { kind: 'not_requested' },
    nonceDiagnostics: null,
  };
}

export function unavailableWalletSessionFixture(
  input: ResolvedWalletSessionAppIdentityFixtureInput = {},
): WalletSession {
  const appIdentity = resolvedWalletSessionAppIdentityFixture(input);
  return {
    appIdentity,
    reusableWalletSession: {
      kind: 'unavailable',
      walletId: appIdentity.walletId,
      reason: 'persistence_unavailable',
    },
    capabilityProjection: { kind: 'not_requested' },
    nonceDiagnostics: null,
  };
}

export function invalidWalletSessionFixture(
  input: ResolvedWalletSessionAppIdentityFixtureInput = {},
): WalletSession {
  const appIdentity = resolvedWalletSessionAppIdentityFixture(input);
  return {
    appIdentity,
    reusableWalletSession: {
      kind: 'invalid',
      walletId: appIdentity.walletId,
      reason: 'malformed',
    },
    capabilityProjection: { kind: 'not_requested' },
    nonceDiagnostics: null,
  };
}

export function restorableEcdsaWalletSessionFixture(
  input: ReusableWalletSessionFixtureInput = {},
): WalletSession {
  const active = activeWalletSessionFixture(input);
  if (active.appIdentity.kind !== 'resolved') {
    throw new Error('Active Wallet Session fixture must resolve app identity');
  }
  const walletId = active.appIdentity.walletId;
  const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId('ecdsa-wallet-session-fixture');
  const capability = parseCapabilityInstanceRef('ecdsa-wallet-session-capability-fixture');
  const authorityDigest = parseWalletAuthorityBindingDigest(
    'ecdsa-wallet-session-authority-fixture',
  );
  if (!capability.ok) throw new Error('ECDSA capability fixture ID must be valid');
  if (!authorityDigest.ok) throw new Error('ECDSA authority fixture digest must be valid');
  const subject: EvmFamilyEcdsaWalletUnlockSubject = {
    kind: 'evm_family_ecdsa_wallet',
    walletId,
    capability: capability.value,
    authority: {
      kind: 'wallet_auth_authority_ref',
      walletId,
      authorityDigest: authorityDigest.value,
    },
    ecdsaThresholdKeyId,
  };
  return {
    appIdentity: active.appIdentity,
    reusableWalletSession: active.reusableWalletSession,
    capabilityProjection: {
      kind: 'resolved',
      subjectSet: {
        kind: 'wallet_unlock_subject_set',
        walletId,
        subjects: [subject],
      },
      capabilities: [
        {
          kind: 'evm_family_ecdsa',
          subject,
          targets: {
            kind: 'configured_targets',
            lanes: [
              {
                chainTarget: thresholdEcdsaChainTargetFromChainFamily({
                  chain: 'evm',
                  chainId: 1,
                }),
                readiness: {
                  kind: 'restorable',
                },
              },
            ],
          },
        },
      ],
    },
    nonceDiagnostics: active.nonceDiagnostics,
  };
}

export function anonymousWalletSessionFixture(): WalletSession {
  return {
    appIdentity: { kind: 'anonymous' },
    reusableWalletSession: { kind: 'not_requested' },
    capabilityProjection: { kind: 'not_requested' },
    nonceDiagnostics: null,
  };
}

function fixtureWalletId(value?: string): WalletId {
  return walletIdFromString(value || 'wallet-session-fixture');
}

function fixtureWalletSessionId(value?: string): WalletSessionId {
  const parsed = parseWalletSessionId(value || 'wallet-session-fixture');
  if (!parsed.ok) {
    throw new Error(`invalid Wallet Session fixture id: ${value}`);
  }
  return parsed.value;
}

function walletSessionNonceDiagnosticsFixture(): NonceCoordinatorDiagnostics {
  const leasesByState = {
    [NonceLeaseState.Reserved]: 0,
    [NonceLeaseState.Released]: 0,
    [NonceLeaseState.Expired]: 0,
    [NonceLeaseState.Signed]: 0,
    [NonceLeaseState.SignedLeaseExpired]: 0,
    [NonceLeaseState.BroadcastAccepted]: 0,
    [NonceLeaseState.BroadcastRejected]: 0,
    [NonceLeaseState.Finalized]: 0,
    [NonceLeaseState.Dropped]: 0,
    [NonceLeaseState.Replaced]: 0,
    [NonceLeaseState.Reconciled]: 0,
  };
  return {
    leaseCount: 0,
    leasesByState,
    laneCount: 0,
    metrics: {
      atMs: 1,
      leaseCount: 0,
      laneCount: 0,
      oldestLeaseAgeMs: 0,
      oldestInFlightLeaseAgeMs: 0,
      staleInFlightLeaseCount: 0,
      staleInFlightLaneCount: 0,
      reservedLeaseCount: 0,
      signedLeaseCount: 0,
      broadcastAcceptedLeaseCount: 0,
      droppedLeaseCount: 0,
      replacedLeaseCount: 0,
      reconciledLeaseCount: 0,
      releasedLeaseCount: 0,
      outcomes: {
        droppedCount: 0,
        replacedCount: 0,
        reconciledCount: 0,
        releasedCount: 0,
        expiredCount: 0,
        broadcastRejectedCount: 0,
        releaseReasons: {},
        reconcileReasons: {},
        expiryReasons: {},
      },
    },
    coordinationWarnings: [],
    lanes: [],
    near: {
      hasContext: false,
      reservedNonceCount: 0,
    },
  };
}
