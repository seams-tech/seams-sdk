import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
  WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  assertMatchingVerifiedEcdsaPublicFacts,
  deriveEvmFamilySigningKeySlotId,
  deriveEvmFamilyKeyFingerprintFromPublicFacts,
  toVerifiedEcdsaPublicFactsFromDurableRecord,
  type EvmFamilyEcdsaKeyIdentity,
  type ThresholdEcdsaSessionId,
  type VerifiedEcdsaPublicFacts,
  type SigningGrantId,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type {
  AvailableEcdsaSigningLane,
  ConcreteAvailableEcdsaSigningLane,
} from '../../session/availability/availableSigningLanes';
import { isConcreteAvailableSigningLane } from '../../session/availability/availableSigningLanes';
import {
  deriveThresholdEcdsaRuntimeLaneKey,
  buildPersistedEcdsaRoleLocalMaterial,
  requirePersistedEcdsaRoleLocalMaterial,
  type PersistedEcdsaRoleLocalMaterial,
} from '../../session/persistence/records';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import {
  listExactSealedSessionsForWallet,
  type CurrentEcdsaSealedSessionRecord,
  type EcdsaReauthAnchorPublicRestore,
} from '../../session/persistence/sealedSessionStore';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import type { EvmFamilySigningTarget } from '../signEvmFamily/types';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { buildEcdsaRoleLocalPublicFacts } from '@/core/platform';
import { parseEcdsaRoleLocalPersistedMaterialRef } from '../../session/keyMaterialBrands';
import { resolveActiveEcdsaCapabilityRuntime } from '../../session/material/activeEcdsaCapabilityRuntime';
import {
  resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime,
  type EmailOtpEcdsaSigningSessionAuthority,
} from '../../session/emailOtp/ecdsaSigningSessionAuthority';

export type EcdsaExportMaterialAvailability =
  | { kind: 'loaded_worker_material' }
  | { kind: 'sealed_worker_material' }
  | { kind: 'material_pending'; reason: 'email_otp_route_auth' };

type ExactEcdsaExportSessionBase = {
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: 'email_otp' | 'passkey';
  material: EcdsaExportMaterialAvailability;
  ecdsaThresholdKeyId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  participantIds?: never;
  thresholdOwnerAddress?: never;
};

type CurrentExactEcdsaExportSession = ExactEcdsaExportSessionBase & {
  state: Exclude<ConcreteAvailableEcdsaSigningLane['state'], 'expired' | 'exhausted'>;
  source: Exclude<ConcreteAvailableEcdsaSigningLane['source'], 'durable_sealed_record'>;
  publicReauthAuthority?: never;
};

type PublicReauthExactEcdsaExportSession = ExactEcdsaExportSessionBase & {
  state: ConcreteAvailableEcdsaSigningLane['state'];
  source: 'durable_sealed_record';
  publicReauthAuthority: EcdsaReauthAnchorPublicRestore;
};

export type ExactEcdsaExportSession =
  | CurrentExactEcdsaExportSession
  | PublicReauthExactEcdsaExportSession;

export type ExactEcdsaExportLane = {
  curve: 'ecdsa';
  laneIdentity: ExactEcdsaSigningLaneIdentity;
  key: EvmFamilyEcdsaKeyIdentity;
  publicFacts: VerifiedEcdsaPublicFacts;
  session: ExactEcdsaExportSession;
};

export type EcdsaExportSessionStoreDeps = {
  exportArtifactsByLane: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
};

export type EmailOtpEcdsaExportAuthLane = Extract<
  EmailOtpSigningSessionAuthLane,
  { curve: 'ecdsa' }
>;

// The discriminated export operation authority. Mirrors the wire union: a
// reusable Wallet Session authorizes warm export; an explicit single-operation
// grant authorizes step-up export. Session and grant identifiers exist only
// inside this branch.
export type EcdsaExportOperationAuthorization =
  | { kind: 'reusable_wallet_session'; walletSessionId: string; grantId?: never }
  | { kind: 'operation_step_up'; grantId: string; walletSessionId?: never };

export type EmailOtpEcdsaPublicReauthExportAuthority = Extract<
  EcdsaReauthAnchorPublicRestore,
  { source: 'email_otp' }
>;

type FreshEmailOtpEcdsaWalletSessionExportAuthority = {
  kind: 'wallet_session_authorized';
  signingSessionAuthority: EmailOtpEcdsaSigningSessionAuthority;
  operationAuthorization: EcdsaExportOperationAuthorization;
  publicReauthAuthority?: never;
};

type FreshEmailOtpEcdsaPublicReauthExportAuthority = {
  kind: 'public_reauth_authority_backed';
  publicReauthAuthority: EmailOtpEcdsaPublicReauthExportAuthority;
  record?: never;
  authLane?: never;
  operationAuthorization?: never;
};

export type FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready';
  chainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  authorization:
    | FreshEmailOtpEcdsaWalletSessionExportAuthority
    | FreshEmailOtpEcdsaPublicReauthExportAuthority;
  record?: never;
  authLane?: never;
};

export type FreshPasskeyEcdsaExportMaterial = {
  kind: 'fresh_passkey_needs_authorization';
  chainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
  bootstrap: PasskeyEcdsaExportBootstrapContext;
};

export type PasskeyEcdsaExportBootstrapContext = {
  source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  relayerUrl: string;
  relayerKeyId: string;
  ecdsaThresholdKeyId: string;
  evmFamilySigningKeySlotId: string;
  signingRootId: string;
  signingRootVersion: string;
  participantIds: readonly number[];
};

export type EcdsaExportMaterial =
  | FreshEmailOtpEcdsaExportMaterial
  | FreshPasskeyEcdsaExportMaterial;

export function ecdsaExportBoundaryChain(lane: ExactEcdsaExportLane): 'evm' | 'tempo' {
  return lane.session.chainTarget.kind;
}

export function ecdsaSigningTargetFromChainTarget(
  chainTarget: ThresholdEcdsaChainTarget,
): EvmFamilySigningTarget {
  return chainTarget;
}

export function isConcreteEcdsaExportLane(
  lane: AvailableEcdsaSigningLane | null | undefined,
): lane is ConcreteAvailableEcdsaSigningLane & {
  source: 'canonical_capability';
  authorization: NonNullable<ConcreteAvailableEcdsaSigningLane['authorization']>;
} {
  return (
    Boolean(lane) &&
    lane!.curve === 'ecdsa' &&
    Boolean(lane!.chainTarget) &&
    isConcreteAvailableSigningLane(lane!) &&
    lane!.source === 'canonical_capability' &&
    Boolean(lane!.authorization) &&
    Boolean(String(lane!.publicFacts.keyHandle || '').trim())
  );
}

export function ecdsaExportOperationAuthorizationForLane(
  exportLane: ExactEcdsaExportLane,
): EcdsaExportOperationAuthorization {
  return {
    kind: 'reusable_wallet_session',
    walletSessionId: String(
      exportLane.laneIdentity.authorization.projection.walletSessionId,
    ),
  };
}

export async function resolveExactSealedEcdsaExportRecordForLane(
  exportLane: ExactEcdsaExportLane,
): Promise<CurrentEcdsaSealedSessionRecord> {
  const matches = (
    await listExactSealedSessionsForWallet({
      walletId: String(exportLane.key.walletId),
      filter: {
        authMethod: exportLane.session.authMethod,
        curve: 'ecdsa',
        chainTarget: exportLane.session.chainTarget,
      },
    })
  ).filter((record): record is CurrentEcdsaSealedSessionRecord => {
    if (record.curve !== 'ecdsa' || !record.ecdsaRestore) return false;
    const sealedWalletId = String(record.walletId || '').trim();
    const sealedKeyHandle = String(record.ecdsaRestore?.keyHandle || '').trim();
    if (
      sealedWalletId !== String(exportLane.key.walletId) ||
      sealedKeyHandle !== String(exportLane.publicFacts.keyHandle)
    ) {
      return false;
    }
    // Durable material identity: the sealed restore must reference the exact
    // material activation the lane names. Session and grant identifiers no
    // longer participate in sealed-record matching.
    try {
      return mpcMaterialActivationRefsEqual(
        parseEcdsaRoleLocalPersistedMaterialRef(record.ecdsaRestore.roleLocalMaterialRef)
          .materialActivation,
        exportLane.laneIdentity.signer.materialActivation,
      );
    } catch {
      return false;
    }
  });
  if (matches.length !== 1) {
    throw new Error(
      `[SigningEngine][ecdsa-export] exact sealed export lane not found for ${ecdsaExportBoundaryChain(exportLane)} ${exportLane.session.authMethod}`,
    );
  }
  return matches[0];
}

function requirePasskeyEcdsaExportField(value: unknown, label: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`[SigningEngine][ecdsa-export] passkey export requires ${label}`);
  }
  return normalized;
}

function requirePasskeyEcdsaExportParticipants(
  participantIds: readonly number[],
): readonly number[] {
  if (
    participantIds.length === 0 ||
    participantIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || participantId < 1,
    )
  ) {
    throw new Error('[SigningEngine][ecdsa-export] passkey export participants are invalid');
  }
  return [...participantIds];
}

function passkeyEcdsaExportBootstrapFromSealedRecord(
  record: CurrentEcdsaSealedSessionRecord,
  exportLane: ExactEcdsaExportLane,
): PasskeyEcdsaExportBootstrapContext {
  const restore = record.ecdsaRestore;
  if (restore.source === 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] durable passkey export source is invalid');
  }
  return {
    source: restore.source,
    relayerUrl: requirePasskeyEcdsaExportField(record.relayerUrl, 'relayerUrl'),
    relayerKeyId: requirePasskeyEcdsaExportField(restore.relayerKeyId, 'relayerKeyId'),
    ecdsaThresholdKeyId: requirePasskeyEcdsaExportField(
      restore.ecdsaThresholdKeyId || exportLane.key.ecdsaThresholdKeyId,
      'ecdsaThresholdKeyId',
    ),
    evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
      walletId: exportLane.key.walletId,
      signingRootId: restore.signingRootId,
      signingRootVersion: restore.signingRootVersion,
    }),
    signingRootId: requirePasskeyEcdsaExportField(restore.signingRootId, 'signingRootId'),
    signingRootVersion: requirePasskeyEcdsaExportField(
      restore.signingRootVersion,
      'signingRootVersion',
    ),
    participantIds: requirePasskeyEcdsaExportParticipants(restore.participantIds),
  };
}

function emailOtpPublicReauthAuthorityForExportLane(
  exportLane: ExactEcdsaExportLane,
): EmailOtpEcdsaPublicReauthExportAuthority | null {
  if (exportLane.session.source !== 'durable_sealed_record') return null;
  const authority = exportLane.session.publicReauthAuthority;
  if (authority.source !== 'email_otp') {
    throw new Error(
      '[SigningEngine][ecdsa-export] Email OTP public reauth lane has non-Email-OTP authority',
    );
  }
  return authority;
}

async function verifiedEcdsaPublicFactsFromPublicReauthAuthority(
  authority: EmailOtpEcdsaPublicReauthExportAuthority,
): Promise<VerifiedEcdsaPublicFacts> {
  return await toVerifiedEcdsaPublicFactsFromDurableRecord({
    record: {
      ecdsaRestore: {
        keyHandle: authority.keyHandle,
        thresholdEcdsaPublicKeyB64u: authority.thresholdEcdsaPublicKeyB64u,
        participantIds: authority.participantIds,
        ethereumAddress: authority.ethereumAddress,
      },
    },
  });
}

export async function resolveFreshEmailOtpEcdsaExportMaterialForLane(
  _deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): Promise<FreshEmailOtpEcdsaExportMaterial> {
  if (exportLane.session.authMethod !== 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] fresh Email OTP export requires Email OTP lane');
  }
  const publicReauthAuthority = emailOtpPublicReauthAuthorityForExportLane(exportLane);
  if (!publicReauthAuthority) {
    const resolution = await resolveActiveEcdsaCapabilityRuntime({
      walletId: exportLane.key.walletId,
      chainTarget: exportLane.session.chainTarget,
    });
    if (resolution.kind !== 'resolved') {
      throw new Error(
        `[SigningEngine][ecdsa-export] Email OTP capability runtime unavailable: ${resolution.reason}`,
      );
    }
    if (
      !mpcMaterialActivationRefsEqual(
        resolution.runtime.materialActivation,
        exportLane.laneIdentity.signer.materialActivation,
      )
    ) {
      throw new Error('[SigningEngine][ecdsa-export] Email OTP material activation mismatch');
    }
    const authority = resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime({
      runtime: resolution.runtime,
      authorization: exportLane.laneIdentity.authorization.projection,
    });
    if (authority.kind !== 'ready') {
      throw new Error(
        `[SigningEngine][ecdsa-export] Email OTP signing-session authority unavailable: ${authority.kind}`,
      );
    }
    const runtimePolicyScope = resolution.runtime.runtimePolicyScope;
    if (!runtimePolicyScope) {
      throw new Error('[SigningEngine][ecdsa-export] Email OTP runtime policy scope is missing');
    }
    return {
      kind: 'fresh_email_otp_route_auth_ready',
      chainTarget: exportLane.session.chainTarget,
      publicFacts: exportLane.publicFacts,
      runtimePolicyScope,
      authorization: {
        kind: 'wallet_session_authorized',
        signingSessionAuthority: authority.authority,
        operationAuthorization: ecdsaExportOperationAuthorizationForLane(exportLane),
      },
    };
  }
  if (publicReauthAuthority) {
    const publicFacts =
      await verifiedEcdsaPublicFactsFromPublicReauthAuthority(publicReauthAuthority);
    assertMatchingVerifiedEcdsaPublicFacts({
      expected: exportLane.publicFacts,
      actual: publicFacts,
      context: 'fresh Email OTP export lane',
    });
    return {
      kind: 'fresh_email_otp_route_auth_ready',
      chainTarget: exportLane.session.chainTarget,
      publicFacts,
      runtimePolicyScope: publicReauthAuthority.runtimePolicyScope,
      authorization: {
        kind: 'public_reauth_authority_backed',
        publicReauthAuthority,
      },
    };
  }
  // No exact runtime record and no public reauth anchor: the sealed
  // signing-session authority inference is deleted. Export requires either an
  // active wallet-session-authorized lane or the public reauth path.
  throw new Error(
    '[SigningEngine][ecdsa-export] Email OTP export requires an authorized lane or public reauth authority',
  );
}

export async function resolveEcdsaExportMaterialForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): Promise<EcdsaExportMaterial> {
  if (exportLane.session.authMethod === 'email_otp') {
    return await resolveFreshEmailOtpEcdsaExportMaterialForLane(deps, exportLane);
  }
  const durableAuthority =
    exportLane.session.source === 'durable_sealed_record'
      ? exportLane.session.publicReauthAuthority
      : null;
  const sealedRecord = durableAuthority
    ? null
    : await resolveExactSealedEcdsaExportRecordForLane(exportLane);
  const restore = durableAuthority || sealedRecord?.ecdsaRestore;
  const relayerUrl = durableAuthority?.relayerUrl || sealedRecord?.relayerUrl;
  if (!restore || restore.source === 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] durable passkey export authority is invalid');
  }
  const publicFacts = await toVerifiedEcdsaPublicFactsFromDurableRecord({
    record: {
      ecdsaRestore: {
        keyHandle: restore.keyHandle,
        thresholdEcdsaPublicKeyB64u: restore.thresholdEcdsaPublicKeyB64u,
        participantIds: restore.participantIds,
        ethereumAddress: restore.ethereumAddress,
      },
    },
  });
  assertMatchingVerifiedEcdsaPublicFacts({
    expected: exportLane.publicFacts,
    actual: publicFacts,
    context: 'durable passkey export lane',
  });
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(restore.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error(
      '[SigningEngine][ecdsa-export] durable passkey export requires runtimePolicyScope',
    );
  }
  return {
    kind: 'fresh_passkey_needs_authorization',
    chainTarget: exportLane.session.chainTarget,
    publicFacts,
    runtimePolicyScope,
    publicCapability: restore.publicCapability,
    existingRoleLocalMaterial: buildPersistedEcdsaRoleLocalMaterial({
      authority: restore.authority,
      materialActivation: parseEcdsaRoleLocalPersistedMaterialRef(
        restore.roleLocalMaterialRef,
      ).materialActivation,
      publicFacts: buildEcdsaRoleLocalPublicFacts({
        walletId: exportLane.key.walletId,
        evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
          walletId: exportLane.key.walletId,
          signingRootId: restore.signingRootId,
          signingRootVersion: restore.signingRootVersion,
        }),
        chainTarget: exportLane.session.chainTarget,
        keyHandle: restore.keyHandle,
        ecdsaThresholdKeyId: restore.ecdsaThresholdKeyId,
        signingRootId: restore.signingRootId,
        signingRootVersion: restore.signingRootVersion,
        applicationBindingDigestB64u:
          restore.publicCapability.context.application_binding_digest_b64u,
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds: restore.participantIds,
        contextBinding32B64u:
          restore.publicCapability.public_identity.context_binding_b64u,
        derivationClientSharePublicKey33B64u:
          restore.publicCapability.public_identity
            .derivation_client_share_public_key33_b64u,
        relayerPublicKey33B64u:
          restore.publicCapability.public_identity.server_public_key33_b64u,
        groupPublicKey33B64u:
          restore.publicCapability.public_identity.threshold_public_key33_b64u,
        ethereumAddress: restore.ethereumAddress,
        publicCapability: restore.publicCapability,
      }),
    }),
    bootstrap: {
      source: restore.source,
      relayerUrl: requirePasskeyEcdsaExportField(relayerUrl, 'relayerUrl'),
      relayerKeyId: requirePasskeyEcdsaExportField(restore.relayerKeyId, 'relayerKeyId'),
      ecdsaThresholdKeyId: requirePasskeyEcdsaExportField(
        restore.ecdsaThresholdKeyId || exportLane.key.ecdsaThresholdKeyId,
        'ecdsaThresholdKeyId',
      ),
      evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
        walletId: exportLane.key.walletId,
        signingRootId: restore.signingRootId,
        signingRootVersion: restore.signingRootVersion,
      }),
      signingRootId: requirePasskeyEcdsaExportField(restore.signingRootId, 'signingRootId'),
      signingRootVersion: requirePasskeyEcdsaExportField(
        restore.signingRootVersion,
        'signingRootVersion',
      ),
      participantIds: requirePasskeyEcdsaExportParticipants(restore.participantIds),
    },
  };
}
import type { ThresholdEcdsaCanonicalExportArtifact } from '../../interfaces/signing';
