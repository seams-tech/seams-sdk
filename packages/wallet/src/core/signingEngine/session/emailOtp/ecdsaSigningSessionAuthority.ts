import {
  isEmailOtpWalletAuthAuthority,
  walletAuthAuthoritiesMatch,
  walletAuthAuthorityRef,
  type EmailOtpWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { type EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ExactEcdsaSealedRuntime } from '../material/ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from '../material/ecdsaCapabilityManifest';
import type { CanonicalEvmFamilyEcdsaSigningCapability } from '../material/ecdsaSigningCapability';
import {
  walletSessionThresholdSessionIdForCurve,
  walletSessionTokenForCurve,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  resolveExactWalletAuthAuthority,
  type OwnerLaneScopeStores,
} from '../identity/ownerLaneScope';
import { readEmailOtpProviderSubjectForWalletV1 } from '../../threshold/ed25519/yaoPublicCapabilityReferences';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type EmailOtpEcdsaSigningSessionAuthority = {
  authLane: Extract<EmailOtpAuthLane, { kind: 'signing_session'; curve: 'ecdsa' }>;
  authority: EmailOtpWalletAuthAuthority;
};

async function getEmailOtpSigningSessionWalletAuthMethod(walletAuthMethodId: string) {
  return await IndexedDBManager.getWalletAuthMethodV2(walletAuthMethodId);
}

async function listEmailOtpSigningSessionWalletAuthMethods(walletId: string) {
  return await IndexedDBManager.listWalletAuthMethodsForWallet(walletId);
}

async function getEmailOtpSigningSessionPasskeyAuthenticator(args: {
  readonly walletId: string;
  readonly credentialId: string;
}) {
  return await IndexedDBManager.getWalletPasskeyAuthenticator(args);
}

async function readEmailOtpSigningSessionProviderSubject(walletId: string) {
  return await readEmailOtpProviderSubjectForWalletV1(IndexedDBManager, walletId);
}

const emailOtpSigningSessionFactorStores: OwnerLaneScopeStores = {
  getWalletAuthMethodV2: getEmailOtpSigningSessionWalletAuthMethod,
  listWalletAuthMethodsForWallet: listEmailOtpSigningSessionWalletAuthMethods,
  getWalletPasskeyAuthenticator: getEmailOtpSigningSessionPasskeyAuthenticator,
  readEmailOtpProviderSubjectForWallet: readEmailOtpSigningSessionProviderSubject,
};

export function buildEmailOtpEcdsaSigningSessionAuthority(args: {
  authLane: EmailOtpAuthLane | null | undefined;
  authority: EmailOtpWalletAuthAuthority;
}): EmailOtpEcdsaSigningSessionAuthority | null {
  const authLane = args.authLane;
  if (authLane?.kind !== 'signing_session' || authLane.curve !== 'ecdsa') return null;
  return {
    authLane,
    authority: args.authority,
  };
}

export type EmailOtpEcdsaSigningSessionAuthorityResolution =
  | {
      kind: 'ready';
      authority: EmailOtpEcdsaSigningSessionAuthority;
    }
  | {
      kind: 'record_missing';
      authority?: never;
    }
  | {
      kind: 'wallet_session_auth_unavailable';
      reason: 'cookie_session' | 'missing_wallet_session_token';
      authority?: never;
    }
  | {
      kind: 'missing_session_identity';
      authority?: never;
    }
  | {
      kind: 'authority_not_ecdsa_signing_session';
      authority?: never;
    };

/**
 * The sealed runtime and capability manifest identify the material and Email
 * OTP authority. The selected authority and exact Wallet Session record must
 * reproduce that tuple before the signing-session lane can be built.
 */
export async function resolveExactEmailOtpEcdsaSigningSessionAuthority(args: {
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly runtime: ExactEcdsaSealedRuntime;
}): Promise<EmailOtpEcdsaSigningSessionAuthority | null> {
  if (
    args.runtime.kind !== 'exact_ecdsa_sealed_runtime_v1' ||
    args.runtime.walletId !== args.walletId ||
    !thresholdEcdsaChainTargetsEqual(args.runtime.chainTarget, args.chainTarget) ||
    !mpcMaterialActivationRefsEqual(
      args.runtime.materialActivation,
      args.manifest.activation.materialActivation,
    ) ||
    args.manifest.signer.walletId !== args.walletId
  ) {
    return null;
  }
  if (args.runtime.authBinding.kind !== 'email_otp') return null;

  let runtimeAuthorityRef: Awaited<ReturnType<typeof walletAuthAuthorityRef>>;
  try {
    runtimeAuthorityRef = await walletAuthAuthorityRef({
      authority: args.runtime.authBinding.emailOtpAuthority,
    });
  } catch {
    return null;
  }
  const manifestAuthorityRef = args.manifest.signer.authority;
  if (
    runtimeAuthorityRef.walletId !== args.walletId ||
    runtimeAuthorityRef.walletAuthMethodId !== manifestAuthorityRef.walletAuthMethodId ||
    runtimeAuthorityRef.authorityDigest !== manifestAuthorityRef.authorityDigest ||
    manifestAuthorityRef.walletId !== args.walletId
  ) {
    return null;
  }

  let selected: Awaited<ReturnType<typeof IndexedDBManager.resolveSelectedWalletAuthority>>;
  try {
    selected = await IndexedDBManager.resolveSelectedWalletAuthority(String(args.walletId));
  } catch {
    return null;
  }
  if (selected.kind !== 'resolved') return null;
  const { selection, authMethod, authority } = selected;
  const ecdsaActivation = authority.signerActivations.ecdsa;
  if (
    selection.lockState !== 'unlocked' ||
    selection.walletId !== args.walletId ||
    authMethod.kind !== 'email_otp' ||
    authMethod.status !== 'active' ||
    authMethod.walletId !== args.walletId ||
    authority.state !== 'active' ||
    authority.walletId !== args.walletId ||
    selection.walletAuthMethodId !== authMethod.walletAuthMethodId ||
    authMethod.walletAuthorityId !== authority.authorityId ||
    authMethod.walletAuthMethodId !== runtimeAuthorityRef.walletAuthMethodId ||
    !ecdsaActivation ||
    ecdsaActivation.signer.walletId !== args.walletId ||
    !mpcMaterialActivationRefsEqual(
      ecdsaActivation.materialActivation,
      args.runtime.materialActivation,
    )
  ) {
    return null;
  }

  let selectedFactorAuthority: WalletAuthAuthority;
  try {
    selectedFactorAuthority = await resolveExactWalletAuthAuthority({
      authMethod,
      stores: emailOtpSigningSessionFactorStores,
    });
  } catch {
    return null;
  }
  if (
    !walletAuthAuthoritiesMatch(selectedFactorAuthority, args.runtime.authBinding.emailOtpAuthority)
  ) {
    return null;
  }

  let authorizationRead: Awaited<
    ReturnType<typeof walletSessionAuthorizations.readExactWithOperationCredential>
  >;
  try {
    authorizationRead = await walletSessionAuthorizations.readExactWithOperationCredential({
      walletId: args.walletId,
      authorityId: authority.authorityId,
      authMethodId: authMethod.walletAuthMethodId,
    });
  } catch {
    return null;
  }
  if (authorizationRead.kind !== 'found') return null;
  const { record, operationCredential } = authorizationRead;
  if (
    record.walletId !== args.walletId ||
    record.authorityId !== authority.authorityId ||
    record.authMethodId !== authMethod.walletAuthMethodId ||
    record.authorityDigestB64u !== authority.authorityDigestB64u ||
    record.authorityRevocationEpoch !== authority.revocationEpoch ||
    record.expiresAtMs <= Date.now() ||
    operationCredential.walletSessionId.trim().length === 0 ||
    operationCredential.token.trim().length === 0
  ) {
    return null;
  }
  const signSubjects = record.capabilitySubjects.filter(
    (subject) =>
      subject.kind === 'sign' &&
      subject.keyFamily === 'ecdsa_secp256k1' &&
      mpcMaterialActivationRefsEqual(subject.materialActivation, args.runtime.materialActivation),
  );
  if (signSubjects.length !== 1) return null;

  return buildEmailOtpEcdsaSigningSessionAuthority({
    authority: args.runtime.authBinding.emailOtpAuthority,
    authLane: {
      kind: 'signing_session',
      walletSessionToken: operationCredential.token,
      thresholdSessionId: args.runtime.sealedRecord.thresholdSessionId,
      curve: 'ecdsa',
      chainTarget: args.runtime.chainTarget,
    },
  });
}

/**
 * Registration establishes the canonical capability and a reusable Wallet
 * Session before any Email OTP sealed session exists. The Wallet Session token
 * carries the threshold-session identity needed by the signing-session route;
 * the capability carries the Email OTP authority. Keep this path separate from
 * sealed-runtime resolution so a missing sealed record cannot hide a usable
 * post-registration lane.
 */
export function resolveEmailOtpEcdsaSigningSessionAuthorityFromCapability(args: {
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  authorization: ActiveWalletSessionAuthorizationProjection;
  chainTarget: ThresholdEcdsaChainTarget;
}): EmailOtpEcdsaSigningSessionAuthorityResolution {
  const capabilityAuthority = args.capability.authority;
  if (!isEmailOtpWalletAuthAuthority(capabilityAuthority)) {
    return { kind: 'record_missing' };
  }
  const signer = args.capability.manifest.signer;
  if (
    signer.walletId !== args.authorization.walletId ||
    signer.authority.authorityDigest !== args.authorization.authority.authorityDigest ||
    !signer.scope.targetMemberships.some((target) =>
      thresholdEcdsaChainTargetsEqual(target, args.chainTarget),
    ) ||
    args.capability.material.publicFacts.walletId !== signer.walletId
  ) {
    return { kind: 'record_missing' };
  }
  const walletSessionToken = walletSessionTokenForCurve(args.authorization, 'ecdsa');
  if (!walletSessionToken) {
    return { kind: 'wallet_session_auth_unavailable', reason: 'missing_wallet_session_token' };
  }
  const thresholdSessionId = walletSessionThresholdSessionIdForCurve(args.authorization, 'ecdsa');
  if (!thresholdSessionId) return { kind: 'missing_session_identity' };
  const authority = buildEmailOtpEcdsaSigningSessionAuthority({
    authority: capabilityAuthority,
    authLane: {
      kind: 'signing_session',
      walletSessionToken,
      thresholdSessionId,
      curve: 'ecdsa',
      chainTarget: args.chainTarget,
    },
  });
  return authority ? { kind: 'ready', authority } : { kind: 'authority_not_ecdsa_signing_session' };
}
