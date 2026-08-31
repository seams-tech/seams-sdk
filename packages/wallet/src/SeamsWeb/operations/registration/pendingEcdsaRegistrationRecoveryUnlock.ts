import { joinCustodyJsonFromEstablishedCommitPayload } from '@/core/signingEngine/walletCustody/registrationCeremony';
import { buildFreshEmailOtpRoutePlan } from '@/core/signingEngine/session/emailOtp/routePlan';
import { unlockEmailOtpWallet } from '@/core/signingEngine/session/emailOtp/walletUnlock';
import { DEFAULT_THRESHOLD_SESSION_POLICY } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  verifyPasskeyWalletUnlock,
  type PasskeySessionEcdsaCustodySignerV1,
  type PasskeyWalletUnlockInputWithEcdsaActivation,
} from '@/core/rpcClients/near/rpcCalls';
import type { WalletRegistrationEcdsaWalletKey } from '@/core/rpcClients/relayer/walletRegistration';
import type { ActiveWalletSessionV1 } from '@shared/device-linking';
import { parseWalletSessionMintId } from '@shared/authorization/capabilityKinds';
import { parseThresholdEcdsaSessionId } from '@shared/utils/domainIds';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  type RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { base64UrlDecode } from '@shared/utils/base64';
import { alphabetizeStringify } from '@shared/utils/digests';
import { generateSessionId } from '@/core/signingEngine/session/passkey/prfCache';
import {
  toWalletId,
  thresholdEcdsaChainTargetKey,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  passkeyCredentialIdB64uFromAuthentication,
  requirePasskeyPrfFirstB64u,
} from '@/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';
import { WALLET_EMAIL_OTP_UNLOCK_OPERATION } from '@shared/utils/emailOtpDomain';
import type {
  CommittedEcdsaRegistrationResponse,
  PendingEcdsaOnlyRegistrationCommit,
  PendingEcdsaRegistrationUnlockInput,
  PendingEcdsaRegistrationUnlockMaterial,
  PendingRegistrationExactMethod,
  PendingRegistrationRecoverySigningSurface,
} from './pendingEcdsaRegistrationRecoveryValidation';
import { requireEcdsaProjection } from './pendingEcdsaRegistrationRecoveryValidation';
type PasskeyUnlockChallenge = {
  readonly challengeId: string;
  readonly challengeB64u: string;
};
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function requireParsedThresholdSessionId(value: string) {
  const parsed = parseThresholdEcdsaSessionId(value);
  if (!parsed.ok) throw new Error('ECDSA registration recovery could not create a session id');
  return parsed.value;
}
function requireParsedWalletSessionMintId(value: string) {
  const parsed = parseWalletSessionMintId(value);
  if (!parsed.ok)
    throw new Error('ECDSA registration recovery could not create a Wallet Session mint id');
  return parsed.value;
}
function buildEcdsaUnlockPolicy(args: {
  readonly keyHandle: string;
  readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
}): PasskeyWalletUnlockInputWithEcdsaActivation['ecdsaSessionPolicy'] {
  return parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1({
    kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1',
    key_handle: args.keyHandle,
    session_policy: {
      threshold_session_id: requireParsedThresholdSessionId(
        generateSessionId('threshold-ecdsa-registration-recovery'),
      ),
      wallet_session_mint_id: requireParsedWalletSessionMintId(
        generateSessionId('wallet-session-mint'),
      ),
      ttl_ms: DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
      remaining_uses: DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
      runtime_policy_scope: args.runtimePolicyScope,
    },
  });
}
async function requestPasskeyUnlockChallenge(args: {
  readonly relayerUrl: string;
  readonly walletId: string;
  readonly rpId: string;
}): Promise<PasskeyUnlockChallenge> {
  const response = await fetch(joinNormalizedUrl(args.relayerUrl, '/wallet/unlock/challenge'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ unlockBackend: 'passkey', userId: args.walletId, rpId: args.rpId }),
  });
  const raw: unknown = await response.json().catch(() => ({}));
  const body = isRecord(raw) ? raw : {};
  const challengeId = typeof body.challengeId === 'string' ? body.challengeId.trim() : '';
  const challengeB64u = typeof body.challengeB64u === 'string' ? body.challengeB64u.trim() : '';
  if (!response.ok || body.ok !== true || !challengeId || !challengeB64u) {
    throw new Error(
      typeof body.message === 'string'
        ? body.message
        : `wallet/unlock/challenge failed (HTTP ${response.status})`,
    );
  }
  return { challengeId, challengeB64u };
}
function isAuthenticatorTransport(value: string): value is AuthenticatorTransport {
  return (
    value === 'ble' ||
    value === 'hybrid' ||
    value === 'internal' ||
    value === 'nfc' ||
    value === 'usb'
  );
}
function exactPasskeyAllowCredential(
  credentialIdB64u: string,
  transports: readonly string[],
): {
  readonly id: string;
  readonly type: 'public-key';
  readonly transports: AuthenticatorTransport[];
} {
  return {
    id: credentialIdB64u,
    type: 'public-key',
    transports: transports.filter(isAuthenticatorTransport),
  };
}
function assertIssuedEcdsaSessionMatchesRegistration(args: {
  readonly pending: PendingEcdsaOnlyRegistrationCommit;
  readonly response: CommittedEcdsaRegistrationResponse;
  readonly session: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
  readonly walletKey: WalletRegistrationEcdsaWalletKey;
}): void {
  const walletSession: ActiveWalletSessionV1 = args.session.session.wallet_session;
  if (
    walletSession.walletId !== args.pending.walletId ||
    walletSession.authMethodId !== args.pending.walletAuthMethodId ||
    walletSession.authorityId !== args.response.foundingAuthority.authorityId ||
    walletSession.expiresAtMs !== args.session.session.expires_at_ms ||
    walletSession.authorizationId !== args.session.session.authorization_id ||
    walletSession.quotaId !== args.session.session.quota_id ||
    args.session.session.remaining_uses <= 0 ||
    args.session.session.expires_at_ms <= Date.now() ||
    args.session.session.wallet_session_id !==
      args.session.session.operation_credential.walletSessionId ||
    alphabetizeStringify(args.session.public_capability) !==
      alphabetizeStringify(args.walletKey.publicCapability)
  ) {
    throw new Error('ECDSA registration unlock did not issue the exact Wallet Session');
  }
}
function assertCustodyContinuityMatchesRegistration(args: {
  readonly pending: PendingEcdsaOnlyRegistrationCommit;
  readonly response: CommittedEcdsaRegistrationResponse;
  readonly walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  readonly signers: readonly PasskeySessionEcdsaCustodySignerV1[];
}): void {
  if (args.signers.length !== args.walletKeys.length) {
    throw new Error('ECDSA registration unlock returned incomplete custody continuity');
  }
  args.signers.forEach((signer, index) => {
    const walletKey = args.walletKeys[index];
    if (!walletKey) throw new Error('ECDSA registration unlock returned an unknown target');
    if (
      thresholdEcdsaChainTargetKey(signer.chainTarget) !==
        thresholdEcdsaChainTargetKey(walletKey.chainTarget) ||
      signer.walletKey.walletId !== args.pending.walletId ||
      signer.walletKey.keyHandle !== walletKey.keyHandle ||
      signer.walletKey.ecdsaThresholdKeyId !== walletKey.ecdsaThresholdKeyId ||
      signer.walletKey.signingRootId !== walletKey.signingRootId ||
      signer.walletKey.signingRootVersion !== walletKey.signingRootVersion ||
      signer.walletKey.relayerKeyId !== walletKey.relayerKeyId ||
      signer.walletKey.contextBinding32B64u !== walletKey.contextBinding32B64u ||
      signer.walletKey.derivationClientSharePublicKey33B64u !==
        walletKey.derivationClientSharePublicKey33B64u ||
      alphabetizeStringify(signer.walletKey.publicCapability) !==
        alphabetizeStringify(walletKey.publicCapability) ||
      alphabetizeStringify(signer.activationReceipt) !==
        alphabetizeStringify(args.response.ecdsa.activation)
    ) {
      throw new Error('ECDSA registration unlock returned different custody continuity');
    }
  });
}
function zeroizeArrayBuffer(buffer: ArrayBuffer): void {
  new Uint8Array(buffer).fill(0);
}
async function unlockWithPasskey(args: {
  readonly relayerUrl: string;
  readonly pending: PendingEcdsaOnlyRegistrationCommit;
  readonly response: CommittedEcdsaRegistrationResponse;
  readonly walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  readonly exactMethod: Extract<PendingRegistrationExactMethod, { readonly kind: 'passkey' }>;
  readonly signingSurface: PendingRegistrationRecoverySigningSurface;
}): Promise<PendingEcdsaRegistrationUnlockMaterial> {
  if (args.pending.auth.kind !== 'passkey')
    throw new Error('ECDSA registration passkey unlock has a different pending factor');
  const primaryKey = args.walletKeys[0];
  if (!primaryKey) throw new Error('ECDSA registration unlock has no primary wallet key');
  const expectedOrigin = args.exactMethod.expectedOrigin.trim();
  if (!expectedOrigin) throw new Error('ECDSA registration passkey unlock requires an origin');
  const challenge = await requestPasskeyUnlockChallenge({
    relayerUrl: args.relayerUrl,
    walletId: String(args.pending.walletId),
    rpId: args.pending.auth.rpId,
  });
  const credential = await args.signingSurface.getAuthenticationCredentialsSerialized({
    subjectId: String(args.pending.walletId),
    challengeB64u: challenge.challengeB64u,
    allowCredentials: [
      exactPasskeyAllowCredential(args.pending.auth.credentialIdB64u, args.pending.auth.transports),
    ],
    includeSecondPrfOutput: true,
  });
  if (
    passkeyCredentialIdB64uFromAuthentication(credential) !== args.pending.auth.credentialIdB64u
  ) {
    throw new Error('ECDSA registration unlock returned a different Passkey credential');
  }
  const prfFirstB64u = requirePasskeyPrfFirstB64u(credential, 'ECDSA registration recovery');
  const verified = await verifyPasskeyWalletUnlock(args.relayerUrl, {
    type: 'passkey_assertion',
    challengeId: challenge.challengeId,
    walletId: String(args.pending.walletId),
    webauthn_authentication: credential,
    ed25519SessionRequest: { kind: 'not_requested' },
    expected_origin: expectedOrigin,
    ecdsaSessionPolicy: buildEcdsaUnlockPolicy({
      keyHandle: primaryKey.keyHandle,
      runtimePolicyScope: requireEcdsaProjection(args.response).ecdsa.runtimePolicyScope,
    }),
  });
  if (!verified.success)
    throw new Error(verified.error || 'Passkey ECDSA registration unlock failed');
  if (
    verified.ecdsaSession.kind !== 'router_ab_ecdsa_post_registration_session_activated_v1' ||
    !verified.ecdsaCustody ||
    !verified.walletCustody
  ) {
    throw new Error('Passkey ECDSA registration unlock did not issue exact session custody');
  }
  assertIssuedEcdsaSessionMatchesRegistration({
    pending: args.pending,
    response: args.response,
    session: verified.ecdsaSession,
    walletKey: primaryKey,
  });
  assertCustodyContinuityMatchesRegistration({
    pending: args.pending,
    response: args.response,
    walletKeys: args.walletKeys,
    signers: verified.ecdsaCustody.signers,
  });
  const factorSecret = Uint8Array.from(base64UrlDecode(prfFirstB64u)).buffer;
  try {
    const rejoined = await args.signingSurface.rejoinWalletCustodyEvmFamilyKeySet({
      walletId: String(args.pending.walletId),
      custodyJson: joinCustodyJsonFromEstablishedCommitPayload(
        args.pending.localMaterial.custodyCommit,
      ),
      factorSecret,
      evmFamilySigningKeySlotId: primaryKey.evmFamilySigningKeySlotId,
      applicationBindingDigestB64u: args.response.ecdsa.bootstrap.applicationBindingDigestB64u,
      registeredClientRootPublicKey33B64u: primaryKey.derivationClientSharePublicKey33B64u,
      relayerPublicIdentityJson: JSON.stringify({
        relayerKeyId: primaryKey.relayerKeyId,
        relayerPublicKey33B64u: primaryKey.relayerVerifyingShareB64u,
        groupPublicKey33B64u: primaryKey.thresholdEcdsaPublicKeyB64u,
        ethereumAddress: primaryKey.thresholdOwnerAddress,
        relayerShareRetryCounter: primaryKey.relayerShareRetryCounter,
      }),
    });
    return {
      session: verified.ecdsaSession,
      readyStateBlobB64u: rejoined.readyStateBlobB64u,
      publicFacts: rejoined.publicFacts,
    };
  } finally {
    zeroizeArrayBuffer(factorSecret);
  }
}
async function unlockWithEmailOtp(args: {
  readonly relayerUrl: string;
  readonly pending: PendingEcdsaOnlyRegistrationCommit;
  readonly response: CommittedEcdsaRegistrationResponse;
  readonly walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  readonly exactMethod: Extract<PendingRegistrationExactMethod, { readonly kind: 'email_otp' }>;
  readonly signingSurface: PendingRegistrationRecoverySigningSurface;
}): Promise<PendingEcdsaRegistrationUnlockMaterial> {
  if (args.pending.auth.kind !== 'email_otp') {
    throw new Error('ECDSA registration Email OTP unlock has a different pending factor');
  }
  const primaryKey = args.walletKeys[0];
  if (!primaryKey) throw new Error('ECDSA registration unlock has no primary wallet key');
  const runtimePolicyScope = requireEcdsaProjection(args.response).ecdsa.runtimePolicyScope;
  const verified = await unlockEmailOtpWallet({
    walletSession: {
      walletId: toWalletId(args.pending.walletId),
      walletSessionUserId: String(args.pending.walletId),
    },
    authoritySelector: {
      kind: 'wallet_auth_method',
      walletAuthMethodId: args.pending.walletAuthMethodId,
    },
    relayUrl: args.relayerUrl,
    groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    routePlan: buildFreshEmailOtpRoutePlan({
      freshRouteFamily: 'login',
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    }),
    workerCtx: args.signingSurface.getSignerWorkerContext(),
    verification: {
      kind: 'otp',
      challengeId: args.exactMethod.challengeId,
      otpCode: args.exactMethod.otpCode,
    },
    runtimePolicyScope,
    ecdsaSessionHandleBinding: {
      keyHandle: primaryKey.keyHandle,
      authSubjectId: args.pending.auth.providerSubject,
      operation: 'wallet_unlock',
      chainTarget: primaryKey.chainTarget,
    },
    ecdsaSessionPolicy: buildEcdsaUnlockPolicy({
      keyHandle: primaryKey.keyHandle,
      runtimePolicyScope,
    }),
  });
  if (verified.operation !== 'wallet_unlock') {
    throw new Error('Email OTP ECDSA registration unlock returned the wrong operation');
  }
  assertIssuedEcdsaSessionMatchesRegistration({
    pending: args.pending,
    response: args.response,
    session: verified.ecdsaSession,
    walletKey: primaryKey,
  });
  assertCustodyContinuityMatchesRegistration({
    pending: args.pending,
    response: args.response,
    walletKeys: args.walletKeys,
    signers: verified.ecdsaCustody.continuity.signers,
  });
  return {
    session: verified.ecdsaSession,
    readyStateBlobB64u: verified.ecdsaCustody.readyStateBlobB64u,
    publicFacts: verified.ecdsaCustody.publicFacts,
  };
}
export async function unlockPendingEcdsaRegistration(
  args: PendingEcdsaRegistrationUnlockInput,
): Promise<PendingEcdsaRegistrationUnlockMaterial> {
  switch (args.exactMethod.kind) {
    case 'passkey':
      return await unlockWithPasskey({
        relayerUrl: args.relayerUrl,
        pending: args.pending,
        response: args.response,
        walletKeys: args.walletKeys,
        exactMethod: args.exactMethod,
        signingSurface: args.signingSurface,
      });
    case 'email_otp':
      return await unlockWithEmailOtp({
        relayerUrl: args.relayerUrl,
        pending: args.pending,
        response: args.response,
        walletKeys: args.walletKeys,
        exactMethod: args.exactMethod,
        signingSurface: args.signingSurface,
      });
    default:
      args.exactMethod satisfies never;
      throw new Error(
        `Unsupported pending registration unlock method: ${String(args.exactMethod)}`,
      );
  }
}
