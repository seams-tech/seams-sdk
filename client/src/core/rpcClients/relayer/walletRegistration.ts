import type {
  AddAuthMethodInput,
  AddAuthMethodIntentGrant,
  AddAuthMethodIntentV1,
  AddSignerIntentV1,
  AddSignerIntentGrant,
  EmailOtpRegistrationProof,
  RegistrationAuthMethodInput,
  RegisterWalletInput,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  RegistrationSignerSelection,
  WalletAuthMethodTarget,
  WalletId,
} from '@shared/utils/registrationIntent';
import type { AccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import {
  parseThresholdEcdsaKeyIdentityTargets,
  type ThresholdEcdsaKeyIdentityInventoryEntry,
} from '@/core/signingEngine/session/passkey/ecdsaKeyFactsInventory';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import type {
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssServerVisibleClientRequestEnvelope,
  ThresholdEd25519HssStagedEvaluatorArtifactEnvelope,
  ThresholdEcdsaHssRoleLocalClientBootstrap,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  EcdsaHssRoleLocalPublicIdentity,
  ThresholdEcdsaHssRoleLocalBootstrapValue,
} from './thresholdEcdsa';
import { buildEcdsaRoleLocalReadyRecordFromLegacyState } from '@/core/platform/ecdsaRoleLocalRecords';

function stripTrailingSlashes(url: string): string {
  return String(url || '').replace(/\/+$/, '');
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  return ((await response.json().catch(() => ({}))) || {}) as Record<string, unknown>;
}

async function postJson<TResponse>(args: {
  relayerUrl: string;
  path: string;
  body: unknown;
  headers?: Record<string, string>;
}): Promise<TResponse> {
  const response = await fetch(`${stripTrailingSlashes(args.relayerUrl)}${args.path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(args.headers || {}),
    },
    credentials: 'omit',
    body: JSON.stringify(args.body),
  });
  const data = await readJson(response);
  if (!response.ok || data.ok === false) {
    throw new Error(String(data.message || data.error || data.code || `HTTP ${response.status}`));
  }
  return data as TResponse;
}

export type CreateRegistrationIntentRequest = {
  wallet: RegisterWalletInput;
  rpId: string;
  authMethod: RegistrationAuthMethodInput;
  signerSelection: RegistrationSignerSelection;
};

export type CreateRegistrationIntentResponse = {
  ok: true;
  intent: RegistrationIntentV1;
  registrationIntentDigestB64u: string;
  registrationIntentGrant: RegistrationIntentGrant;
  expiresAtMs: number;
};

export type WalletRegistrationStartResponse = {
  ok: true;
  registrationCeremonyId: string;
  intent: RegistrationIntentV1;
  ed25519?: {
    ceremonyHandle: string;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
    clientOtOfferMessageB64u: string;
  };
  ecdsa?: {
    kind: 'evm_family_ecdsa_keygen';
    chainTargets: ThresholdEcdsaChainTarget[];
    prepare: WalletRegistrationEcdsaPrepareContext;
  };
};

export type WalletRegistrationHssRespondResponse = {
  ok: true;
  registrationCeremonyId: string;
  ed25519?: {
    contextBindingB64u: string;
    serverInputDeliveryB64u: string;
  };
  ecdsa?: {
    bootstrap: ThresholdEcdsaHssRoleLocalBootstrapValue;
  };
};

export type WalletRegistrationFinalizeResponse = {
  ok: true;
  walletId: WalletId;
  rpId: string;
  ed25519?: {
    nearAccountId: string;
    publicKey: string;
    relayerKeyId: string;
    keyVersion: string;
    recoveryExportCapable: true;
    clientParticipantId?: number;
    relayerParticipantId?: number;
    participantIds?: number[];
    session?: {
      sessionKind: 'jwt' | 'cookie';
      sessionId: string;
      walletSigningSessionId: string;
      expiresAtMs: number;
      expiresAt?: string;
      participantIds?: number[];
      remainingUses?: number;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      jwt?: string;
    };
  };
  ecdsa?: {
    walletKeys: WalletRegistrationEcdsaWalletKey[];
  };
};

export type WalletRegistrationEmailOtpEnrollmentMaterial = {
  recoveryWrappedEnrollmentEscrows: unknown[];
  enrollmentSealKeyVersion: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
  thresholdEcdsaClientVerifyingShareB64u: string;
};

export type AddSignerAppSessionPolicy = {
  permission: 'wallet_signer_provision';
  walletId: WalletId;
  signerSelection: AddSignerIntentV1['signerSelection'];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  expiresAtMs: number;
};

export type AddAuthMethodAppSessionPolicy = {
  permission: 'wallet_auth_method_provision';
  walletId: WalletId;
  authMethod: AddAuthMethodInput;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  expiresAtMs: number;
};

export type RevokeAuthMethodAppSessionPolicy = {
  permission: 'wallet_auth_method_revoke';
  walletId: WalletId;
  target: WalletAuthMethodTarget;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  expiresAtMs: number;
};

export type CreateAddAuthMethodIntentRequest = {
  walletId: WalletId;
  rpId: string;
  authMethod: AddAuthMethodInput;
};

export type CreateAddAuthMethodIntentResponse = {
  ok: true;
  intent: AddAuthMethodIntentV1;
  addAuthMethodIntentDigestB64u: string;
  addAuthMethodIntentGrant: AddAuthMethodIntentGrant;
  expiresAtMs: number;
};

export type CreateAddSignerIntentRequest = {
  walletId: WalletId;
  rpId: string;
  signerSelection: AddSignerIntentV1['signerSelection'];
};

export type CreateAddSignerIntentResponse = {
  ok: true;
  intent: AddSignerIntentV1;
  addSignerIntentDigestB64u: string;
  addSignerIntentGrant: AddSignerIntentGrant;
  expiresAtMs: number;
};

export type AddSignerAuth =
  | {
      kind: 'webauthn_assertion';
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      appSessionJwt: string;
      policy: AddSignerAppSessionPolicy;
    };

export type AddAuthMethodAuth =
  | {
      kind: 'webauthn_assertion';
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      appSessionJwt: string;
      policy: AddAuthMethodAppSessionPolicy;
    };

export type WalletAddAuthMethodAuthority =
  | {
      kind: 'passkey';
      webauthnRegistration: unknown;
      emailOtpRegistrationProof?: never;
    }
  | {
      kind: 'email_otp';
      emailOtpRegistrationProof: EmailOtpRegistrationProof;
      webauthnRegistration?: never;
    };

export type WalletAddAuthMethodStartResponse = {
  ok: true;
  addAuthMethodCeremonyId: string;
  intent: AddAuthMethodIntentV1;
};

export type WalletAddAuthMethodFinalizeResponse = {
  ok: true;
  walletId: WalletId;
  rpId: string;
  authMethod: {
    kind: 'passkey' | 'email_otp';
    status: 'active' | 'revoked';
  };
};

export type RevokeAuthMethodAuth =
  | {
      kind: 'webauthn_assertion';
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      appSessionJwt: string;
      policy: RevokeAuthMethodAppSessionPolicy;
    };

export type WalletRevokeAuthMethodResponse = {
  ok: true;
  walletId: WalletId;
  rpId: string;
  authMethod: {
    kind: 'passkey' | 'email_otp';
    status: 'revoked';
  };
};

export type WalletAddSignerStartResponse = {
  ok: true;
  addSignerCeremonyId: string;
  intent: AddSignerIntentV1;
  ed25519?: WalletRegistrationStartResponse['ed25519'];
  ecdsa?: WalletRegistrationStartResponse['ecdsa'];
};

export type WalletAddSignerHssRespondResponse = {
  ok: true;
  addSignerCeremonyId: string;
  ed25519?: WalletRegistrationHssRespondResponse['ed25519'];
  ecdsa?: WalletRegistrationHssRespondResponse['ecdsa'];
};

export type WalletAddSignerFinalizeResponse = {
  ok: true;
  walletId: WalletId;
  rpId: string;
  ed25519?: WalletRegistrationFinalizeResponse['ed25519'];
  ecdsa?: WalletRegistrationFinalizeResponse['ecdsa'];
};

export type WalletRegistrationEcdsaPrepareContext = {
  formatVersion: 'ecdsa-hss-role-local';
  walletId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  requestId: string;
  sessionId: string;
  walletSigningSessionId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

export type WalletRegistrationEcdsaClientBootstrap = WalletRegistrationEcdsaPrepareContext & {
  hssClientSharePublicKey33B64u: string;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  clientRootProof?: never;
  passkeyBootstrapAuthorization?: never;
};

export type WalletRegistrationEcdsaWalletKey = {
  keyScope: 'evm-family';
  chainTarget: ThresholdEcdsaChainTarget;
  walletId: string;
  rpId: string;
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  thresholdEcdsaPublicKeyB64u: string;
  thresholdOwnerAddress: string;
  relayerKeyId: string;
  relayerVerifyingShareB64u: string;
  participantIds: number[];
};

export type WalletRegistrationEcdsaCompletedBootstrap = {
  bootstrap: ThresholdEcdsaHssRoleLocalBootstrapValue;
  publicIdentity: EcdsaHssRoleLocalPublicIdentity;
};

type WalletRegistrationStartAuthority =
  | {
      kind: 'passkey';
      webauthnRegistration: unknown;
      emailOtpRegistrationProof?: never;
    }
  | {
      kind: 'email_otp';
      emailOtpRegistrationProof: EmailOtpRegistrationProof;
      webauthnRegistration?: never;
    };

export type WalletRegistrationEcdsaLocalClientBootstrap = ThresholdEcdsaHssRoleLocalClientBootstrap;

export type WalletRegistrationEcdsaHssRespondBootstrap = {
  walletId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssRoleLocalPublicIdentity;
  keyHandle: string;
  signingRootId: string;
  signingRootVersion: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  relayerVerifyingShareB64u: string;
  participantIds: number[];
  thresholdSessionId: string;
  walletSigningSessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  thresholdSessionAuthToken: string;
};

function requireMatchingString(args: {
  field: string;
  expected: unknown;
  actual: unknown;
}): string {
  const expected = String(args.expected || '').trim();
  const actual = String(args.actual || '').trim();
  if (!expected || !actual) {
    throw new Error(`ECDSA registration bootstrap returned incomplete ${args.field}`);
  }
  if (expected !== actual) {
    throw new Error(`ECDSA registration bootstrap ${args.field} mismatch`);
  }
  return actual;
}

function requireMatchingParticipantIds(args: {
  expected: readonly unknown[];
  actual: readonly unknown[];
}): number[] {
  const expected = args.expected.map((participantId) => Math.floor(Number(participantId)));
  const actual = args.actual.map((participantId) => Math.floor(Number(participantId)));
  const invalid =
    expected.length === 0 ||
    actual.length === 0 ||
    expected.some((participantId) => !Number.isSafeInteger(participantId) || participantId <= 0) ||
    actual.some((participantId) => !Number.isSafeInteger(participantId) || participantId <= 0);
  if (invalid) {
    throw new Error('ECDSA registration bootstrap returned incomplete participantIds');
  }
  if (expected.length !== actual.length || expected.some((id, index) => id !== actual[index])) {
    throw new Error('ECDSA registration bootstrap participantIds mismatch');
  }
  return actual;
}

export function parseWalletRegistrationEcdsaHssRespond(args: {
  localBootstrap: WalletRegistrationEcdsaLocalClientBootstrap;
  serverBootstrap: ThresholdEcdsaHssRoleLocalBootstrapValue;
}): WalletRegistrationEcdsaHssRespondBootstrap {
  const localBootstrap = args.localBootstrap;
  const serverBootstrap = args.serverBootstrap;
  requireMatchingString({
    field: 'hssClientSharePublicKey33B64u',
    expected: localBootstrap.clientPublicKey33B64u,
    actual: serverBootstrap.publicIdentity.hssClientSharePublicKey33B64u,
  });
  const contextBinding32B64u = requireMatchingString({
    field: 'contextBinding32B64u',
    expected: localBootstrap.contextBinding32B64u,
    actual: serverBootstrap.contextBinding32B64u,
  });

  const thresholdSessionAuthToken = String(serverBootstrap.jwt || '').trim();
  const walletId = String(serverBootstrap.walletId || '').trim();
  const rpId = String(serverBootstrap.rpId || '').trim();
  const ecdsaThresholdKeyId = String(serverBootstrap.ecdsaThresholdKeyId || '').trim();
  const keyHandle = String(serverBootstrap.keyHandle || '').trim();
  const signingRootId = String(serverBootstrap.signingRootId || '').trim();
  const signingRootVersion = String(serverBootstrap.signingRootVersion || '').trim();
  const thresholdEcdsaPublicKeyB64u = String(serverBootstrap.thresholdEcdsaPublicKeyB64u || '').trim();
  const ethereumAddress = String(serverBootstrap.ethereumAddress || '').trim();
  const relayerKeyId = String(serverBootstrap.relayerKeyId || '').trim();
  const relayerVerifyingShareB64u = String(serverBootstrap.relayerVerifyingShareB64u || '').trim();
  const thresholdSessionId = String(serverBootstrap.sessionId || '').trim();
  const walletSigningSessionId = String(serverBootstrap.walletSigningSessionId || '').trim();
  const remainingUses = Math.max(0, Math.floor(Number(serverBootstrap.remainingUses)));
  const expiresAtMs = Math.max(0, Math.floor(Number(serverBootstrap.expiresAtMs)));
  const participantIds = serverBootstrap.participantIds.map((participantId) =>
    Math.floor(Number(participantId)),
  );
  if (
    !walletId ||
    !rpId ||
    !keyHandle ||
    !ecdsaThresholdKeyId ||
    !signingRootId ||
    !signingRootVersion ||
    !thresholdEcdsaPublicKeyB64u ||
    !ethereumAddress ||
    !relayerKeyId ||
    !relayerVerifyingShareB64u ||
    !thresholdSessionId ||
    !walletSigningSessionId ||
    !thresholdSessionAuthToken ||
    !participantIds.length ||
    participantIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || participantId <= 0,
    ) ||
    !Number.isFinite(remainingUses) ||
    !Number.isFinite(expiresAtMs)
  ) {
    throw new Error('ECDSA registration bootstrap returned incomplete session material');
  }
  return {
    walletId,
    rpId,
    ecdsaThresholdKeyId,
    relayerKeyId,
    contextBinding32B64u,
    publicIdentity: serverBootstrap.publicIdentity,
    keyHandle,
    signingRootId,
    signingRootVersion,
    thresholdEcdsaPublicKeyB64u,
    ethereumAddress,
    relayerVerifyingShareB64u,
    participantIds,
    thresholdSessionId,
    walletSigningSessionId,
    expiresAtMs,
    remainingUses,
    thresholdSessionAuthToken,
  };
}

export function buildWalletRegistrationEcdsaSessionBootstrap(args: {
  walletId: string;
  relayerUrl: string;
  chainTarget: ThresholdEcdsaChainTarget;
  keygenSessionId: string;
  localBootstrap: WalletRegistrationEcdsaLocalClientBootstrap;
  serverBootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
  walletKey: WalletRegistrationEcdsaWalletKey;
  nowMs?: number;
}): ThresholdEcdsaSessionBootstrapResult {
  const localBootstrap = args.localBootstrap;
  const serverBootstrap = args.serverBootstrap;
  requireMatchingString({
    field: 'walletId',
    expected: args.walletId,
    actual: serverBootstrap.walletId,
  });
  requireMatchingString({
    field: 'walletKey.walletId',
    expected: args.walletId,
    actual: args.walletKey.walletId,
  });
  const rpId = requireMatchingString({
    field: 'rpId',
    expected: args.walletKey.rpId,
    actual: serverBootstrap.rpId,
  });
  const keyHandle = requireMatchingString({
    field: 'keyHandle',
    expected: args.walletKey.keyHandle,
    actual: serverBootstrap.keyHandle,
  });
  const ecdsaThresholdKeyId = requireMatchingString({
    field: 'ecdsaThresholdKeyId',
    expected: args.walletKey.ecdsaThresholdKeyId,
    actual: serverBootstrap.ecdsaThresholdKeyId,
  });
  const signingRootId = requireMatchingString({
    field: 'signingRootId',
    expected: args.walletKey.signingRootId,
    actual: serverBootstrap.signingRootId,
  });
  const signingRootVersion = requireMatchingString({
    field: 'signingRootVersion',
    expected: args.walletKey.signingRootVersion,
    actual: serverBootstrap.signingRootVersion,
  });
  const thresholdEcdsaPublicKeyB64u = requireMatchingString({
    field: 'thresholdEcdsaPublicKeyB64u',
    expected: args.walletKey.thresholdEcdsaPublicKeyB64u,
    actual: serverBootstrap.thresholdEcdsaPublicKeyB64u,
  });
  const ethereumAddress = requireMatchingString({
    field: 'ethereumAddress',
    expected: args.walletKey.thresholdOwnerAddress,
    actual: serverBootstrap.ethereumAddress,
  });
  const relayerKeyId = requireMatchingString({
    field: 'relayerKeyId',
    expected: args.walletKey.relayerKeyId,
    actual: serverBootstrap.relayerKeyId,
  });
  const relayerVerifyingShareB64u = requireMatchingString({
    field: 'relayerVerifyingShareB64u',
    expected: args.walletKey.relayerVerifyingShareB64u,
    actual: serverBootstrap.relayerVerifyingShareB64u,
  });
  requireMatchingString({
    field: 'chainTarget',
    expected: thresholdEcdsaChainTargetKey(args.chainTarget),
    actual: thresholdEcdsaChainTargetKey(args.walletKey.chainTarget),
  });

  const participantIds = requireMatchingParticipantIds({
    expected: args.walletKey.participantIds,
    actual: serverBootstrap.participantIds,
  });
  const nowMs = Number.isSafeInteger(args.nowMs) ? args.nowMs! : Date.now();
  const thresholdSessionAuthToken = serverBootstrap.thresholdSessionAuthToken;
  const thresholdSessionId = serverBootstrap.thresholdSessionId;
  const walletSigningSessionId = serverBootstrap.walletSigningSessionId;
  const remainingUses = serverBootstrap.remainingUses;
  const expiresAtMs = serverBootstrap.expiresAtMs;
  const ecdsaHssRoleLocalClientState = {
    kind: 'role_local_ready' as const,
    artifactKind: 'ecdsa-hss-role-local-client-state' as const,
    contextBinding32B64u: localBootstrap.contextBinding32B64u,
    clientShare32B64u: localBootstrap.clientShare32B64u,
    clientPublicKey33B64u: localBootstrap.clientPublicKey33B64u,
    clientShareRetryCounter: localBootstrap.clientShareRetryCounter,
    relayerPublicKey33B64u: serverBootstrap.publicIdentity.relayerPublicKey33B64u,
    groupPublicKey33B64u: serverBootstrap.publicIdentity.groupPublicKey33B64u,
    ethereumAddress,
    clientCaitSithInput: localBootstrap.clientCaitSithInput,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
  const ecdsaRoleLocalReadyRecord = buildEcdsaRoleLocalReadyRecordFromLegacyState({
    walletId: args.walletId,
    rpId,
    chainTarget: args.chainTarget,
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    participantIds,
    state: ecdsaHssRoleLocalClientState,
  });

  const keyRef: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: args.walletId,
    chainTarget: args.chainTarget,
    relayerUrl: args.relayerUrl,
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    backendBinding: {
      relayerKeyId,
      clientVerifyingShareB64u: localBootstrap.clientPublicKey33B64u,
      clientAdditiveShare32B64u: localBootstrap.clientShare32B64u,
      ecdsaRoleLocalReadyRecord,
      ecdsaHssRoleLocalClientState,
    },
    participantIds,
    thresholdEcdsaPublicKeyB64u,
    ethereumAddress,
    relayerVerifyingShareB64u,
    thresholdSessionKind: 'jwt',
    thresholdSessionAuthToken,
    thresholdSessionId,
    walletSigningSessionId,
  };
  return {
    thresholdEcdsaKeyRef: keyRef,
    keygen: {
      ok: true,
      keygenSessionId: args.keygenSessionId,
      rpId,
      keyHandle,
      ecdsaThresholdKeyId,
      clientVerifyingShareB64u: localBootstrap.clientPublicKey33B64u,
      clientAdditiveShare32B64u: localBootstrap.clientShare32B64u,
      thresholdEcdsaPublicKeyB64u,
      ethereumAddress,
      relayerKeyId,
      relayerVerifyingShareB64u,
      participantIds,
      ...(typeof args.chainTarget.chainId === 'number'
        ? { chainId: args.chainTarget.chainId }
        : {}),
    },
    session: {
      ok: true,
      sessionId: thresholdSessionId,
      walletSigningSessionId,
      expiresAtMs,
      remainingUses,
      jwt: thresholdSessionAuthToken,
    },
  };
}

export type WalletEcdsaKeyFactsInventoryTarget = {
  keyHandle: string;
  ecdsaThresholdKeyId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
};

export type WalletEcdsaKeyFactsInventoryAppSessionPolicy = {
  permission: 'ecdsa_key_facts_inventory';
  walletId: AccountId;
  chainTargets: readonly ThresholdEcdsaChainTarget[];
  expiresAtMs: number;
};

export type WalletEcdsaKeyFactsInventoryResponse = {
  ok: true;
  records: ThresholdEcdsaKeyIdentityInventoryEntry[];
  diagnostics: unknown;
};

export async function createWalletRegistrationIntent(args: {
  relayerUrl: string;
  request: CreateRegistrationIntentRequest;
  headers?: Record<string, string>;
}): Promise<CreateRegistrationIntentResponse> {
  return await postJson<CreateRegistrationIntentResponse>({
    relayerUrl: args.relayerUrl,
    path: '/wallets/register/intent',
    body: args.request,
    headers: args.headers,
  });
}

export async function createWalletAddSignerIntent(args: {
  relayerUrl: string;
  walletId: WalletId;
  request: CreateAddSignerIntentRequest;
  headers?: Record<string, string>;
}): Promise<CreateAddSignerIntentResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-signer intent');
  return await postJson<CreateAddSignerIntentResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/intent`,
    headers: args.headers,
    body: args.request,
  });
}

export async function createWalletAddAuthMethodIntent(args: {
  relayerUrl: string;
  walletId: WalletId;
  request: CreateAddAuthMethodIntentRequest;
  headers?: Record<string, string>;
}): Promise<CreateAddAuthMethodIntentResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-auth-method intent');
  return await postJson<CreateAddAuthMethodIntentResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/auth-methods/intent`,
    headers: args.headers,
    body: args.request,
  });
}

function walletRegistrationStartAuthorityBody(
  authority: WalletRegistrationStartAuthority,
): Record<string, unknown> {
  switch (authority.kind) {
    case 'passkey':
      return { webauthn_registration: authority.webauthnRegistration };
    case 'email_otp':
      return { emailOtpRegistrationProof: authority.emailOtpRegistrationProof };
  }
}

export async function startWalletRegistration(args: {
  relayerUrl: string;
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  intent: RegistrationIntentV1;
} & WalletRegistrationStartAuthority): Promise<WalletRegistrationStartResponse> {
  const body = {
    registrationIntentGrant: args.registrationIntentGrant,
    registrationIntentDigestB64u: args.registrationIntentDigestB64u,
    intent: args.intent,
    ...walletRegistrationStartAuthorityBody(args),
  };
  return await postJson<WalletRegistrationStartResponse>({
    relayerUrl: args.relayerUrl,
    path: '/wallets/register/start',
    body,
  });
}

export async function respondWalletRegistrationHss(args: {
  relayerUrl: string;
  registrationCeremonyId: string;
  ed25519?: {
    clientRequest: ThresholdEd25519HssServerVisibleClientRequestEnvelope;
  };
  ecdsa?: {
    clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  };
}): Promise<WalletRegistrationHssRespondResponse> {
  return await postJson<WalletRegistrationHssRespondResponse>({
    relayerUrl: args.relayerUrl,
    path: '/wallets/register/hss/respond',
    body: {
      registrationCeremonyId: args.registrationCeremonyId,
      ...(args.ed25519 ? { ed25519: args.ed25519 } : {}),
      ...(args.ecdsa ? { ecdsa: args.ecdsa } : {}),
    },
  });
}

export async function finalizeWalletRegistration(args: {
  relayerUrl: string;
  registrationCeremonyId: string;
  ed25519?: {
    evaluationResult: ThresholdEd25519HssStagedEvaluatorArtifactEnvelope;
    sessionPolicy?: unknown;
    sessionKind?: 'jwt' | 'cookie';
  };
  ecdsa?: {
    expectedKeyHandles?: string[];
  };
  emailOtpEnrollment?: WalletRegistrationEmailOtpEnrollmentMaterial;
}): Promise<WalletRegistrationFinalizeResponse> {
  return await postJson<WalletRegistrationFinalizeResponse>({
    relayerUrl: args.relayerUrl,
    path: '/wallets/register/finalize',
    body: {
      registrationCeremonyId: args.registrationCeremonyId,
      ...(args.ed25519 ? { ed25519: args.ed25519 } : {}),
      ...(args.ecdsa ? { ecdsa: args.ecdsa } : {}),
      ...(args.emailOtpEnrollment ? { emailOtpEnrollment: args.emailOtpEnrollment } : {}),
    },
  });
}

function addSignerAuthHeaders(auth: AddSignerAuth): Record<string, string> | undefined {
  if (auth.kind !== 'app_session') return undefined;
  const token = String(auth.appSessionJwt || '').trim();
  if (!token) throw new Error('appSessionJwt is required for app-session add-signer auth');
  return { Authorization: `Bearer ${token}` };
}

function addSignerAuthBody(auth: AddSignerAuth): unknown {
  switch (auth.kind) {
    case 'webauthn_assertion':
      return {
        kind: 'webauthn_assertion',
        credential: auth.credential,
        expectedChallengeDigestB64u: auth.expectedChallengeDigestB64u,
      };
    case 'app_session':
      return {
        kind: 'app_session',
        policy: auth.policy,
      };
  }
}

function addAuthMethodAuthHeaders(auth: AddAuthMethodAuth): Record<string, string> | undefined {
  if (auth.kind !== 'app_session') return undefined;
  const token = String(auth.appSessionJwt || '').trim();
  if (!token) throw new Error('appSessionJwt is required for app-session add-auth-method auth');
  return { Authorization: `Bearer ${token}` };
}

function addAuthMethodAuthBody(auth: AddAuthMethodAuth): unknown {
  switch (auth.kind) {
    case 'webauthn_assertion':
      return {
        kind: 'webauthn_assertion',
        credential: auth.credential,
        expectedChallengeDigestB64u: auth.expectedChallengeDigestB64u,
      };
    case 'app_session':
      return {
        kind: 'app_session',
        policy: auth.policy,
      };
  }
}

function addAuthMethodAuthorityBody(authority: WalletAddAuthMethodAuthority): Record<string, unknown> {
  switch (authority.kind) {
    case 'passkey':
      return { webauthnRegistration: authority.webauthnRegistration };
    case 'email_otp':
      return { emailOtpRegistrationProof: authority.emailOtpRegistrationProof };
  }
}

function revokeAuthMethodAuthHeaders(
  auth: RevokeAuthMethodAuth,
): Record<string, string> | undefined {
  if (auth.kind !== 'app_session') return undefined;
  const token = String(auth.appSessionJwt || '').trim();
  if (!token) throw new Error('appSessionJwt is required for app-session auth-method revoke');
  return { Authorization: `Bearer ${token}` };
}

function revokeAuthMethodAuthBody(auth: RevokeAuthMethodAuth): unknown {
  switch (auth.kind) {
    case 'webauthn_assertion':
      return {
        kind: 'webauthn_assertion',
        credential: auth.credential,
        expectedChallengeDigestB64u: auth.expectedChallengeDigestB64u,
      };
    case 'app_session':
      return {
        kind: 'app_session',
        policy: auth.policy,
      };
  }
}

export async function startWalletAddSigner(args: {
  relayerUrl: string;
  walletId: WalletId;
  addSignerIntentGrant: AddSignerIntentGrant;
  addSignerIntentDigestB64u: string;
  intent: AddSignerIntentV1;
  auth: AddSignerAuth;
}): Promise<WalletAddSignerStartResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-signer start');
  return await postJson<WalletAddSignerStartResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/start`,
    headers: addSignerAuthHeaders(args.auth),
    body: {
      addSignerIntentGrant: args.addSignerIntentGrant,
      addSignerIntentDigestB64u: args.addSignerIntentDigestB64u,
      intent: args.intent,
      auth: addSignerAuthBody(args.auth),
    },
  });
}

export async function startWalletAddAuthMethod(args: {
  relayerUrl: string;
  walletId: WalletId;
  addAuthMethodIntentGrant: AddAuthMethodIntentGrant;
  addAuthMethodIntentDigestB64u: string;
  intent: AddAuthMethodIntentV1;
  auth: AddAuthMethodAuth;
  authority: WalletAddAuthMethodAuthority;
}): Promise<WalletAddAuthMethodStartResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-auth-method start');
  return await postJson<WalletAddAuthMethodStartResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/auth-methods/start`,
    headers: addAuthMethodAuthHeaders(args.auth),
    body: {
      addAuthMethodIntentGrant: args.addAuthMethodIntentGrant,
      addAuthMethodIntentDigestB64u: args.addAuthMethodIntentDigestB64u,
      intent: args.intent,
      auth: addAuthMethodAuthBody(args.auth),
      ...addAuthMethodAuthorityBody(args.authority),
    },
  });
}

export async function respondWalletAddSignerHss(args: {
  relayerUrl: string;
  walletId: WalletId;
  addSignerCeremonyId: string;
  ed25519?: {
    clientRequest: ThresholdEd25519HssServerVisibleClientRequestEnvelope;
  };
  ecdsa?: {
    clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  };
}): Promise<WalletAddSignerHssRespondResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-signer HSS respond');
  return await postJson<WalletAddSignerHssRespondResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/hss/respond`,
    body: {
      addSignerCeremonyId: args.addSignerCeremonyId,
      ...(args.ed25519 ? { ed25519: args.ed25519 } : {}),
      ...(args.ecdsa ? { ecdsa: args.ecdsa } : {}),
    },
  });
}

export async function finalizeWalletAddSigner(args: {
  relayerUrl: string;
  walletId: WalletId;
  addSignerCeremonyId: string;
  ed25519?: {
    evaluationResult: ThresholdEd25519HssStagedEvaluatorArtifactEnvelope;
    sessionPolicy?: unknown;
    sessionKind?: 'jwt' | 'cookie';
  };
  ecdsa?: {
    expectedKeyHandles?: string[];
  };
}): Promise<WalletAddSignerFinalizeResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-signer finalize');
  return await postJson<WalletAddSignerFinalizeResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/finalize`,
    body: {
      addSignerCeremonyId: args.addSignerCeremonyId,
      ...(args.ed25519 ? { ed25519: args.ed25519 } : {}),
      ...(args.ecdsa ? { ecdsa: args.ecdsa } : {}),
    },
  });
}

export async function finalizeWalletAddAuthMethod(args: {
  relayerUrl: string;
  walletId: WalletId;
  addAuthMethodCeremonyId: string;
}): Promise<WalletAddAuthMethodFinalizeResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-auth-method finalize');
  return await postJson<WalletAddAuthMethodFinalizeResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/auth-methods/finalize`,
    body: {
      addAuthMethodCeremonyId: args.addAuthMethodCeremonyId,
    },
  });
}

export async function revokeWalletAuthMethod(args: {
  relayerUrl: string;
  walletId: WalletId;
  rpId: string;
  auth: RevokeAuthMethodAuth;
  target: WalletAuthMethodTarget;
}): Promise<WalletRevokeAuthMethodResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for auth-method revoke');
  const rpId = String(args.rpId || '').trim();
  if (!rpId) throw new Error('rpId is required for auth-method revoke');
  return await postJson<WalletRevokeAuthMethodResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/auth-methods/revoke`,
    headers: revokeAuthMethodAuthHeaders(args.auth),
    body: {
      rpId,
      auth: revokeAuthMethodAuthBody(args.auth),
      target: args.target,
    },
  });
}

export async function repairWalletEcdsaKeyFactsInventoryWithAppSession(args: {
  relayerUrl: string;
  walletId: AccountId;
  rpId: string;
  appSessionJwt: string;
  keyTargets: readonly WalletEcdsaKeyFactsInventoryTarget[];
  policy: WalletEcdsaKeyFactsInventoryAppSessionPolicy;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): Promise<WalletEcdsaKeyFactsInventoryResponse> {
  const walletId = String(args.walletId || '').trim();
  const rpId = String(args.rpId || '').trim();
  const appSessionJwt = String(args.appSessionJwt || '').trim();
  if (!walletId) {
    throw new Error('walletId is required for ECDSA key-facts repair');
  }
  if (!rpId) {
    throw new Error('rpId is required for ECDSA key-facts repair');
  }
  if (!appSessionJwt) {
    throw new Error('appSessionJwt is required for ECDSA key-facts repair');
  }
  if (String(args.policy.walletId || '').trim() !== walletId) {
    throw new Error('policy.walletId must match walletId for ECDSA key-facts repair');
  }

  const data = await postJson<Record<string, unknown>>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/ecdsa/key-facts/inventory`,
    headers: {
      Authorization: `Bearer ${appSessionJwt}`,
    },
    body: {
      rpId,
      keyTargets: args.keyTargets,
      auth: {
        kind: 'app_session',
        policy: args.policy,
      },
    },
  });
  const records = Array.isArray(data.ecdsaKeyIdentityTargets) ? data.ecdsaKeyIdentityTargets : [];
  return {
    ok: true,
    records: parseThresholdEcdsaKeyIdentityTargets({
      nearAccountId: args.walletId,
      rpId,
      ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      records,
    }),
    diagnostics: Object.prototype.hasOwnProperty.call(data, 'diagnostics')
      ? data.diagnostics
      : null,
  };
}

export async function repairWalletEcdsaKeyFactsInventoryWithWebAuthn(args: {
  relayerUrl: string;
  walletId: AccountId;
  rpId: string;
  credential: WebAuthnAuthenticationCredential;
  keyTargets: readonly WalletEcdsaKeyFactsInventoryTarget[];
  serverNonceB64u: string;
  expectedChallengeDigestB64u: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): Promise<WalletEcdsaKeyFactsInventoryResponse> {
  const walletId = String(args.walletId || '').trim();
  const rpId = String(args.rpId || '').trim();
  const serverNonceB64u = String(args.serverNonceB64u || '').trim();
  const expectedChallengeDigestB64u = String(args.expectedChallengeDigestB64u || '').trim();
  if (!walletId) {
    throw new Error('walletId is required for ECDSA key-facts repair');
  }
  if (!rpId) {
    throw new Error('rpId is required for ECDSA key-facts repair');
  }
  if (!serverNonceB64u || !expectedChallengeDigestB64u) {
    throw new Error('WebAuthn ECDSA key-facts repair requires challenge binding');
  }

  const data = await postJson<Record<string, unknown>>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/ecdsa/key-facts/inventory`,
    body: {
      rpId,
      keyTargets: args.keyTargets,
      auth: {
        kind: 'webauthn_assertion',
        credential: args.credential,
        serverNonceB64u,
        expectedChallengeDigestB64u,
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      },
    },
  });
  const records = Array.isArray(data.ecdsaKeyIdentityTargets) ? data.ecdsaKeyIdentityTargets : [];
  return {
    ok: true,
    records: parseThresholdEcdsaKeyIdentityTargets({
      nearAccountId: args.walletId,
      rpId,
      ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      records,
    }),
    diagnostics: Object.prototype.hasOwnProperty.call(data, 'diagnostics')
      ? data.diagnostics
      : null,
  };
}
