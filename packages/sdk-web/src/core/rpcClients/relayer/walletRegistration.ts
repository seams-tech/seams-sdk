import type {
  AddAuthMethodInput,
  AddAuthMethodIntentGrant,
  AddAuthMethodIntentV1,
  AddSignerIntentV1,
  AddSignerIntentGrant,
  EmailOtpRegistrationProof,
  RegistrationAuthMethodInput,
  RegisterWalletInput,
  RegistrationNearAccountProvisioning,
  ResolvedRegistrationNearAccount,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  WalletAuthMethodTarget,
  WalletId,
  WebAuthnRpId,
} from '@shared/utils/registrationIntent';
import {
  parseRouterAbEcdsaHssNormalSigningFromWalletRegistrationJwtV1,
  type RouterAbEcdsaHssNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaHss';
import {
  computeSdkEcdsaHssApplicationBindingDigestB64u,
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { AccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import {
  parseThresholdEcdsaKeyIdentityTargets,
  type ThresholdEcdsaKeyIdentityInventoryEntry,
} from '@/core/signingEngine/session/passkey/ecdsaKeyFactsInventory';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import { parseEcdsaThresholdKeyId } from '@/core/signingEngine/session/keyMaterialBrands';
import type {
  ThresholdEcdsaRoleLocalWorkerShareHandle,
  ThresholdEcdsaSecp256k1KeyRef,
} from '@/core/signingEngine/interfaces/signing';
import type {
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssServerVisibleClientRequestEnvelope,
  ThresholdEd25519HssStagedEvaluatorArtifactEnvelope,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { RouterAbEd25519NormalSigningState } from '@/core/signingEngine/threshold/ed25519/routerAbNormalSigningState';
import type {
  EcdsaHssRoleLocalPublicIdentity,
  ThresholdEcdsaHssRoleLocalBootstrapValue,
} from './thresholdEcdsa';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type { EcdsaRoleLocalReadyStateBlob } from '@/core/platform';
import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';
import {
  registrationSignerSetRequestSelection,
  type RegistrationSignerSetRequest,
} from './registrationSignerSetRequest';

const REGISTRATION_ROUTE_PAYLOAD_DIAGNOSTICS_LABEL = '[Registration] wallet route payload summary';
const ROUTE_PAYLOAD_BREAKDOWN_MAX_DEPTH = 2;
const ROUTE_PAYLOAD_BREAKDOWN_MAX_FIELDS = 64;

function utf8Bytes(value: string): number {
  try {
    return new TextEncoder().encode(String(value || '')).length;
  } catch {
    return String(value || '').length;
  }
}

function registrationBenchmarkDiagnosticsEnabled(): boolean {
  try {
    return (
      (globalThis as { __SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS?: unknown })
        .__SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS === true
    );
  } catch {
    return false;
  }
}

function collectPayloadSizeBreakdown(input: {
  value: unknown;
  out: Record<string, number>;
  path: string;
  depth: number;
}): void {
  if (!input.value || typeof input.value !== 'object' || Array.isArray(input.value)) return;
  if (Object.keys(input.out).length >= ROUTE_PAYLOAD_BREAKDOWN_MAX_FIELDS) return;
  for (const [key, entry] of Object.entries(input.value as Record<string, unknown>)) {
    if (Object.keys(input.out).length >= ROUTE_PAYLOAD_BREAKDOWN_MAX_FIELDS) return;
    const fieldPath = input.path ? `${input.path}.${key}` : key;
    if (typeof entry === 'string') {
      input.out[`${fieldPath}Bytes`] = utf8Bytes(entry);
    } else if (Array.isArray(entry)) {
      input.out[`${fieldPath}Count`] = entry.length;
    } else if (input.depth > 0 && entry && typeof entry === 'object') {
      collectPayloadSizeBreakdown({
        value: entry,
        out: input.out,
        path: fieldPath,
        depth: input.depth - 1,
      });
    }
  }
}

function payloadSizeBreakdown(value: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  collectPayloadSizeBreakdown({
    value,
    out,
    path: '',
    depth: ROUTE_PAYLOAD_BREAKDOWN_MAX_DEPTH,
  });
  return out;
}

function parseJsonText(text: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(text || '{}');
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

async function readResponseText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return '{}';
  }
}

function logWalletRegistrationRouteProgress(
  stage: string,
  details?: Record<string, unknown>,
): void {
  console.info('[wallet-registration][route] progress', {
    stage,
    ...(details || {}),
  });
}

async function postJson<TResponse>(args: {
  relayerUrl: string;
  path: string;
  body: unknown;
  headers?: Record<string, string>;
}): Promise<TResponse> {
  const startedAt = Date.now();
  const requestBody = JSON.stringify(args.body);
  if (args.path === '/wallets/register/finalize') {
    logWalletRegistrationRouteProgress('finalize_fetch_started', {
      requestBytes: utf8Bytes(requestBody),
    });
  }
  const response = await fetch(
    `${normalizeRelayerBaseUrl(args.relayerUrl, { trim: false })}${args.path}`,
    buildRelayerJsonPostRequestInit({
      headers: args.headers,
      body: args.body,
      bodyJson: requestBody,
    }),
  );
  if (args.path === '/wallets/register/finalize') {
    logWalletRegistrationRouteProgress('finalize_fetch_headers_received', {
      status: response.status,
      ok: response.ok,
      durationMs: Date.now() - startedAt,
    });
  }
  const responseText = await readResponseText(response);
  if (args.path === '/wallets/register/finalize') {
    logWalletRegistrationRouteProgress('finalize_fetch_body_read', {
      responseBytes: utf8Bytes(responseText),
      durationMs: Date.now() - startedAt,
    });
  }
  const data = parseJsonText(responseText);
  if (registrationBenchmarkDiagnosticsEnabled()) {
    console.info(REGISTRATION_ROUTE_PAYLOAD_DIAGNOSTICS_LABEL, {
      path: args.path,
      status: response.status,
      requestBytes: utf8Bytes(requestBody),
      requestSizeBreakdown: payloadSizeBreakdown(args.body),
      responseBytes: utf8Bytes(responseText),
      responseSizeBreakdown: payloadSizeBreakdown(data),
      totalMs: Date.now() - startedAt,
    });
  }
  if (!response.ok || data.ok === false) {
    throw new Error(String(data.message || data.error || data.code || `HTTP ${response.status}`));
  }
  return data as TResponse;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function requireResponseString(args: {
  responseName: string;
  field: string;
  value: unknown;
}): string {
  const value = String(args.value || '').trim();
  if (!value) {
    throw new Error(`${args.responseName} response missing ${args.field}`);
  }
  return value;
}

function requireResponseRecord(args: {
  responseName: string;
  field: string;
  value: unknown;
}): Record<string, unknown> {
  if (!isRecord(args.value)) {
    throw new Error(`${args.responseName} response missing ${args.field}`);
  }
  return args.value;
}

export type CreateRegistrationIntentRequest = {
  wallet: RegisterWalletInput;
  authMethod: RegistrationAuthMethodInput;
  signerSelection: RegistrationSignerSetRequest;
};

function createRegistrationIntentWireRequest(
  request: CreateRegistrationIntentRequest,
): CreateRegistrationIntentRequest {
  return {
    wallet: request.wallet,
    authMethod: request.authMethod,
    signerSelection: registrationSignerSetRequestSelection(request.signerSelection),
  };
}

export type CreateRegistrationIntentResponse = {
  ok: true;
  intent: RegistrationIntentV1;
  registrationIntentDigestB64u: string;
  registrationIntentGrant: RegistrationIntentGrant;
  expiresAtMs: number;
};

export type FundImplicitNearAccountForTestingResponse =
  | {
      ok: true;
      walletId: string;
      nearAccountId: string;
      fundedAmountYocto: string;
      transactionHash?: string;
      message?: string;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export async function fundImplicitNearAccountForTesting(args: {
  relayerUrl: string;
  walletId: WalletId | string;
  nearAccountId: string;
  nearPublicKeyStr: string;
  walletSessionJwt: string;
}): Promise<FundImplicitNearAccountForTestingResponse> {
  const walletId = String(args.walletId || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const nearPublicKeyStr = String(args.nearPublicKeyStr || '').trim();
  const walletSessionJwt = String(args.walletSessionJwt || '').trim();
  if (!walletId) throw new Error('walletId is required for implicit NEAR account funding');
  if (!nearAccountId) {
    throw new Error('nearAccountId is required for implicit NEAR account funding');
  }
  if (!nearPublicKeyStr) {
    throw new Error('nearPublicKeyStr is required for implicit NEAR account funding');
  }
  if (!walletSessionJwt) {
    throw new Error('walletSessionJwt is required for implicit NEAR account funding');
  }
  return await postJson<FundImplicitNearAccountForTestingResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/near/implicit-account/fund`,
    headers: buildBearerAuthorizationHeader({
      token: walletSessionJwt,
      missingMessage: 'walletSessionJwt is required for implicit NEAR account funding',
    }),
    body: {
      nearAccountId,
      nearPublicKeyStr,
    },
  });
}

export type RegistrationPreparationId = string & { readonly __brand: 'RegistrationPreparationId' };

export function registrationPreparationIdFromString(value: string): RegistrationPreparationId {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error('Registration preparation id is required');
  }
  return normalized as RegistrationPreparationId;
}

export type WalletRegistrationRouteTimingName =
  | 'registrationIntentLoadMs'
  | 'registrationIntentDigestMs'
  | 'registrationIntentConsumeMs'
  | 'registrationPreparationPersistMs'
  | 'registrationPreparationLoadMs'
  | 'registrationPreparationConsumeMs'
  | 'registrationPreparationScopeCheckMs'
  | 'registrationAuthorityVerifyMs'
  | 'registrationHssPrepareMs'
  | 'registrationPreauthHssPrepareMs'
  | 'registrationHssServerInputDeriveMs'
  | 'registrationHssServerSessionPrepareTotalMs'
  | 'registrationHssPrepareSessionMs'
  | 'registrationHssPrepareExtractDriverStatesMs'
  | 'registrationHssPrepareClientOfferMessageMs'
  | 'registrationHssPrepareCachePreparedSessionMs'
  | 'registrationHssPrepareEncodeStatesMs'
  | 'registrationEcdsaPrepareMs'
  | 'registrationCeremonyPersistMs'
  | 'registerPrepareTotalMs'
  | 'registerStartTotalMs'
  | 'registrationHssRespondMs'
  | 'registrationHssRespondDecodeMessagesMs'
  | 'registrationHssRespondMaterializeSessionMs'
  | 'registrationHssRespondPrepareDeliveryMs'
  | 'registrationHssRespondDeliveryOtOpenJoinMs'
  | 'registrationHssRespondDeliveryServerInputOpenMs'
  | 'registrationHssRespondDeliveryServerInputShareMs'
  | 'registrationHssRespondDeliveryServerInputCommitmentMs'
  | 'registrationHssRespondDeliveryServerInputTranscriptMs'
  | 'registrationHssRespondDeliveryServerInputSealMs'
  | 'registrationHssRespondEncodeDeliveryMs'
  | 'registrationEcdsaRespondMs'
  | 'registerHssRespondTotalMs'
  | 'registrationFinalizeReplayLoadMs'
  | 'registrationCeremonyLoadMs'
  | 'registrationHssFinalizeMs'
  | 'registrationHssFinalizeDecodeArtifactMs'
  | 'registrationHssFinalizeSerializedSessionMaterializeMs'
  | 'registrationHssFinalizeReportMs'
  | 'registrationHssFinalizeEncodeReportMs'
  | 'registrationHssFinalizeOpenServerOutputMs'
  | 'registrationHssFinalizeOpenSeedOutputMs'
  | 'registrationHssFinalizeDeriveSeedKeypairMs'
  | 'registrationHssFinalizeDeriveRelayerVerifyingShareMs'
  | 'registrationHssFinalizeKeyStorePutMs'
  | 'registrationEcdsaBootstrapVerifyMs'
  | 'sponsoredNearAccountCreateMs'
  | 'registrationKeygenMs'
  | 'registrationEmailOtpEnrollmentPlanMs'
  | 'relaySessionMintMs'
  | 'relayGoogleEmailOtpActivationPlanMs'
  | 'relayPersistenceMs'
  | 'registrationFinalizeReplayCacheMs'
  | 'registerFinalizeTotalMs';

export type WalletRegistrationRouteDiagnostics = {
  kind: 'wallet_registration_route_diagnostics_v1';
  route:
    | 'wallets_register_prepare'
    | 'wallets_register_start'
    | 'wallets_register_hss_respond'
    | 'wallets_register_finalize';
  entries: {
    name: WalletRegistrationRouteTimingName;
    durationMs: number;
  }[];
};

export type WalletRegistrationPrepareResponse = {
  ok: true;
  state: 'prepared';
  registrationPreparationId: RegistrationPreparationId;
  expiresAtMs: number;
  registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
  ed25519: {
    ceremonyHandle: string;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
    clientOtOfferMessageB64u: string;
  };
};

function parseWalletRegistrationPrepareResponse(value: unknown): WalletRegistrationPrepareResponse {
  const responseName = 'wallet registration prepare';
  const record = requireResponseRecord({
    responseName,
    field: 'body',
    value,
  });
  if (record.ok !== true) {
    throw new Error(`${responseName} response was not ok`);
  }
  if (record.state !== 'prepared') {
    throw new Error(`${responseName} response was not prepared`);
  }
  const expiresAtMs = Number(record.expiresAtMs);
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error(`${responseName} response missing expiresAtMs`);
  }
  const ed25519 = requireResponseRecord({
    responseName,
    field: 'ed25519',
    value: record.ed25519,
  });
  const registrationDiagnostics = record.registrationDiagnostics;
  const parsedRegistrationDiagnostics = isRecord(registrationDiagnostics)
    ? (registrationDiagnostics as WalletRegistrationRouteDiagnostics)
    : undefined;
  return {
    ok: true,
    state: 'prepared',
    registrationPreparationId: registrationPreparationIdFromString(
      requireResponseString({
        responseName,
        field: 'registrationPreparationId',
        value: record.registrationPreparationId,
      }),
    ),
    expiresAtMs,
    ...(parsedRegistrationDiagnostics
      ? { registrationDiagnostics: parsedRegistrationDiagnostics }
      : {}),
    ed25519: {
      ceremonyHandle: requireResponseString({
        responseName,
        field: 'ed25519.ceremonyHandle',
        value: ed25519.ceremonyHandle,
      }),
      preparedSession: requireResponseRecord({
        responseName,
        field: 'ed25519.preparedSession',
        value: ed25519.preparedSession,
      }) as ThresholdEd25519HssPreparedSessionEnvelope,
      clientOtOfferMessageB64u: requireResponseString({
        responseName,
        field: 'ed25519.clientOtOfferMessageB64u',
        value: ed25519.clientOtOfferMessageB64u,
      }),
    },
  };
}

export type WalletRegistrationStartResponse = {
  ok: true;
  registrationCeremonyId: string;
  intent: RegistrationIntentV1;
  registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
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
  registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
  ed25519?: {
    contextBindingB64u: string;
    serverInputDeliveryB64u: string;
  };
  ecdsa?: {
    bootstrap: ThresholdEcdsaHssRoleLocalBootstrapValue;
  };
};

export type WalletRegistrationFinalizeAuthMethod =
  | {
      kind: 'passkey';
      credentialIdB64u: string;
      credentialPublicKeyB64u: string;
    }
  | {
      kind: 'email_otp';
      registrationAuthorityId: string;
    };

export type WalletRegistrationFinalizeResponse =
  | {
      ok: true;
      walletId: WalletId;
      rpId?: string;
      authMethod: WalletRegistrationFinalizeAuthMethod;
      accountProvisioning: RegistrationNearAccountProvisioning;
      resolvedAccount: ResolvedRegistrationNearAccount;
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      ed25519: {
        nearAccountId: string;
        nearEd25519SigningKeyId: string;
        publicKey: string;
        relayerKeyId: string;
        keyVersion: string;
        recoveryExportCapable: true;
        clientParticipantId?: number;
        relayerParticipantId?: number;
        participantIds?: number[];
        session?: {
          sessionKind: 'jwt' | 'cookie';
          walletId: string;
          nearAccountId: string;
          nearEd25519SigningKeyId: string;
          thresholdSessionId: string;
          signingGrantId: string;
          expiresAtMs: number;
          expiresAt?: string;
          participantIds?: number[];
          remainingUses?: number;
          runtimePolicyScope?: ThresholdRuntimePolicyScope;
          routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
          jwt?: string;
        };
      };
      ecdsa?: {
        walletKeys: WalletRegistrationEcdsaWalletKey[];
      };
    }
  | {
      ok: true;
      walletId: WalletId;
      rpId?: string;
      authMethod: WalletRegistrationFinalizeAuthMethod;
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      ecdsa: {
        walletKeys: WalletRegistrationEcdsaWalletKey[];
      };
      accountProvisioning?: never;
      resolvedAccount?: never;
      ed25519?: never;
    }
  | {
      ok: true;
      kind: 'already_finalized_restore_required';
      walletId: WalletId;
      rpId?: string;
      reason: 'replay_without_session_material';
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      authMethod?: never;
      ed25519?: never;
      ecdsa?: never;
    };

export type WalletRegistrationEmailOtpEnrollmentMaterial = {
  recoveryWrappedEnrollmentEscrows: unknown[];
  enrollmentSealKeyVersion: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
  thresholdEcdsaClientVerifyingShareB64u: string;
};

export type WalletRegistrationEmailOtpBackupAck = {
  kind: 'email_otp_recovery_code_backup_ack_v1';
  offerId?: string;
  candidateId?: string;
  recoveryCodesIssuedAtMs: number;
  backupActionKind: 'download' | 'copy' | 'print' | 'manual';
  acknowledgedAtMs: number;
  idempotencyKey: string;
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
      rpId: WebAuthnRpId;
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      appSessionJwt: string;
      policy: RevokeAuthMethodAppSessionPolicy;
    };

export type WalletRevokeAuthMethodResponse =
  | {
      ok: true;
      walletId: WalletId;
      authMethod: {
        kind: 'passkey';
        status: 'revoked';
      };
      rpId: string;
    }
  | {
      ok: true;
      walletId: WalletId;
      authMethod: {
        kind: 'email_otp';
        status: 'revoked';
      };
      rpId?: never;
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
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  registrationPreparationId?: RegistrationPreparationId;
  requestId: string;
  thresholdSessionId: string;
  signingGrantId: string;
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
  evmFamilySigningKeySlotId: string;
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

export type WalletRegistrationEcdsaHssRespondBootstrap = {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  applicationBindingDigestB64u: string;
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
  signingGrantId: string;
  expiresAtMs: number;
  remainingUses: number;
  walletSessionJwt: string;
  routerAbEcdsaHssNormalSigning: RouterAbEcdsaHssNormalSigningStateV1;
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
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  serverBootstrap: ThresholdEcdsaHssRoleLocalBootstrapValue;
}): WalletRegistrationEcdsaHssRespondBootstrap {
  const clientBootstrap = args.clientBootstrap;
  const serverBootstrap = args.serverBootstrap;
  requireMatchingString({
    field: 'hssClientSharePublicKey33B64u',
    expected: clientBootstrap.hssClientSharePublicKey33B64u,
    actual: serverBootstrap.publicIdentity.hssClientSharePublicKey33B64u,
  });
  const contextBinding32B64u = requireMatchingString({
    field: 'contextBinding32B64u',
    expected: clientBootstrap.contextBinding32B64u,
    actual: serverBootstrap.contextBinding32B64u,
  });

  const walletSessionJwt = String(serverBootstrap.jwt || '').trim();
  const routerAbEcdsaHssNormalSigning =
    parseRouterAbEcdsaHssNormalSigningFromWalletRegistrationJwtV1({
      walletSessionJwt,
      expected: {
        walletId: String(serverBootstrap.walletId || '').trim(),
        evmFamilySigningKeySlotId: String(serverBootstrap.evmFamilySigningKeySlotId || '').trim(),
        keyHandle: String(serverBootstrap.keyHandle || '').trim(),
        relayerKeyId: String(serverBootstrap.relayerKeyId || '').trim(),
        ecdsaThresholdKeyId: String(serverBootstrap.ecdsaThresholdKeyId || '').trim(),
        signingRootId: String(serverBootstrap.signingRootId || '').trim(),
        signingRootVersion: String(serverBootstrap.signingRootVersion || '').trim(),
        thresholdSessionId: String(serverBootstrap.thresholdSessionId || '').trim(),
        signingGrantId: String(serverBootstrap.signingGrantId || '').trim(),
        expiresAtMs: Number(serverBootstrap.expiresAtMs),
        participantIds: serverBootstrap.participantIds.map((participantId) =>
          Math.floor(Number(participantId)),
        ),
        applicationBindingDigestB64u: String(
          serverBootstrap.applicationBindingDigestB64u || '',
        ).trim(),
        contextBinding32B64u: String(serverBootstrap.contextBinding32B64u || '').trim(),
        clientPublicKey33B64u: String(
          serverBootstrap.publicIdentity.hssClientSharePublicKey33B64u || '',
        ).trim(),
        serverPublicKey33B64u: String(
          serverBootstrap.publicIdentity.relayerPublicKey33B64u || '',
        ).trim(),
        thresholdPublicKey33B64u: String(
          serverBootstrap.publicIdentity.groupPublicKey33B64u || '',
        ).trim(),
        ethereumAddress: String(serverBootstrap.ethereumAddress || '').trim(),
        clientShareRetryCounter: Math.floor(Number(serverBootstrap.clientShareRetryCounter)),
        serverShareRetryCounter: Math.floor(Number(serverBootstrap.relayerShareRetryCounter)),
      },
    });
  const walletId = String(serverBootstrap.walletId || '').trim();
  const evmFamilySigningKeySlotId = String(serverBootstrap.evmFamilySigningKeySlotId || '').trim();
  const ecdsaThresholdKeyId = String(serverBootstrap.ecdsaThresholdKeyId || '').trim();
  const keyHandle = String(serverBootstrap.keyHandle || '').trim();
  const signingRootId = String(serverBootstrap.signingRootId || '').trim();
  const signingRootVersion = String(serverBootstrap.signingRootVersion || '').trim();
  const applicationBindingDigestB64u = String(
    serverBootstrap.applicationBindingDigestB64u || '',
  ).trim();
  const thresholdEcdsaPublicKeyB64u = String(
    serverBootstrap.thresholdEcdsaPublicKeyB64u || '',
  ).trim();
  const ethereumAddress = String(serverBootstrap.ethereumAddress || '').trim();
  const relayerKeyId = String(serverBootstrap.relayerKeyId || '').trim();
  const relayerVerifyingShareB64u = String(serverBootstrap.relayerVerifyingShareB64u || '').trim();
  const thresholdSessionId = String(serverBootstrap.thresholdSessionId || '').trim();
  const signingGrantId = String(serverBootstrap.signingGrantId || '').trim();
  const remainingUses = Math.max(0, Math.floor(Number(serverBootstrap.remainingUses)));
  const expiresAtMs = Math.max(0, Math.floor(Number(serverBootstrap.expiresAtMs)));
  const participantIds = serverBootstrap.participantIds.map((participantId) =>
    Math.floor(Number(participantId)),
  );
  if (
    !walletId ||
    !evmFamilySigningKeySlotId ||
    !keyHandle ||
    !ecdsaThresholdKeyId ||
    !signingRootId ||
    !signingRootVersion ||
    !applicationBindingDigestB64u ||
    !thresholdEcdsaPublicKeyB64u ||
    !ethereumAddress ||
    !relayerKeyId ||
    !relayerVerifyingShareB64u ||
    !thresholdSessionId ||
    !signingGrantId ||
    !walletSessionJwt ||
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
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    relayerKeyId,
    applicationBindingDigestB64u,
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
    signingGrantId,
    expiresAtMs,
    remainingUses,
    walletSessionJwt,
    routerAbEcdsaHssNormalSigning,
  };
}

export async function buildWalletRegistrationEcdsaSessionBootstrap(args: {
  walletId: string;
  relayerUrl: string;
  chainTarget: ThresholdEcdsaChainTarget;
  keygenSessionId: string;
  readyStateBlob: EcdsaRoleLocalReadyStateBlob;
  signingMaterialHandle?: ThresholdEcdsaRoleLocalWorkerShareHandle;
  clientVerifyingShareB64u: string;
  serverBootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
  walletKey: WalletRegistrationEcdsaWalletKey;
  authMethod:
    | { kind: 'passkey'; credentialIdB64u: string; rpId: string }
    | { kind: 'email_otp'; authSubjectId?: string };
}): Promise<ThresholdEcdsaSessionBootstrapResult> {
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
  const evmFamilySigningKeySlotId = requireMatchingString({
    field: 'evmFamilySigningKeySlotId',
    expected: args.walletKey.evmFamilySigningKeySlotId,
    actual: serverBootstrap.evmFamilySigningKeySlotId,
  });
  const keyHandle = requireMatchingString({
    field: 'keyHandle',
    expected: args.walletKey.keyHandle,
    actual: serverBootstrap.keyHandle,
  });
  const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId(
    requireMatchingString({
      field: 'ecdsaThresholdKeyId',
      expected: args.walletKey.ecdsaThresholdKeyId,
      actual: serverBootstrap.ecdsaThresholdKeyId,
    }),
  );
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
  const walletSessionJwt = serverBootstrap.walletSessionJwt;
  const routerAbEcdsaHssNormalSigning = serverBootstrap.routerAbEcdsaHssNormalSigning;
  const thresholdSessionId = serverBootstrap.thresholdSessionId;
  const signingGrantId = serverBootstrap.signingGrantId;
  const remainingUses = serverBootstrap.remainingUses;
  const expiresAtMs = serverBootstrap.expiresAtMs;
  const expectedApplicationBindingDigestB64u = await computeSdkEcdsaHssApplicationBindingDigestB64u({
    walletId: toWalletId(args.walletId),
    ecdsaThresholdKeyId,
    signingRootId: parseSdkEcdsaHssSigningRootId(signingRootId),
    signingRootVersion: parseSdkEcdsaHssSigningRootVersion(signingRootVersion),
  });
  const applicationBindingDigestB64u = requireMatchingString({
    field: 'applicationBindingDigestB64u',
    expected: expectedApplicationBindingDigestB64u,
    actual: serverBootstrap.applicationBindingDigestB64u,
  });
  const publicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId: args.walletId,
    evmFamilySigningKeySlotId,
    chainTarget: args.chainTarget,
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    applicationBindingDigestB64u,
    participantIds,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    contextBinding32B64u: serverBootstrap.contextBinding32B64u,
    hssClientSharePublicKey33B64u: args.clientVerifyingShareB64u,
    relayerPublicKey33B64u: serverBootstrap.publicIdentity.relayerPublicKey33B64u,
    groupPublicKey33B64u: serverBootstrap.publicIdentity.groupPublicKey33B64u,
    ethereumAddress,
  });
  const ecdsaRoleLocalReadyRecord = buildEcdsaRoleLocalReadyRecord({
    stateBlob: args.readyStateBlob,
    publicFacts,
    authMethod:
      args.authMethod.kind === 'email_otp'
        ? buildEcdsaRoleLocalEmailOtpAuthMethod({
            authSubjectId: args.authMethod.authSubjectId,
          })
        : buildEcdsaRoleLocalPasskeyAuthMethod({
            credentialIdB64u: args.authMethod.credentialIdB64u,
            rpId: args.authMethod.rpId,
          }),
  });

  const keyRef: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: args.walletId,
    evmFamilySigningKeySlotId,
    chainTarget: args.chainTarget,
    relayerUrl: args.relayerUrl,
    keyHandle,
    ecdsaThresholdKeyId,
    backendBinding: args.signingMaterialHandle
      ? {
          materialKind: 'role_local_worker_handle',
          relayerKeyId,
          clientVerifyingShareB64u: args.clientVerifyingShareB64u,
          roleLocalMaterialHandle: args.signingMaterialHandle,
          ecdsaRoleLocalReadyRecord,
        }
      : {
          materialKind: 'role_local_ready_state_blob',
          relayerKeyId,
          clientVerifyingShareB64u: args.clientVerifyingShareB64u,
          stateBlob: args.readyStateBlob,
          ecdsaRoleLocalReadyRecord,
        },
    participantIds,
    thresholdEcdsaPublicKeyB64u,
    ethereumAddress,
    relayerVerifyingShareB64u,
    routerAbEcdsaHssNormalSigning,
    thresholdSessionKind: 'jwt',
    walletSessionJwt,
    thresholdSessionId,
    signingGrantId,
  };
  return {
    thresholdEcdsaKeyRef: keyRef,
    ...(args.authMethod.kind === 'passkey'
      ? { passkeyCredentialIdB64u: args.authMethod.credentialIdB64u }
      : {}),
    keygen: {
      ok: true,
      keygenSessionId: args.keygenSessionId,
      evmFamilySigningKeySlotId,
      keyHandle,
      ecdsaThresholdKeyId,
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      thresholdEcdsaPublicKeyB64u,
      ethereumAddress,
      relayerKeyId,
      relayerVerifyingShareB64u,
      participantIds,
      chainId: args.chainTarget.chainId,
    },
    session: {
      ok: true,
      thresholdSessionId,
      signingGrantId,
      expiresAtMs,
      remainingUses,
      jwt: walletSessionJwt,
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
  walletId: WalletId;
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
    body: createRegistrationIntentWireRequest(args.request),
    headers: args.headers,
  });
}

export async function prepareWalletRegistration(args: {
  relayerUrl: string;
  headers?: Record<string, string>;
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  intent: RegistrationIntentV1;
  work: { kind: 'ed25519_hss' | 'ed25519_hss_and_ecdsa' };
}): Promise<WalletRegistrationPrepareResponse> {
  const rawResponse = await postJson<unknown>({
    relayerUrl: args.relayerUrl,
    path: '/wallets/register/prepare',
    headers: args.headers,
    body: {
      registrationIntentGrant: args.registrationIntentGrant,
      registrationIntentDigestB64u: args.registrationIntentDigestB64u,
      intent: args.intent,
      work: args.work,
    },
  });
  return parseWalletRegistrationPrepareResponse(rawResponse);
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

export async function startWalletRegistration(
  args: {
    relayerUrl: string;
    headers?: Record<string, string>;
    registrationIntentGrant: RegistrationIntentGrant;
    registrationIntentDigestB64u: string;
    intent: RegistrationIntentV1;
    registrationPreparationId?: RegistrationPreparationId;
  } & WalletRegistrationStartAuthority,
): Promise<WalletRegistrationStartResponse> {
  const body = {
    registrationIntentGrant: args.registrationIntentGrant,
    registrationIntentDigestB64u: args.registrationIntentDigestB64u,
    intent: args.intent,
    ...(args.registrationPreparationId
      ? { registrationPreparationId: args.registrationPreparationId }
      : {}),
    ...walletRegistrationStartAuthorityBody(args),
  };
  return await postJson<WalletRegistrationStartResponse>({
    relayerUrl: args.relayerUrl,
    path: '/wallets/register/start',
    headers: args.headers,
    body,
  });
}

export async function respondWalletRegistrationHss(args: {
  relayerUrl: string;
  headers?: Record<string, string>;
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
    headers: args.headers,
    body: {
      registrationCeremonyId: args.registrationCeremonyId,
      ...(args.ed25519 ? { ed25519: args.ed25519 } : {}),
      ...(args.ecdsa ? { ecdsa: args.ecdsa } : {}),
    },
  });
}

export async function finalizeWalletRegistration(args: {
  relayerUrl: string;
  headers?: Record<string, string>;
  registrationCeremonyId: string;
  idempotencyKey?: string;
  ed25519?: {
    evaluationResult: ThresholdEd25519HssStagedEvaluatorArtifactEnvelope;
    sessionPolicy?: unknown;
    sessionKind?: 'jwt' | 'cookie';
  };
  ecdsa?: {
    expectedKeyHandles?: string[];
  };
  emailOtpEnrollment?: WalletRegistrationEmailOtpEnrollmentMaterial;
  emailOtpBackupAck?: WalletRegistrationEmailOtpBackupAck;
}): Promise<WalletRegistrationFinalizeResponse> {
  return await postJson<WalletRegistrationFinalizeResponse>({
    relayerUrl: args.relayerUrl,
    path: '/wallets/register/finalize',
    headers: args.headers,
    body: {
      registrationCeremonyId: args.registrationCeremonyId,
      ...(args.idempotencyKey ? { idempotencyKey: args.idempotencyKey } : {}),
      ...(args.ed25519 ? { ed25519: args.ed25519 } : {}),
      ...(args.ecdsa ? { ecdsa: args.ecdsa } : {}),
      ...(args.emailOtpEnrollment ? { emailOtpEnrollment: args.emailOtpEnrollment } : {}),
      ...(args.emailOtpBackupAck ? { emailOtpBackupAck: args.emailOtpBackupAck } : {}),
    },
  });
}

function addSignerAuthHeaders(auth: AddSignerAuth): Record<string, string> | undefined {
  if (auth.kind !== 'app_session') return undefined;
  return buildBearerAuthorizationHeader({
    token: auth.appSessionJwt,
    missingMessage: 'appSessionJwt is required for app-session add-signer auth',
  });
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
  return buildBearerAuthorizationHeader({
    token: auth.appSessionJwt,
    missingMessage: 'appSessionJwt is required for app-session add-auth-method auth',
  });
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

function addAuthMethodAuthorityBody(
  authority: WalletAddAuthMethodAuthority,
): Record<string, unknown> {
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
  return buildBearerAuthorizationHeader({
    token: auth.appSessionJwt,
    missingMessage: 'appSessionJwt is required for app-session auth-method revoke',
  });
}

function revokeAuthMethodAuthBody(auth: RevokeAuthMethodAuth): unknown {
  switch (auth.kind) {
    case 'webauthn_assertion':
      return {
        kind: 'webauthn_assertion',
        rpId: auth.rpId,
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
  auth: RevokeAuthMethodAuth;
  target: WalletAuthMethodTarget;
}): Promise<WalletRevokeAuthMethodResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for auth-method revoke');
  return await postJson<WalletRevokeAuthMethodResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/auth-methods/revoke`,
    headers: revokeAuthMethodAuthHeaders(args.auth),
    body: {
      auth: revokeAuthMethodAuthBody(args.auth),
      target: args.target,
    },
  });
}

export async function fetchWalletEcdsaKeyFactsInventoryWithAppSession(args: {
  relayerUrl: string;
  walletId: WalletId;
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
    throw new Error('walletId is required for ECDSA key-facts inventory');
  }
  if (!rpId) {
    throw new Error('rpId is required for ECDSA key-facts inventory');
  }
  if (!appSessionJwt) {
    throw new Error('appSessionJwt is required for ECDSA key-facts inventory');
  }
  if (String(args.policy.walletId || '').trim() !== walletId) {
    throw new Error('policy.walletId must match walletId for ECDSA key-facts inventory');
  }

  const data = await postJson<Record<string, unknown>>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/ecdsa/key-facts/inventory`,
    headers: buildBearerAuthorizationHeader({
      token: appSessionJwt,
      missingMessage: 'appSessionJwt is required for ECDSA key-facts inventory',
    }),
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
      walletId: args.walletId,
      rpId,
      records,
    }),
    diagnostics: Object.prototype.hasOwnProperty.call(data, 'diagnostics')
      ? data.diagnostics
      : null,
  };
}

export async function fetchWalletEcdsaKeyFactsInventoryWithWebAuthn(args: {
  relayerUrl: string;
  walletId: WalletId;
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
    throw new Error('walletId is required for ECDSA key-facts inventory');
  }
  if (!rpId) {
    throw new Error('rpId is required for ECDSA key-facts inventory');
  }
  if (!serverNonceB64u || !expectedChallengeDigestB64u) {
    throw new Error('WebAuthn ECDSA key-facts inventory requires challenge binding');
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
      walletId: args.walletId,
      rpId,
      records,
    }),
    diagnostics: Object.prototype.hasOwnProperty.call(data, 'diagnostics')
      ? data.diagnostics
      : null,
  };
}
