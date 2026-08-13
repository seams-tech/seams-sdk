import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  MAX_WALLET_SESSION_REMAINING_USES,
  MAX_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import { isPlainObject } from '@shared/utils/validation';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import {
  parseThresholdEd25519SessionId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  isPasskeyWalletAuthAuthority,
  parseWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { WebAuthnAuthenticationCredential } from '../../../../core/types';
import type {
  RouterAbEd25519YaoOperationStepUpGrantCommandV1,
  RouterAbEd25519YaoSessionPolicyV1,
  RouterAbEd25519YaoSessionRouteCommandV1,
} from './routerAbEd25519YaoWalletSession';

const OPERATION_STEP_UP_GRANT_KEYS = [
  'kind',
  'normalSigningRequest',
  'displayDigest',
  'proof',
  'materialRecovery',
] as const;
const OPERATION_STEP_UP_PASSKEY_PROOF_KEYS = [
  'kind',
  'authority',
  'webauthn_authentication',
] as const;
const OPERATION_STEP_UP_EMAIL_OTP_PROOF_KEYS = [
  'kind',
  'authority_ref',
  'provider_subject_id',
  'challenge_id',
  'otp_code',
] as const;
const OPERATION_STEP_UP_NO_MATERIAL_RECOVERY_KEYS = ['kind'] as const;
const OPERATION_STEP_UP_EMAIL_OTP_MATERIAL_RECOVERY_KEYS = [
  'kind',
  'worker_ephemeral_public_key_65_b64u',
] as const;
import {
  findUnexpectedRouteKey,
  optionalRouteTrimmedString,
  parseWebAuthnAuthenticationCredential,
} from '../../../framework/routeRequestValidation';

export type ThresholdEd25519RouteErrorBody = {
  ok: false;
  code: 'invalid_body';
  message: string;
};

type ThresholdEd25519RouteParseError = { ok: false; body: ThresholdEd25519RouteErrorBody };

export type ThresholdEd25519RouteParseResult<T> =
  | { ok: true; request: T }
  | ThresholdEd25519RouteParseError;

const SESSION_KEYS = [
  'relayerKeyId',
  'sessionPolicy',
  'projectEnvironmentId',
  'webauthn_authentication',
  'sessionKind',
] as const;

const SESSION_POLICY_KEYS = [
  'version',
  'nearAccountId',
  'nearEd25519SigningKeyId',
  'authority',
  'relayerKeyId',
  'thresholdSessionId',
  'runtimePolicyScope',
  'routerAbNormalSigning',
  'participantIds',
  'ttlMs',
  'remainingUses',
] as const;

function invalidThresholdEd25519Body(message: string): ThresholdEd25519RouteParseError {
  return { ok: false, body: { ok: false, code: 'invalid_body', message } };
}

function requiredStringField(
  record: Record<string, unknown>,
  field: string,
): ThresholdEd25519RouteParseResult<string> {
  const value = record[field];
  if (typeof value !== 'string' || !value.trim()) {
    return invalidThresholdEd25519Body(`${field} is required`);
  }
  return { ok: true, request: value.trim() };
}

function requiredThresholdEd25519SessionId(
  record: Record<string, unknown>,
  field: string,
): ThresholdEd25519RouteParseResult<ThresholdEd25519SessionId> {
  const value = requiredStringField(record, field);
  if (!value.ok) return value;
  const parsed = parseThresholdEd25519SessionId(value.request);
  return parsed.ok
    ? { ok: true, request: parsed.value }
    : invalidThresholdEd25519Body(`${field} is invalid`);
}

function optionalStringField(record: Record<string, unknown>, field: string): string | undefined {
  return optionalRouteTrimmedString(record, field);
}

function parseOptionalWebAuthnAuthentication(
  record: Record<string, unknown>,
): ThresholdEd25519RouteParseResult<WebAuthnAuthenticationCredential | null> {
  if (record.webauthn_authentication === undefined) {
    return { ok: true, request: null };
  }
  const credential = parseWebAuthnAuthenticationCredential(record.webauthn_authentication);
  return credential
    ? { ok: true, request: credential }
    : invalidThresholdEd25519Body('webauthn_authentication is invalid');
}

export function parseRouterAbEd25519YaoSessionPolicyV1(
  raw: unknown,
): ThresholdEd25519RouteParseResult<RouterAbEd25519YaoSessionPolicyV1> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('sessionPolicy is required');
  if (Object.prototype.hasOwnProperty.call(raw, 'rpId')) {
    return invalidThresholdEd25519Body('sessionPolicy.rpId belongs in sessionPolicy.authority');
  }
  const unsupported = findUnexpectedRouteKey(raw, SESSION_POLICY_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(
      `Unsupported threshold-ed25519 sessionPolicy field: ${unsupported}`,
    );
  }
  if (raw.version !== 'threshold_session_v1') {
    return invalidThresholdEd25519Body('sessionPolicy.version must be threshold_session_v1');
  }
  const nearAccountId = requiredStringField(raw, 'nearAccountId');
  if (!nearAccountId.ok) return nearAccountId;
  const nearEd25519SigningKeyId = requiredStringField(raw, 'nearEd25519SigningKeyId');
  if (!nearEd25519SigningKeyId.ok) return nearEd25519SigningKeyId;
  const authority = parseWalletAuthAuthority(raw.authority);
  if (!authority) {
    return invalidThresholdEd25519Body('sessionPolicy.authority is invalid');
  }
  const relayerKeyId = requiredStringField(raw, 'relayerKeyId');
  if (!relayerKeyId.ok) return relayerKeyId;
  const thresholdSessionId = requiredThresholdEd25519SessionId(raw, 'thresholdSessionId');
  if (!thresholdSessionId.ok) return thresholdSessionId;
  if (
    typeof raw.ttlMs !== 'number' ||
    !Number.isSafeInteger(raw.ttlMs) ||
    raw.ttlMs <= 0 ||
    raw.ttlMs > MAX_WALLET_SESSION_TTL_MS
  ) {
    return invalidThresholdEd25519Body('sessionPolicy.ttlMs is required');
  }
  if (
    typeof raw.remainingUses !== 'number' ||
    !Number.isSafeInteger(raw.remainingUses) ||
    raw.remainingUses <= 0 ||
    raw.remainingUses > MAX_WALLET_SESSION_REMAINING_USES
  ) {
    return invalidThresholdEd25519Body('sessionPolicy.remainingUses is required');
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  if (!participantIds || participantIds.length !== 2 || participantIds[0] === participantIds[1]) {
    return invalidThresholdEd25519Body(
      'sessionPolicy.participantIds must contain exactly two distinct participants',
    );
  }
  let runtimePolicyScope: RouterAbEd25519YaoSessionPolicyV1['runtimePolicyScope'];
  try {
    runtimePolicyScope = normalizeRuntimePolicyScope(raw.runtimePolicyScope);
  } catch {
    return invalidThresholdEd25519Body('sessionPolicy.runtimePolicyScope is required');
  }
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(raw.routerAbNormalSigning);
  if (!routerAbNormalSigning) {
    return invalidThresholdEd25519Body('sessionPolicy.routerAbNormalSigning is required');
  }
  return {
    ok: true,
    request: {
      version: 'threshold_session_v1',
      nearAccountId: nearAccountId.request,
      nearEd25519SigningKeyId: nearEd25519SigningKeyId.request,
      authority,
      relayerKeyId: relayerKeyId.request,
      thresholdSessionId: thresholdSessionId.request,
      runtimePolicyScope,
      routerAbNormalSigning,
      participantIds: [participantIds[0]!, participantIds[1]!],
      ttlMs: raw.ttlMs,
      remainingUses: raw.remainingUses,
    },
  };
}

export function parseThresholdEd25519SessionRouteRequest(
  raw: unknown,
): ThresholdEd25519RouteParseResult<RouterAbEd25519YaoSessionRouteCommandV1> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('Expected JSON object body');
  if (raw.sessionKind !== 'jwt') {
    return invalidThresholdEd25519Body(
      'Router A/B Ed25519 Wallet Session issuance requires sessionKind=jwt',
    );
  }
  const unsupported = findUnexpectedRouteKey(raw, SESSION_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(
      `Unsupported threshold-ed25519 session field: ${unsupported}`,
    );
  }
  const relayerKeyId = requiredStringField(raw, 'relayerKeyId');
  if (!relayerKeyId.ok) return relayerKeyId;
  const sessionPolicy = parseRouterAbEd25519YaoSessionPolicyV1(raw.sessionPolicy);
  if (!sessionPolicy.ok) return sessionPolicy;
  if (sessionPolicy.request.relayerKeyId !== relayerKeyId.request) {
    return invalidThresholdEd25519Body('relayerKeyId must match sessionPolicy.relayerKeyId');
  }
  const webauthnAuthentication = parseOptionalWebAuthnAuthentication(raw);
  if (!webauthnAuthentication.ok) return webauthnAuthentication;
  const projectEnvironmentId = optionalStringField(raw, 'projectEnvironmentId');
  return {
    ok: true,
    request: {
      relayerKeyId: relayerKeyId.request,
      sessionPolicy: sessionPolicy.request,
      ...(projectEnvironmentId ? { projectEnvironmentId } : {}),
      routeAuth: webauthnAuthentication.request
        ? {
            kind: 'passkey',
            webauthnAuthentication: webauthnAuthentication.request,
          }
        : { kind: 'signed_session' },
      sessionKind: 'jwt',
    },
  };
}

export function parseThresholdEd25519OperationStepUpGrantRequest(
  raw: unknown,
): ThresholdEd25519RouteParseResult<RouterAbEd25519YaoOperationStepUpGrantCommandV1> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('Expected JSON object body');
  const unsupported = findUnexpectedRouteKey(raw, OPERATION_STEP_UP_GRANT_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(`Unsupported operation step-up grant field: ${unsupported}`);
  }
  if (raw.kind !== 'router_ab_ed25519_yao_operation_step_up_grant_v1') {
    return invalidThresholdEd25519Body(
      'kind must be router_ab_ed25519_yao_operation_step_up_grant_v1',
    );
  }
  if (!isPlainObject(raw.normalSigningRequest)) {
    return invalidThresholdEd25519Body('normalSigningRequest is required');
  }
  const displayDigest = requiredStringField(raw, 'displayDigest');
  if (!displayDigest.ok) return displayDigest;
  if (!isPlainObject(raw.proof)) {
    return invalidThresholdEd25519Body('proof is required');
  }
  if (!isPlainObject(raw.materialRecovery)) {
    return invalidThresholdEd25519Body('materialRecovery is required');
  }
  const proof = raw.proof;
  const materialRecovery = raw.materialRecovery;
  switch (proof.kind) {
    case 'passkey': {
      const authority = parseWalletAuthAuthority(proof.authority);
      const unsupportedProofKey = findUnexpectedRouteKey(
        proof,
        OPERATION_STEP_UP_PASSKEY_PROOF_KEYS,
      );
      if (unsupportedProofKey) {
        return invalidThresholdEd25519Body(
          `Unsupported passkey operation step-up proof field: ${unsupportedProofKey}`,
        );
      }
      if (!authority || !isPasskeyWalletAuthAuthority(authority)) {
        return invalidThresholdEd25519Body('proof.authority must be an exact passkey authority');
      }
      const credential = parseOptionalWebAuthnAuthentication(proof);
      if (!credential.ok) return credential;
      if (!credential.request) {
        return invalidThresholdEd25519Body('proof.webauthn_authentication is required');
      }
      const unsupportedMaterialRecoveryKey = findUnexpectedRouteKey(
        materialRecovery,
        OPERATION_STEP_UP_NO_MATERIAL_RECOVERY_KEYS,
      );
      if (unsupportedMaterialRecoveryKey) {
        return invalidThresholdEd25519Body(
          `Unsupported Passkey operation step-up material recovery field: ${unsupportedMaterialRecoveryKey}`,
        );
      }
      if (materialRecovery.kind !== 'not_requested') {
        return invalidThresholdEd25519Body(
          'Passkey operation step-up materialRecovery.kind must be not_requested',
        );
      }
      return {
        ok: true,
        request: {
          kind: 'router_ab_ed25519_yao_operation_step_up_grant_v1',
          normalSigningRequest: raw.normalSigningRequest,
          displayDigest: displayDigest.request,
          proof: {
            kind: 'passkey',
            authority,
            webauthnAuthentication: credential.request,
          },
          materialRecovery: { kind: 'not_requested' },
        },
      };
    }
    case 'email_otp': {
      const unsupportedProofKey = findUnexpectedRouteKey(
        proof,
        OPERATION_STEP_UP_EMAIL_OTP_PROOF_KEYS,
      );
      if (unsupportedProofKey) {
        return invalidThresholdEd25519Body(
          `Unsupported Email OTP operation step-up proof field: ${unsupportedProofKey}`,
        );
      }
      const authorityRef = parseWalletAuthAuthorityRef(proof.authority_ref);
      if (!authorityRef) {
        return invalidThresholdEd25519Body(
          'proof.authority_ref must be an exact wallet authority reference',
        );
      }
      const providerSubjectId = requiredStringField(proof, 'provider_subject_id');
      if (!providerSubjectId.ok) return providerSubjectId;
      const challengeId = requiredStringField(proof, 'challenge_id');
      if (!challengeId.ok) return challengeId;
      const otpCode = requiredStringField(proof, 'otp_code');
      if (!otpCode.ok) return otpCode;
      let parsedMaterialRecovery: RouterAbEd25519YaoOperationStepUpGrantCommandV1['materialRecovery'];
      switch (materialRecovery.kind) {
        case 'not_requested': {
          const unsupportedMaterialRecoveryKey = findUnexpectedRouteKey(
            materialRecovery,
            OPERATION_STEP_UP_NO_MATERIAL_RECOVERY_KEYS,
          );
          if (unsupportedMaterialRecoveryKey) {
            return invalidThresholdEd25519Body(
              `Unsupported Email OTP operation step-up material recovery field: ${unsupportedMaterialRecoveryKey}`,
            );
          }
          parsedMaterialRecovery = { kind: 'not_requested' };
          break;
        }
        case 'email_otp_factor_release_v1': {
          const unsupportedMaterialRecoveryKey = findUnexpectedRouteKey(
            materialRecovery,
            OPERATION_STEP_UP_EMAIL_OTP_MATERIAL_RECOVERY_KEYS,
          );
          if (unsupportedMaterialRecoveryKey) {
            return invalidThresholdEd25519Body(
              `Unsupported Email OTP operation step-up material recovery field: ${unsupportedMaterialRecoveryKey}`,
            );
          }
          const workerEphemeralPublicKey65B64u = requiredStringField(
            materialRecovery,
            'worker_ephemeral_public_key_65_b64u',
          );
          if (!workerEphemeralPublicKey65B64u.ok) return workerEphemeralPublicKey65B64u;
          parsedMaterialRecovery = {
            kind: 'email_otp_factor_release_v1',
            workerEphemeralPublicKey65B64u: workerEphemeralPublicKey65B64u.request,
          };
          break;
        }
        default:
          return invalidThresholdEd25519Body(
            'Email OTP operation step-up materialRecovery.kind is invalid',
          );
      }
      return {
        ok: true,
        request: {
          kind: 'router_ab_ed25519_yao_operation_step_up_grant_v1',
          normalSigningRequest: raw.normalSigningRequest,
          displayDigest: displayDigest.request,
          proof: {
            kind: 'email_otp',
            authorityRef,
            providerSubjectId: providerSubjectId.request,
            challengeId: challengeId.request,
            otpCode: otpCode.request,
          },
          materialRecovery: parsedMaterialRecovery,
        },
      };
    }
    default:
      return invalidThresholdEd25519Body('proof.kind must be passkey or email_otp');
  }
}
