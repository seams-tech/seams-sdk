import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
  computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32B64u,
  computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u,
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
  type EcdsaClientRootPublicKey33B64u,
  type EcdsaHssClientSharePublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdEcdsaHssRoleLocalClientState } from '../../interfaces/signing';
import {
  thresholdEcdsaHssRoleLocalBootstrap,
  type ThresholdEcdsaHssRoleLocalClientRootProof,
  type ThresholdEcdsaHssRoleLocalPasskeyBootstrapAuthorization,
  type ThresholdEcdsaHssRoleLocalBootstrapRequest,
  type ThresholdEcdsaHssRouteAuth,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import { decodeJwtPayloadRecord } from '@shared/utils/sessionTokens';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { type ThresholdIndexedDbPort, type ThresholdWebAuthnPromptPort } from '../crypto/webauthn';
import {
  buildEcdsaHssSessionPolicy,
  clampThresholdSessionPolicy,
  DEFAULT_THRESHOLD_SESSION_POLICY,
  generateThresholdSessionId,
  generateWalletSigningSessionId,
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '../sessionPolicy';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
} from '../../session/identity/emailOtpHssIdentity';
import {
  finalizeEcdsaClientBootstrapCommandWasm,
  prepareEcdsaClientBootstrapCommandWasm,
} from '../crypto/hssClientSignerWasm';
import {
  buildEmailOtpWorkerSessionSecretSource,
  buildWebAuthnPrfFirstSecretSourceFromParts,
  type EcdsaBootstrapSecretSource,
  type EmailOtpWorkerIssuedSessionHandle,
  type PrepareEcdsaClientBootstrapOutput,
} from '@/core/platform/types';
import {
  parseGeneratedFinalizeEcdsaClientBootstrapOutput,
  parseGeneratedPrepareEcdsaClientBootstrapOutput,
  toGeneratedFinalizeEcdsaClientBootstrapCommand,
  toGeneratedPrepareEcdsaClientBootstrapCommand,
} from '@/core/platform/signerCoreCommandAdapters';
import { type ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaSessionLanePolicy,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  deriveEvmFamilyKeyFingerprint,
  toRpId,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import { thresholdEcdsaChainTargetKey, toWalletId } from '../../interfaces/ecdsaChainTarget';
import { collectAuthenticationCredentialForWalletChallengeB64u } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import { getPrfFirstB64uFromCredential } from '../../webauthnAuth/credentials/credentialExtensions';
import { buildEcdsaRoleLocalPublicFacts } from '../../session/persistence/ecdsaRoleLocalRecords';
import {
  secp256k1PrivateKey32ToPublicKey33Wasm,
  signSecp256k1RecoverableWasm,
} from '../../chains/evm/ethSignerWasm';

const PASSKEY_THRESHOLD_ECDSA_CLIENT_ROOT_INFO_V1 =
  'seams/passkey/threshold-ecdsa-client-root/v1';

function joinUrlPath(base: string, path: string): string {
  return `${String(base || '').replace(/\/+$/, '')}/${String(path || '').replace(/^\/+/, '')}`;
}

async function postJsonExpectOk(args: {
  url: string;
  headers?: Record<string, string>;
  operation: string;
  body: unknown;
}): Promise<Record<string, unknown>> {
  if (typeof fetch !== 'function') {
    throw new Error(`${args.operation} requires fetch`);
  }
  const response = await fetch(args.url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(args.headers || {}),
    },
    credentials: 'omit',
    body: JSON.stringify(args.body),
  });
  const data = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok || data.ok === false) {
    throw new Error(
      String(data.message || data.code || `${args.operation} failed with HTTP ${response.status}`),
    );
  }
  return data;
}

async function requestManagedRegistrationBootstrapGrant(args: {
  relayerUrl: string;
  environmentId: string;
  publishableKey: string;
  walletId: string;
  rpId: string;
}): Promise<{ token: string; runtimePolicyScope: ThresholdRuntimePolicyScope }> {
  const data = await postJsonExpectOk({
    url: joinUrlPath(args.relayerUrl, '/v1/registration/bootstrap-grants'),
    headers: { Authorization: `Bearer ${args.publishableKey}` },
    operation: 'Managed registration bootstrap grant',
    body: {
      environmentId: args.environmentId,
      newAccountId: args.walletId,
      rpId: args.rpId,
      flow: 'registration_v1',
    },
  });
  const grant =
    data.grant && typeof data.grant === 'object' && !Array.isArray(data.grant)
      ? (data.grant as Record<string, unknown>)
      : {};
  const token = String(grant.token || '').trim();
  const orgId = String(grant.orgId || '').trim();
  const projectId = String(grant.projectId || '').trim();
  const envId = String(grant.envId || '').trim();
  const signingRootVersion = String(grant.signingRootVersion || '').trim();
  if (!token || !orgId || !projectId || !envId || !signingRootVersion) {
    throw new Error('Managed registration grant response missing token or runtime scope');
  }
  return {
    token,
    runtimePolicyScope: {
      orgId,
      projectId,
      envId,
      signingRootVersion,
    },
  };
}

function generateKeygenSessionId(): string {
  return secureRandomId('tecdsa-keygen', 32, 'threshold ECDSA keygen session IDs');
}

function summarizeJwtClaims(jwtRaw: string | undefined): Record<string, unknown> {
  const payload = decodeJwtPayloadRecord(String(jwtRaw || '').trim());
  if (!payload) return { present: false };
  return {
    present: true,
    kind: payload.kind,
    sub: payload.sub,
    walletId: payload.walletId,
    userId: payload.userId,
    sessionId: payload.sessionId,
    walletSigningSessionId: payload.walletSigningSessionId,
    exp: payload.exp,
  };
}

function summarizeHssRouteAuth(
  auth: ThresholdEcdsaHssRouteAuth | undefined,
): Record<string, unknown> {
  if (!auth) return { kind: 'none' };
  if (auth.kind === 'threshold_session' || auth.kind === 'app_session') {
    return {
      kind: auth.kind,
      jwtClaims: summarizeJwtClaims(auth.jwt),
    };
  }
  if (auth.kind === 'cookie') return { kind: 'cookie' };
  return { kind: auth.kind, hasToken: Boolean(String(auth.token || '').trim()) };
}

async function emitBootstrapChallengeDiagnostic(args: {
  challengeB64u?: string;
  requestId: string;
  sessionId: string;
  walletSigningSessionId: string;
  challengeKind: 'ecdsa_role_local_bootstrap';
}): Promise<void> {
  const challengeB64u = String(args.challengeB64u || '').trim();
  if (!challengeB64u) return;
  try {
    const challengeHash8 = base64UrlEncode(await sha256BytesUtf8(challengeB64u)).slice(0, 8);
    console.info('[threshold-ecdsa][webauthn-challenge]', {
      stage: 'bootstrap_verify',
      challengeKind: args.challengeKind,
      challengeHash8,
      requestId: args.requestId,
      thresholdSessionId: args.sessionId,
      walletSigningSessionId: args.walletSigningSessionId,
    });
  } catch {}
}

type BootstrapSecretSourceResolution =
  | {
      ok: true;
      kind: 'email_otp';
      secretSource: EcdsaBootstrapSecretSource;
      authorizationCredential?: never;
      passkeyPrfFirstB64u?: never;
      credentialIdB64u?: never;
    }
  | {
      ok: true;
      kind: 'passkey';
      secretSource: Extract<EcdsaBootstrapSecretSource, { kind: 'webauthn_prf_first' }>;
      authorizationCredential: WebAuthnAuthenticationCredential | null;
      passkeyPrfFirstB64u: string;
      credentialIdB64u: string;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

function credentialIdB64uFromAuthenticationCredential(
  credential: WebAuthnAuthenticationCredential,
): string {
  const credentialIdB64u = String(credential.rawId || credential.id || '').trim();
  if (!credentialIdB64u) {
    throw new Error('threshold-ecdsa passkey bootstrap requires credential id');
  }
  return credentialIdB64u;
}

function passkeyPrfSecretSourceFromParts(args: {
  prfFirstB64u: string;
  rpId: string;
  credentialIdB64u: string;
}): Extract<EcdsaBootstrapSecretSource, { kind: 'webauthn_prf_first' }> {
  return buildWebAuthnPrfFirstSecretSourceFromParts({
    prfFirstB64u: args.prfFirstB64u,
    rpId: toRpId(args.rpId),
    credentialIdB64u: args.credentialIdB64u,
  });
}

type ResolveBootstrapSecretSourceRequest =
  | {
      kind: 'email_otp';
      emailOtpWorkerSessionHandle: Extract<
        EmailOtpWorkerIssuedSessionHandle,
        { action: 'threshold_ecdsa_bootstrap' }
      >;
    }
  | {
      kind: 'passkey_prf_first_bytes';
      providedPrfFirst32: Uint8Array;
      credentialIdB64u: string;
      authorizationCredential: WebAuthnAuthenticationCredential | null;
      rpId: string;
    }
  | {
      kind: 'passkey_prf_first_b64u';
      providedPrfFirstB64u: string;
      credentialIdB64u: string;
      authorizationCredential: WebAuthnAuthenticationCredential | null;
      rpId: string;
    }
  | {
      kind: 'passkey_webauthn_credential';
      credential: WebAuthnAuthenticationCredential;
      rpId: string;
    }
  | {
      kind: 'passkey_webauthn_challenge';
      indexedDB: ThresholdIndexedDbPort;
      touchIdPrompt: ThresholdWebAuthnPromptPort;
      walletId: string;
      challengeB64u: string;
      rpId: string;
    };

type BuildBootstrapSecretSourceRequestResult =
  | {
      ok: true;
      request: ResolveBootstrapSecretSourceRequest;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

function passkeyBootstrapSecretSourceResolution(args: {
  prfFirstB64u: string;
  credentialIdB64u: string;
  authorizationCredential: WebAuthnAuthenticationCredential | null;
  rpId: string;
}): BootstrapSecretSourceResolution {
  return {
    ok: true,
    kind: 'passkey',
    passkeyPrfFirstB64u: args.prfFirstB64u,
    credentialIdB64u: args.credentialIdB64u,
    authorizationCredential: args.authorizationCredential,
    secretSource: passkeyPrfSecretSourceFromParts({
      prfFirstB64u: args.prfFirstB64u,
      rpId: args.rpId,
      credentialIdB64u: args.credentialIdB64u,
    }),
  };
}

function passkeyBootstrapSecretSourceResolutionFromCredential(args: {
  credential: WebAuthnAuthenticationCredential;
  rpId: string;
}): BootstrapSecretSourceResolution {
  const passkeyPrfFirstB64u = String(getPrfFirstB64uFromCredential(args.credential) || '').trim();
  if (!passkeyPrfFirstB64u) {
    return {
      ok: false,
      code: 'unsupported',
      message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
    };
  }
  let credentialIdB64u: string;
  try {
    credentialIdB64u = credentialIdB64uFromAuthenticationCredential(args.credential);
  } catch (error) {
    return {
      ok: false,
      code: 'invalid_args',
      message:
        error instanceof Error
          ? error.message
          : 'threshold-ecdsa passkey bootstrap requires credential id',
    };
  }
  return passkeyBootstrapSecretSourceResolution({
    prfFirstB64u: passkeyPrfFirstB64u,
    credentialIdB64u,
    authorizationCredential: args.credential,
    rpId: args.rpId,
  });
}

async function derivePasskeyThresholdEcdsaClientRootShare32(args: {
  prfFirstB64u: string;
}): Promise<Uint8Array> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('threshold-ecdsa passkey client root proof requires WebCrypto HKDF');
  }
  const prfFirst32 = base64UrlDecode(args.prfFirstB64u);
  const salt32 = new Uint8Array(32);
  if (prfFirst32.length !== 32) {
    prfFirst32.fill(0);
    throw new Error('threshold-ecdsa passkey PRF.first must be 32 bytes');
  }
  try {
    const hkdfKey = await globalThis.crypto.subtle.importKey('raw', prfFirst32, 'HKDF', false, [
      'deriveBits',
    ]);
    const bits = await globalThis.crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt32,
        info: new TextEncoder().encode(PASSKEY_THRESHOLD_ECDSA_CLIENT_ROOT_INFO_V1),
      },
      hkdfKey,
      256,
    );
    return new Uint8Array(bits);
  } finally {
    prfFirst32.fill(0);
    salt32.fill(0);
  }
}

async function buildEcdsaClientRootProof(args: {
  bootstrapRequest: ThresholdEcdsaHssRoleLocalBootstrapRequest;
  passkeyPrfFirstB64u: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEcdsaHssRoleLocalClientRootProof> {
  const digest32B64u = await computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32B64u(
    args.bootstrapRequest,
  );
  const digest32 = base64UrlDecode(digest32B64u);
  const clientRootShare32 = await derivePasskeyThresholdEcdsaClientRootShare32({
    prfFirstB64u: args.passkeyPrfFirstB64u,
  });
  try {
    const clientRootPublicKey33 = await secp256k1PrivateKey32ToPublicKey33Wasm({
      privateKey32: clientRootShare32,
      workerCtx: args.workerCtx,
    });
    const signature65 = await signSecp256k1RecoverableWasm({
      digest32,
      privateKey32: clientRootShare32,
      workerCtx: args.workerCtx,
    });
    return {
      version: ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
      clientRootPublicKey33B64u: base64UrlEncode(
        clientRootPublicKey33,
      ) as EcdsaClientRootPublicKey33B64u,
      digest32B64u,
      signature65B64u: base64UrlEncode(signature65),
    };
  } finally {
    digest32.fill(0);
    clientRootShare32.fill(0);
  }
}

async function resolveBootstrapSecretSource(
  args: ResolveBootstrapSecretSourceRequest,
): Promise<BootstrapSecretSourceResolution> {
  switch (args.kind) {
    case 'email_otp':
      return {
        ok: true,
        kind: 'email_otp',
        secretSource: buildEmailOtpWorkerSessionSecretSource(args.emailOtpWorkerSessionHandle),
      };
    case 'passkey_prf_first_bytes':
      if (args.providedPrfFirst32.length !== 32) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'threshold-ecdsa passkey PRF.first bytes must be 32 bytes',
        };
      }
      return passkeyBootstrapSecretSourceResolution({
        prfFirstB64u: base64UrlEncode(args.providedPrfFirst32),
        credentialIdB64u: args.credentialIdB64u,
        authorizationCredential: args.authorizationCredential,
        rpId: args.rpId,
      });
    case 'passkey_prf_first_b64u':
      return passkeyBootstrapSecretSourceResolution({
        prfFirstB64u: args.providedPrfFirstB64u,
        credentialIdB64u: args.credentialIdB64u,
        authorizationCredential: args.authorizationCredential,
        rpId: args.rpId,
      });
    case 'passkey_webauthn_credential':
      return passkeyBootstrapSecretSourceResolutionFromCredential({
        credential: args.credential,
        rpId: args.rpId,
      });
    case 'passkey_webauthn_challenge': {
      const credential = await collectAuthenticationCredentialForWalletChallengeB64u({
        indexedDB: args.indexedDB,
        touchIdPrompt: args.touchIdPrompt,
        walletId: args.walletId,
        challengeB64u: args.challengeB64u,
      });
      if (!credential) {
        return {
          ok: false,
          code: 'invalid_args',
          message:
            'Missing threshold-ecdsa passkey PRF.first for bootstrap; reconnect with WebAuthn or provide primed session material',
        };
      }
      return passkeyBootstrapSecretSourceResolutionFromCredential({
        credential,
        rpId: args.rpId,
      });
    }
  }
  args satisfies never;
  return { ok: false, code: 'invalid_args', message: 'Unsupported ECDSA bootstrap secret source' };
}

function buildBootstrapSecretSourceRequest(args: {
  sessionArgs: BootstrapEcdsaSessionArgs;
  challengeB64u: string;
  userId: string;
  rpId: string;
}): BuildBootstrapSecretSourceRequestResult {
  switch (args.sessionArgs.authKind) {
    case 'email_otp':
      return {
        ok: true,
        request: {
          kind: 'email_otp',
          emailOtpWorkerSessionHandle: args.sessionArgs.emailOtpWorkerSessionHandle,
        },
      };
    case 'passkey_prf_bytes':
      return {
        ok: true,
        request: {
          kind: 'passkey_prf_first_bytes',
          providedPrfFirst32: args.sessionArgs.passkeyPrfFirst32,
          credentialIdB64u: args.sessionArgs.passkeyCredentialIdB64u,
          authorizationCredential: null,
          rpId: args.rpId,
        },
      };
    case 'passkey_prf_b64u':
      return {
        ok: true,
        request: {
          kind: 'passkey_prf_first_b64u',
          providedPrfFirstB64u: args.sessionArgs.passkeyPrfFirstB64u,
          credentialIdB64u: args.sessionArgs.passkeyCredentialIdB64u,
          authorizationCredential: null,
          rpId: args.rpId,
        },
      };
    case 'passkey_webauthn_prf_b64u': {
      let credentialIdB64u: string;
      try {
        credentialIdB64u = credentialIdB64uFromAuthenticationCredential(
          args.sessionArgs.webauthnAuthentication,
        );
      } catch (error) {
        return {
          ok: false,
          code: 'invalid_args',
          message:
            error instanceof Error
              ? error.message
              : 'threshold-ecdsa passkey bootstrap requires credential id',
        };
      }
      return {
        ok: true,
        request: {
          kind: 'passkey_prf_first_b64u',
          providedPrfFirstB64u: args.sessionArgs.passkeyPrfFirstB64u,
          credentialIdB64u,
          authorizationCredential: args.sessionArgs.webauthnAuthentication,
          rpId: args.rpId,
        },
      };
    }
    case 'passkey_webauthn':
      return {
        ok: true,
        request: {
          kind: 'passkey_webauthn_credential',
          credential: args.sessionArgs.webauthnAuthentication,
          rpId: args.rpId,
        },
      };
    case 'passkey_prompt':
      if (args.challengeB64u) {
        return {
          ok: true,
          request: {
            kind: 'passkey_webauthn_challenge',
            indexedDB: args.sessionArgs.indexedDB,
            touchIdPrompt: args.sessionArgs.touchIdPrompt,
            walletId: args.userId,
            challengeB64u: args.challengeB64u,
            rpId: args.rpId,
          },
        };
      }
      return {
        ok: false,
        code: 'invalid_args',
        message:
          'Missing threshold-ecdsa passkey PRF.first for bootstrap; reconnect with WebAuthn or provide primed session material',
      };
  }
  args.sessionArgs satisfies never;
  return { ok: false, code: 'invalid_args', message: 'Unsupported ECDSA bootstrap auth source' };
}

async function prepareEcdsaClientBootstrapForSecretSource(args: {
  input: Parameters<typeof toGeneratedPrepareEcdsaClientBootstrapCommand>[0];
  workerCtx: WorkerOperationContext;
}): Promise<PrepareEcdsaClientBootstrapOutput> {
  const command = toGeneratedPrepareEcdsaClientBootstrapCommand(args.input);
  if (command.secretSource.kind === 'email_otp_worker_session') {
    const generatedOutput = await args.workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'prepareEcdsaClientBootstrapFromEmailOtpHandle',
        timeoutMs: 60_000,
        payload: { command },
      },
    });
    return parseGeneratedPrepareEcdsaClientBootstrapOutput(generatedOutput);
  }
  const generatedOutput = await prepareEcdsaClientBootstrapCommandWasm({
    command,
    workerCtx: args.workerCtx,
  });
  return parseGeneratedPrepareEcdsaClientBootstrapOutput(generatedOutput);
}

type BootstrapEcdsaSessionBaseArgs = {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  relayerUrl: string;
  userId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  participantIds?: number[];
  sessionKind?: ThresholdSessionKind;
  requestId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  ttlMs?: number;
  remainingUses?: number;
  workerCtx: WorkerOperationContext;
};

type BootstrapEcdsaPasskeyPromptAuthArgs = {
  authKind: 'passkey_prompt';
  passkeyPrfFirst32?: never;
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
  emailOtpWorkerSessionHandle?: never;
  webauthnAuthentication?: never;
};

type BootstrapEcdsaPasskeyWebAuthnAuthArgs = {
  authKind: 'passkey_webauthn';
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  passkeyPrfFirst32?: never;
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
  emailOtpWorkerSessionHandle?: never;
};

type BootstrapEcdsaPasskeyWebAuthnPrfB64uAuthArgs = {
  authKind: 'passkey_webauthn_prf_b64u';
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  passkeyPrfFirstB64u: string;
  passkeyPrfFirst32?: never;
  passkeyCredentialIdB64u?: never;
  emailOtpWorkerSessionHandle?: never;
};

type BootstrapEcdsaPasskeyPrfB64uAuthArgs = {
  authKind: 'passkey_prf_b64u';
  passkeyPrfFirstB64u: string;
  passkeyCredentialIdB64u: string;
  passkeyPrfFirst32?: never;
  emailOtpWorkerSessionHandle?: never;
  webauthnAuthentication?: never;
};

type BootstrapEcdsaPasskeyPrfBytesAuthArgs = {
  authKind: 'passkey_prf_bytes';
  passkeyPrfFirst32: Uint8Array;
  passkeyCredentialIdB64u: string;
  passkeyPrfFirstB64u?: never;
  emailOtpWorkerSessionHandle?: never;
  webauthnAuthentication?: never;
};

type BootstrapEcdsaEmailOtpAuthArgs = {
  authKind: 'email_otp';
  emailOtpWorkerSessionHandle: Extract<
    EmailOtpWorkerIssuedSessionHandle,
    { action: 'threshold_ecdsa_bootstrap' }
  >;
  passkeyPrfFirst32?: never;
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
  webauthnAuthentication?: never;
};

export type BootstrapEcdsaSessionAuthArgs =
  | BootstrapEcdsaPasskeyPromptAuthArgs
  | BootstrapEcdsaPasskeyWebAuthnAuthArgs
  | BootstrapEcdsaPasskeyWebAuthnPrfB64uAuthArgs
  | BootstrapEcdsaPasskeyPrfB64uAuthArgs
  | BootstrapEcdsaPasskeyPrfBytesAuthArgs
  | BootstrapEcdsaEmailOtpAuthArgs;

type BootstrapEcdsaRegistrationArgs = BootstrapEcdsaSessionBaseArgs &
  BootstrapEcdsaSessionAuthArgs & {
    bootstrapAuth?: ThresholdEcdsaHssRouteAuth;
    ecdsaThresholdKeyId?: string;
    sessionId?: string;
    walletSigningSessionId?: string;
  };

type BootstrapEcdsaExactSessionArgs = BootstrapEcdsaSessionBaseArgs &
  BootstrapEcdsaSessionAuthArgs & {
    bootstrapAuth?: ThresholdEcdsaHssRouteAuth;
    keyHandle: EvmFamilyEcdsaKeyHandle;
    key: EvmFamilyEcdsaKeyIdentity;
    lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
    ecdsaThresholdKeyId?: never;
    sessionId?: never;
    walletSigningSessionId?: never;
  };

type BootstrapEcdsaSessionArgs = BootstrapEcdsaRegistrationArgs | BootstrapEcdsaExactSessionArgs;

type BootstrapEcdsaSessionFailure = {
  ok: false;
  code: string;
  message: string;
};

type BootstrapEcdsaSessionSuccessCommon = {
  ok: true;
  keygenSessionId: string;
  rpId: string;
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  clientVerifyingShareB64u: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  relayerKeyId: string;
  relayerVerifyingShareB64u: string;
  participantIds: number[];
  chainId: number;
  sessionId: string;
  walletSigningSessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  signingRootId: string;
  signingRootVersion: string;
  jwt?: string;
  ecdsaHssRoleLocalClientState: ThresholdEcdsaHssRoleLocalClientState;
};

type BootstrapEcdsaPasskeySessionSuccess = BootstrapEcdsaSessionSuccessCommon & {
  secretSourceKind: 'passkey';
  passkeyPrfFirstB64u: string;
  passkeyCredentialIdB64u: string;
};

type BootstrapEcdsaEmailOtpSessionSuccess = BootstrapEcdsaSessionSuccessCommon & {
  secretSourceKind: 'email_otp';
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
};

export type BootstrapEcdsaSessionResult =
  | BootstrapEcdsaPasskeySessionSuccess
  | BootstrapEcdsaEmailOtpSessionSuccess
  | BootstrapEcdsaSessionFailure;

function isExactSessionBootstrapArgs(
  args: BootstrapEcdsaSessionArgs,
): args is BootstrapEcdsaExactSessionArgs {
  return Boolean(
    'keyHandle' in args &&
    args.keyHandle &&
    'key' in args &&
    args.key &&
    'lanePolicy' in args &&
    args.lanePolicy,
  );
}

function bootstrapAuthProvidesPasskeyPrfFirst(args: BootstrapEcdsaSessionArgs): boolean {
  switch (args.authKind) {
    case 'passkey_prf_bytes':
    case 'passkey_prf_b64u':
    case 'passkey_webauthn_prf_b64u':
      return true;
    case 'passkey_prompt':
    case 'passkey_webauthn':
    case 'email_otp':
      return false;
  }
  args satisfies never;
  return false;
}

export async function bootstrapEcdsaSession(
  args: BootstrapEcdsaSessionArgs,
): Promise<BootstrapEcdsaSessionResult> {
  const exactSessionBootstrap = isExactSessionBootstrapArgs(args);
  const sessionKind: ThresholdSessionKind = exactSessionBootstrap
    ? args.lanePolicy.thresholdSessionKind
    : args.sessionKind || 'jwt';
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }

  const userId = exactSessionBootstrap
    ? String(args.key.walletId).trim()
    : String(args.userId || '').trim();
  if (!userId) {
    return { ok: false, code: 'invalid_args', message: 'Missing userId' };
  }

  const requestedKeygenSessionId = String(args.requestId || '').trim();
  const keygenSessionId = requestedKeygenSessionId || generateKeygenSessionId();
  const requestedSessionId = exactSessionBootstrap
    ? String(args.lanePolicy.thresholdSessionId).trim()
    : String(args.sessionId || '').trim();
  const requestedWalletSigningSessionId = exactSessionBootstrap
    ? String(args.lanePolicy.walletSigningSessionId).trim()
    : String(args.walletSigningSessionId || '').trim();
  const keyHandle = exactSessionBootstrap ? String(args.keyHandle).trim() : '';
  const ecdsaThresholdKeyId = exactSessionBootstrap
    ? ''
    : String(args.ecdsaThresholdKeyId || '').trim();
  if (
    !exactSessionBootstrap &&
    args.bootstrapAuth &&
    ecdsaThresholdKeyId &&
    requestedSessionId &&
    requestedWalletSigningSessionId
  ) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Threshold ECDSA session bootstrap requires shared key identity and lane policy',
    };
  }
  if (
    exactSessionBootstrap &&
    (!keyHandle || !requestedSessionId || !requestedWalletSigningSessionId)
  ) {
    return {
      ok: false,
      code: 'invalid_args',
      message:
        'Threshold ECDSA session bootstrap requires keyHandle, sessionId, and walletSigningSessionId',
    };
  }
  try {
    const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
      ttlMs: exactSessionBootstrap
        ? args.lanePolicy.ttlMs
        : (args.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs),
      remainingUses: exactSessionBootstrap
        ? args.lanePolicy.remainingUses
        : (args.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses),
    });
    const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
    const runtimeEnvironmentId = String(args.runtimeScopeBootstrap?.environmentId || '').trim();
    const runtimeScopePublishableKey = String(
      args.runtimeScopeBootstrap?.publishableKey || '',
    ).trim();
    const managedBootstrapGrant =
      !exactSessionBootstrap &&
      !args.runtimePolicyScope &&
      runtimeEnvironmentId &&
      runtimeScopePublishableKey
        ? await requestManagedRegistrationBootstrapGrant({
            relayerUrl: args.relayerUrl,
            environmentId: runtimeEnvironmentId,
            publishableKey: runtimeScopePublishableKey,
            walletId: userId,
            rpId: toRpId(rpId),
          })
        : null;
    const runtimePolicyScope =
      (exactSessionBootstrap
        ? normalizeThresholdRuntimePolicyScope(args.lanePolicy.runtimePolicyScope)
        : normalizeThresholdRuntimePolicyScope(args.runtimePolicyScope)) ||
      managedBootstrapGrant?.runtimePolicyScope;
    const sessionId = requestedSessionId || generateThresholdSessionId();
    const walletSigningSessionId =
      requestedWalletSigningSessionId || generateWalletSigningSessionId();
    const sessionPolicyChainTarget = exactSessionBootstrap
      ? args.lanePolicy.chainTarget
      : args.chainTarget;
    const sessionPolicyParticipantIds = exactSessionBootstrap
      ? args.key.participantIds.map((participantId) => Number(participantId))
      : participantIds || undefined;
    const exactBootstrapSigningRootScope = exactSessionBootstrap
      ? {
          signingRootId: args.key.signingRootId,
          signingRootVersion: args.key.signingRootVersion,
        }
      : null;
    const firstBootstrapSigningRootScope =
      !exactSessionBootstrap && runtimePolicyScope
        ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
        : null;
    const roleLocalSigningRootScope =
      exactBootstrapSigningRootScope || firstBootstrapSigningRootScope;
    const exactBootstrapRelayerKeyId = exactSessionBootstrap
      ? await computeEcdsaHssRoleLocalRelayerKeyId({
          walletId: userId,
          rpId,
        })
      : '';
    const firstBootstrapRelayerKeyId = firstBootstrapSigningRootScope
      ? await computeEcdsaHssRoleLocalRelayerKeyId({
          walletId: userId,
          rpId,
        })
      : '';
    const firstBootstrapThresholdKeyId = firstBootstrapSigningRootScope
      ? await computeEcdsaHssRoleLocalThresholdKeyId({
          walletId: userId,
          rpId,
          signingRootId: firstBootstrapSigningRootScope.signingRootId,
          signingRootVersion: firstBootstrapSigningRootScope.signingRootVersion || 'default',
        })
      : '';
    const passkeyBootstrapIdentity =
      exactSessionBootstrap && exactBootstrapSigningRootScope && exactBootstrapRelayerKeyId
        ? {
            walletId: userId,
            rpId: toRpId(rpId),
            ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(args.key.ecdsaThresholdKeyId),
            signingRootId: exactBootstrapSigningRootScope.signingRootId,
            signingRootVersion: exactBootstrapSigningRootScope.signingRootVersion || 'default',
            keyScope: 'evm-family' as const,
            relayerKeyId: exactBootstrapRelayerKeyId,
            requestId: keygenSessionId,
            sessionId,
            walletSigningSessionId,
            ttlMs,
            remainingUses,
            participantIds: sessionPolicyParticipantIds || [1, 2],
          }
        : !exactSessionBootstrap &&
            firstBootstrapSigningRootScope &&
            firstBootstrapRelayerKeyId &&
            firstBootstrapThresholdKeyId &&
            (!ecdsaThresholdKeyId || ecdsaThresholdKeyId === firstBootstrapThresholdKeyId)
          ? {
              walletId: userId,
              rpId,
              ecdsaThresholdKeyId: firstBootstrapThresholdKeyId,
              signingRootId: firstBootstrapSigningRootScope.signingRootId,
              signingRootVersion: firstBootstrapSigningRootScope.signingRootVersion || 'default',
              keyScope: 'evm-family' as const,
              relayerKeyId: firstBootstrapRelayerKeyId,
              requestId: keygenSessionId,
              sessionId,
              walletSigningSessionId,
              ttlMs,
              remainingUses,
              participantIds: sessionPolicyParticipantIds || [1, 2],
            }
          : null;
    if (!exactSessionBootstrap && !passkeyBootstrapIdentity) {
      return {
        ok: false,
        code: 'role_local_required',
        message:
          'Threshold ECDSA registration bootstrap requires runtimePolicyScope or runtimeScopeBootstrap for role-local key creation',
      };
    }
    const challengeB64u = passkeyBootstrapIdentity
      ? await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u(passkeyBootstrapIdentity)
      : undefined;
    await emitBootstrapChallengeDiagnostic({
      challengeB64u,
      requestId: keygenSessionId,
      sessionId,
      walletSigningSessionId,
      challengeKind: 'ecdsa_role_local_bootstrap',
    });
    const secretSourceRequest = buildBootstrapSecretSourceRequest({
      sessionArgs: args,
      challengeB64u: challengeB64u || '',
      userId,
      rpId,
    });
    if (!secretSourceRequest.ok) {
      return secretSourceRequest;
    }
    const resolvedSecretSource = await resolveBootstrapSecretSource(secretSourceRequest.request);
    if (!resolvedSecretSource.ok) {
      return resolvedSecretSource;
    }
    // Authorization bootstraps may still be driven by a fresh WebAuthn proof
    // during passkey reauth. Preserve that proof so the server can refresh the
    // wallet signing-session budget for the newly minted threshold material.
    const webauthnAuthentication =
      resolvedSecretSource.kind === 'passkey'
        ? resolvedSecretSource.authorizationCredential || undefined
        : undefined;
    const hssAuth: ThresholdEcdsaHssRouteAuth | undefined = (() => {
      if (exactSessionBootstrap) return args.bootstrapAuth;
      if (args.bootstrapAuth) return args.bootstrapAuth;
      if (!exactSessionBootstrap && passkeyBootstrapIdentity && runtimeScopePublishableKey) {
        return { kind: 'publishable_key', token: runtimeScopePublishableKey };
      }
      if (managedBootstrapGrant?.token) {
        return { kind: 'bootstrap_grant', token: managedBootstrapGrant.token };
      }
      if (runtimeScopePublishableKey) {
        return { kind: 'publishable_key', token: runtimeScopePublishableKey };
      }
      return undefined;
    })();
    const evmFamilyKeyFingerprint = exactSessionBootstrap
      ? deriveEvmFamilyKeyFingerprint(args.key)
      : undefined;
    const sessionPolicy = buildEcdsaHssSessionPolicy({
      walletId: userId,
      rpId,
      chainTarget: sessionPolicyChainTarget,
      ...(keyHandle ? { keyHandle } : {}),
      ...(ecdsaThresholdKeyId || firstBootstrapThresholdKeyId
        ? { ecdsaThresholdKeyId: ecdsaThresholdKeyId || firstBootstrapThresholdKeyId }
        : {}),
      sessionId,
      walletSigningSessionId,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      participantIds: sessionPolicyParticipantIds,
      ttlMs,
      remainingUses,
    });
    const preparedEcdsaThresholdKeyId = exactSessionBootstrap
      ? toEcdsaHssThresholdKeyId(args.key.ecdsaThresholdKeyId)
      : sessionPolicy.ecdsaThresholdKeyId ||
        (ecdsaThresholdKeyId ? toEcdsaHssThresholdKeyId(ecdsaThresholdKeyId) : undefined);
    const hssDiagnosticIdentity = {
      operation: exactSessionBootstrap ? 'session_bootstrap' : 'key_enrollment_bootstrap',
      userId,
      rpId,
      keygenSessionId,
      chainTargetKey: thresholdEcdsaChainTargetKey(sessionPolicyChainTarget),
      ...(evmFamilyKeyFingerprint ? { evmFamilyKeyFingerprint } : {}),
      keyHandle: keyHandle || undefined,
      ecdsaThresholdKeyId: ecdsaThresholdKeyId || undefined,
      requestedSessionId: requestedSessionId || undefined,
    };
    try {
      console.info('[threshold-ecdsa][hss-prepare][diagnostic]', {
        ...hssDiagnosticIdentity,
        chainId: sessionPolicyChainTarget.chainId,
        plannedSessionPolicy: {
          sessionId: sessionPolicy.sessionId,
          walletSigningSessionId: sessionPolicy.walletSigningSessionId,
          remainingUses: sessionPolicy.remainingUses,
          ttlMs: sessionPolicy.ttlMs,
          participantCount: Array.isArray(sessionPolicy.participantIds)
            ? sessionPolicy.participantIds.length
            : 0,
          runtimePolicyScope: sessionPolicy.runtimePolicyScope,
        },
        auth: summarizeHssRouteAuth(hssAuth),
        hasWebAuthnAuthentication: Boolean(webauthnAuthentication),
        hasProvidedPasskeyPrfFirst: bootstrapAuthProvidesPasskeyPrfFirst(args),
      });
    } catch {}
    const roleLocalRelayerKeyId =
      exactBootstrapRelayerKeyId || (passkeyBootstrapIdentity ? firstBootstrapRelayerKeyId : '');
    const canUseRoleLocalBootstrap =
      Boolean(preparedEcdsaThresholdKeyId) &&
      Boolean(roleLocalSigningRootScope?.signingRootId) &&
      Boolean(roleLocalRelayerKeyId);
    if (
      canUseRoleLocalBootstrap &&
      preparedEcdsaThresholdKeyId &&
      roleLocalSigningRootScope &&
      roleLocalRelayerKeyId
    ) {
      let prepared: PrepareEcdsaClientBootstrapOutput;
      try {
        prepared = await prepareEcdsaClientBootstrapForSecretSource({
          input: {
            kind: 'prepare_ecdsa_client_bootstrap_v1',
            algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
            context: {
              walletId: toWalletId(sessionPolicy.walletId),
              rpId: toRpId(rpId),
              chainTarget: sessionPolicyChainTarget,
              ecdsaThresholdKeyId: preparedEcdsaThresholdKeyId,
              signingRootId: toEcdsaHssSigningRootId(roleLocalSigningRootScope.signingRootId),
              signingRootVersion: toEcdsaHssSigningRootVersion(
                roleLocalSigningRootScope.signingRootVersion || 'default',
              ),
              keyPurpose: 'evm-signing',
              keyVersion: 'v1',
            },
            participants: {
              clientParticipantId: 1,
              relayerParticipantId: 2,
              participantIds: [1, 2],
            },
            secretSource: resolvedSecretSource.secretSource,
          },
          workerCtx: args.workerCtx,
        });
      } catch (error) {
        return {
          ok: false,
          code: 'internal',
          message:
            error instanceof Error
              ? error.message
              : 'Threshold ECDSA role-local client bootstrap failed',
        };
      }

      const bootstrapRequestBase = {
        formatVersion: 'ecdsa-hss-role-local',
        walletId: toWalletId(sessionPolicy.walletId),
        rpId,
        ecdsaThresholdKeyId: preparedEcdsaThresholdKeyId,
        signingRootId: toEcdsaHssSigningRootId(roleLocalSigningRootScope.signingRootId),
        signingRootVersion: toEcdsaHssSigningRootVersion(
          roleLocalSigningRootScope.signingRootVersion || 'default',
        ),
        keyScope: 'evm-family',
        relayerKeyId: roleLocalRelayerKeyId,
        hssClientSharePublicKey33B64u: prepared.clientBootstrap
          .hssClientSharePublicKey33B64u as EcdsaHssClientSharePublicKey33B64u,
        clientShareRetryCounter: prepared.clientBootstrap.clientShareRetryCounter,
        contextBinding32B64u: prepared.clientBootstrap.contextBinding32B64u,
        requestId: keygenSessionId,
        sessionId,
        walletSigningSessionId,
        ttlMs,
        remainingUses,
        participantIds: sessionPolicyParticipantIds || [1, 2],
        auth: hssAuth,
        sessionKind,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      } satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest;
      let passkeyBootstrapAuthorization: ThresholdEcdsaHssRoleLocalPasskeyBootstrapAuthorization | null =
        null;
      if (!args.bootstrapAuth && passkeyBootstrapIdentity && webauthnAuthentication) {
        passkeyBootstrapAuthorization = runtimePolicyScope
          ? {
              kind: 'passkey_bootstrap',
              webauthn_authentication: webauthnAuthentication,
              runtimePolicyScope,
            }
          : runtimeEnvironmentId && runtimeScopePublishableKey
            ? {
                kind: 'passkey_bootstrap',
                webauthn_authentication: webauthnAuthentication,
                runtimeEnvironmentId,
                runtimeEnvironmentPublishableKey: runtimeScopePublishableKey,
              }
            : null;
      }
      let clientRootProof: ThresholdEcdsaHssRoleLocalClientRootProof | null = null;
      if (
        !passkeyBootstrapAuthorization &&
        args.bootstrapAuth &&
        resolvedSecretSource.kind === 'passkey'
      ) {
        clientRootProof = await buildEcdsaClientRootProof({
          bootstrapRequest: bootstrapRequestBase,
          passkeyPrfFirstB64u: resolvedSecretSource.passkeyPrfFirstB64u,
          workerCtx: args.workerCtx,
        });
      }
      let bootstrapRequest: ThresholdEcdsaHssRoleLocalBootstrapRequest;
      if (passkeyBootstrapAuthorization) {
        bootstrapRequest = { ...bootstrapRequestBase, passkeyBootstrapAuthorization };
      } else if (clientRootProof) {
        bootstrapRequest = { ...bootstrapRequestBase, clientRootProof };
      } else {
        bootstrapRequest = bootstrapRequestBase;
      }
      const bootstrap = await thresholdEcdsaHssRoleLocalBootstrap(
        args.relayerUrl,
        bootstrapRequest,
      );
      if (!bootstrap.ok) {
        return {
          ok: false,
          code: bootstrap.code || 'bootstrap_failed',
          message: bootstrap.error || bootstrap.message || 'Threshold role-local bootstrap failed',
        };
      }
      const value = bootstrap.value;
      let finalized;
      try {
        const generatedOutput = await finalizeEcdsaClientBootstrapCommandWasm({
          command: toGeneratedFinalizeEcdsaClientBootstrapCommand({
            kind: 'finalize_ecdsa_client_bootstrap_v1',
            pendingStateBlob: prepared.pendingStateBlob,
            relayerPublicIdentity: {
              relayerKeyId: value.relayerKeyId,
              relayerPublicKey33B64u: value.publicIdentity.relayerPublicKey33B64u,
              groupPublicKey33B64u: value.publicIdentity.groupPublicKey33B64u,
              ethereumAddress: value.publicIdentity.ethereumAddress as `0x${string}`,
            },
          }),
          workerCtx: args.workerCtx,
        });
        finalized = parseGeneratedFinalizeEcdsaClientBootstrapOutput(generatedOutput);
      } catch (error) {
        return {
          ok: false,
          code: 'internal',
          message:
            error instanceof Error
              ? error.message
              : 'Threshold ECDSA role-local client finalize failed',
        };
      }
      const thresholdEcdsaPublicKeyB64u =
        String(value.thresholdEcdsaPublicKeyB64u || '').trim() ||
        finalized.publicFacts.groupPublicKey33B64u;
      const ethereumAddress =
        String(value.ethereumAddress || '').trim() || finalized.publicFacts.ethereumAddress;
      const publicFacts = buildEcdsaRoleLocalPublicFacts({
        walletId: toWalletId(sessionPolicy.walletId),
        rpId,
        chainTarget: sessionPolicyChainTarget,
        keyHandle: value.keyHandle,
        ecdsaThresholdKeyId: value.ecdsaThresholdKeyId,
        signingRootId: value.signingRootId,
        signingRootVersion: value.signingRootVersion,
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds: value.participantIds,
        contextBinding32B64u: finalized.publicFacts.contextBinding32B64u,
        hssClientSharePublicKey33B64u: finalized.publicFacts.hssClientSharePublicKey33B64u,
        relayerPublicKey33B64u: finalized.publicFacts.relayerPublicKey33B64u,
        groupPublicKey33B64u: finalized.publicFacts.groupPublicKey33B64u,
        ethereumAddress,
      });
      const ecdsaHssRoleLocalClientState: ThresholdEcdsaHssRoleLocalClientState = {
        kind: 'role_local_ready',
        artifactKind: 'ecdsa-hss-role-local-client-state',
        stateBlob: finalized.stateBlob,
        publicFacts,
      };
      try {
        console.info('[threshold-ecdsa][hss-role-local-bootstrap][diagnostic]', {
          ...hssDiagnosticIdentity,
          ok: true,
          sessionId: value.sessionId,
          walletSigningSessionId: value.walletSigningSessionId,
          keyHandle: value.keyHandle,
          signingRootId: value.signingRootId,
          signingRootVersion: value.signingRootVersion,
        });
      } catch {}
      if (
        String(finalized.publicFacts.groupPublicKey33B64u || '').trim() !==
          thresholdEcdsaPublicKeyB64u ||
        String(finalized.publicFacts.ethereumAddress || '')
          .trim()
          .toLowerCase() !== ethereumAddress.toLowerCase()
      ) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'Threshold ECDSA role-local bootstrap public identity mismatch',
        };
      }
      const jwt = String(value.jwt || '').trim();
      if (resolvedSecretSource.kind === 'passkey') {
        if (jwt) {
          return {
            ok: true,
            secretSourceKind: 'passkey',
            keygenSessionId,
            rpId,
            keyHandle: value.keyHandle,
            ecdsaThresholdKeyId: value.ecdsaThresholdKeyId,
            clientVerifyingShareB64u: finalized.publicFacts.hssClientSharePublicKey33B64u,
            thresholdEcdsaPublicKeyB64u,
            ethereumAddress,
            relayerKeyId: value.relayerKeyId,
            relayerVerifyingShareB64u: value.relayerVerifyingShareB64u,
            participantIds: value.participantIds,
            chainId: sessionPolicyChainTarget.chainId,
            sessionId: value.sessionId,
            walletSigningSessionId: value.walletSigningSessionId,
            expiresAtMs: value.expiresAtMs,
            remainingUses: value.remainingUses,
            jwt,
            signingRootId: value.signingRootId,
            signingRootVersion: value.signingRootVersion,
            ecdsaHssRoleLocalClientState,
            passkeyPrfFirstB64u: resolvedSecretSource.passkeyPrfFirstB64u,
            passkeyCredentialIdB64u: resolvedSecretSource.credentialIdB64u,
          };
        }
        return {
          ok: true,
          secretSourceKind: 'passkey',
          keygenSessionId,
          rpId,
          keyHandle: value.keyHandle,
          ecdsaThresholdKeyId: value.ecdsaThresholdKeyId,
          clientVerifyingShareB64u: finalized.publicFacts.hssClientSharePublicKey33B64u,
          thresholdEcdsaPublicKeyB64u,
          ethereumAddress,
          relayerKeyId: value.relayerKeyId,
          relayerVerifyingShareB64u: value.relayerVerifyingShareB64u,
          participantIds: value.participantIds,
          chainId: sessionPolicyChainTarget.chainId,
          sessionId: value.sessionId,
          walletSigningSessionId: value.walletSigningSessionId,
          expiresAtMs: value.expiresAtMs,
          remainingUses: value.remainingUses,
          signingRootId: value.signingRootId,
          signingRootVersion: value.signingRootVersion,
          ecdsaHssRoleLocalClientState,
          passkeyPrfFirstB64u: resolvedSecretSource.passkeyPrfFirstB64u,
          passkeyCredentialIdB64u: resolvedSecretSource.credentialIdB64u,
        };
      }
      if (jwt) {
        return {
          ok: true,
          secretSourceKind: 'email_otp',
          keygenSessionId,
          rpId,
          keyHandle: value.keyHandle,
          ecdsaThresholdKeyId: value.ecdsaThresholdKeyId,
          clientVerifyingShareB64u: finalized.publicFacts.hssClientSharePublicKey33B64u,
          thresholdEcdsaPublicKeyB64u,
          ethereumAddress,
          relayerKeyId: value.relayerKeyId,
          relayerVerifyingShareB64u: value.relayerVerifyingShareB64u,
          participantIds: value.participantIds,
          chainId: sessionPolicyChainTarget.chainId,
          sessionId: value.sessionId,
          walletSigningSessionId: value.walletSigningSessionId,
          expiresAtMs: value.expiresAtMs,
          remainingUses: value.remainingUses,
          jwt,
          signingRootId: value.signingRootId,
          signingRootVersion: value.signingRootVersion,
          ecdsaHssRoleLocalClientState,
        };
      }
      return {
        ok: true,
        secretSourceKind: 'email_otp',
        keygenSessionId,
        rpId,
        keyHandle: value.keyHandle,
        ecdsaThresholdKeyId: value.ecdsaThresholdKeyId,
        clientVerifyingShareB64u: finalized.publicFacts.hssClientSharePublicKey33B64u,
        thresholdEcdsaPublicKeyB64u,
        ethereumAddress,
        relayerKeyId: value.relayerKeyId,
        relayerVerifyingShareB64u: value.relayerVerifyingShareB64u,
        participantIds: value.participantIds,
        chainId: sessionPolicyChainTarget.chainId,
        sessionId: value.sessionId,
        walletSigningSessionId: value.walletSigningSessionId,
        expiresAtMs: value.expiresAtMs,
        remainingUses: value.remainingUses,
        signingRootId: value.signingRootId,
        signingRootVersion: value.signingRootVersion,
        ecdsaHssRoleLocalClientState,
      };
    }
    return {
      ok: false,
      code: 'role_local_required',
      message:
        'Threshold ECDSA session bootstrap requires a role-local key identity and relayerKeyId',
    };
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'bootstrap failed',
    );
    return { ok: false, code: 'internal', message: msg };
  }
}
