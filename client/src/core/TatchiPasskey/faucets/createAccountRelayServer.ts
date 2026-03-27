import {
  RegistrationSSEEvent,
  RegistrationPhase,
  RegistrationStatus,
} from '../../types/sdkSentEvents';
import { PasskeyManagerContext } from '..';
import {
  serializeRegistrationCredential,
  normalizeRegistrationCredential,
} from '../../signingEngine/signers/webauthn/credentials/helpers';
import { redactCredentialExtensionOutputs } from '../../signingEngine/signers/webauthn/credentials';
import type { WebAuthnRegistrationCredential } from '../../types/webauthn';
import {
  cloneAuthenticatorOptions,
  type AuthenticatorOptions,
} from '../../types/authenticatorOptions';
import type {
  CreateAccountAndRegisterResult,
  CreateAccountAndRegisterSmartAccountDeployment,
  CreateAccountAndRegisterSmartAccountTarget,
  ThresholdEd25519BootstrapRecoveryShareResponse,
} from '@server/core/types';
import type {
  EcdsaSessionPolicy,
  Ed25519SessionPolicy,
} from '../../signingEngine/threshold/session/sessionPolicy';
import { isObject } from '@shared/utils/validation';
import { errorMessage } from '@shared/utils/errors';
import { computeRegistrationBootstrapRequestHashSha256 } from '@shared/utils/registrationBootstrapHash';
import type { RegistrationErrorCode } from '../../types/tatchi';

function isSerializedRegistrationCredential(
  credential: WebAuthnRegistrationCredential | PublicKeyCredential,
): credential is WebAuthnRegistrationCredential {
  if (!isObject(credential)) return false;
  const resp = (credential as { response?: unknown }).response;
  if (!isObject(resp)) return false;
  return typeof (resp as { attestationObject?: unknown }).attestationObject === 'string';
}

function improveAtomicRegistrationError(args: {
  raw: string;
  nearAccountId: string;
  relayUrl: string;
}): string {
  const raw = String(args.raw || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const relayUrl = String(args.relayUrl || '').trim();

  // Server validation: account creation can only create subaccounts under a specific namespace.
  const mRelayer =
    /new_account_id must be a subaccount of relayer(?:\s+signer\s+)?account\s*\(([^)]+)\)/i.exec(
      raw,
    );

  const expectedRelayer = mRelayer?.[1] ? String(mRelayer[1]).trim() : '';

  if (expectedRelayer) {
    const hint =
      `Registration accountId must be a subaccount of the relay signer account.\n` +
      `Expected: <username>.${expectedRelayer}\n` +
      (nearAccountId ? `Got: ${nearAccountId}\n` : '') +
      `Fix: set client config \`relayerAccount: '${expectedRelayer}'\` (must match relay RELAYER_ACCOUNT_ID)` +
      (relayUrl ? ` for relayer \`${relayUrl}\`` : '') +
      `.`;
    return hint;
  }

  return raw || 'Atomic registration failed';
}

const REGISTRATION_FAILURE_CODES: readonly RegistrationErrorCode[] = [
  'secret_key_missing',
  'secret_key_invalid',
  'secret_key_revoked',
  'secret_key_forbidden_scope',
  'secret_key_ip_blocked',
  'secret_key_environment_mismatch',
  'publishable_key_missing',
  'publishable_key_invalid',
  'publishable_key_revoked',
  'publishable_key_origin_blocked',
  'publishable_key_environment_mismatch',
  'publishable_key_rate_limited',
  'publishable_key_quota_exhausted',
  'invalid_environment',
  'environment_archived',
  'invalid_body',
  'payment_required',
  'payment_invalid',
  'bootstrap_token_missing',
  'bootstrap_token_invalid',
  'bootstrap_token_expired',
  'bootstrap_token_already_used',
  'bootstrap_token_request_mismatch',
  'bootstrap_token_origin_mismatch',
];

function isRegistrationErrorCode(raw: unknown): raw is RegistrationErrorCode {
  const value = String(raw || '').trim();
  return REGISTRATION_FAILURE_CODES.includes(value as RegistrationErrorCode);
}

export class RelayRegistrationError extends Error {
  readonly code: RegistrationErrorCode;
  readonly status: number;

  constructor(input: { code: RegistrationErrorCode; status: number; message: string }) {
    super(input.message);
    this.name = 'RelayRegistrationError';
    this.code = input.code;
    this.status = input.status;
  }
}

function isRelayRegistrationError(error: unknown): error is RelayRegistrationError {
  return error instanceof RelayRegistrationError;
}

function joinUrlPath(baseUrl: string, path: string): string {
  const base = String(baseUrl || '').trim().replace(/\/+$/, '');
  const suffix = String(path || '').trim();
  if (!base) return '';
  if (!suffix) return base;
  return `${base}${suffix.startsWith('/') ? suffix : `/${suffix}`}`;
}

function replaceUrlPathSuffix(url: string, fromPath: string, toPath: string): string {
  const raw = String(url || '').trim();
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    if (parsed.pathname === fromPath || parsed.pathname === `${fromPath}/`) {
      parsed.pathname = toPath;
      return parsed.toString();
    }
  } catch {}
  if (raw.endsWith(fromPath)) {
    return `${raw.slice(0, raw.length - fromPath.length)}${toPath}`;
  }
  if (raw.endsWith(`${fromPath}/`)) {
    return `${raw.slice(0, raw.length - fromPath.length - 1)}${toPath}`;
  }
  return '';
}

type ResolvedRegistrationTransport =
  | {
      mode: 'backend_proxy';
      bootstrapUrl: string;
      recoveryShareUrl: string;
    }
  | {
      mode: 'managed';
      relayerUrl: string;
      environmentId: string;
      publishableKey: string;
      paymentMode?: string;
    };

function resolveRegistrationTransport(context: PasskeyManagerContext): ResolvedRegistrationTransport {
  const configs = context.configs as PasskeyManagerContext['configs'] & {
    registration?: unknown;
  };
  const registration = configs.registration;
  if (registration && typeof registration === 'object' && !Array.isArray(registration)) {
    const mode = String((registration as { mode?: unknown }).mode || 'backend_proxy').trim();
    if (mode === 'managed') {
      const relayerUrl = String(context.configs.network.relayer.url || '').trim();
      const environmentId = String(
        (registration as { environmentId?: unknown }).environmentId || '',
      ).trim();
      const publishableKey = String(
        (registration as { publishableKey?: unknown }).publishableKey || '',
      ).trim();
      const paymentMode = String((registration as { paymentMode?: unknown }).paymentMode || '').trim();
      if (!relayerUrl) throw new Error('Managed registration requires relayer.url');
      if (!environmentId) throw new Error('Managed registration requires registration.environmentId');
      if (!publishableKey) {
        throw new Error('Managed registration requires registration.publishableKey');
      }
      return {
        mode: 'managed',
        relayerUrl,
        environmentId,
        publishableKey,
        ...(paymentMode ? { paymentMode } : {}),
      };
    }
    const bootstrapUrl = String(
      (registration as { bootstrapUrl?: unknown; registrationBootstrapUrl?: unknown })
        .bootstrapUrl ??
        (registration as { registrationBootstrapUrl?: unknown }).registrationBootstrapUrl ??
        '',
    ).trim();
    if (bootstrapUrl) {
      const recoveryShareUrl =
        replaceUrlPathSuffix(
          bootstrapUrl,
          '/registration/bootstrap',
          '/registration/recovery-share',
        ) || joinUrlPath(bootstrapUrl, '/registration/recovery-share');
      return { mode: 'backend_proxy', bootstrapUrl, recoveryShareUrl };
    }
  }
  const relayerUrl = String(context.configs.network.relayer.url || '').trim();
  return {
    mode: 'backend_proxy',
    bootstrapUrl: joinUrlPath(relayerUrl, '/registration/bootstrap'),
    recoveryShareUrl: joinUrlPath(relayerUrl, '/registration/recovery-share'),
  };
}

function buildManagedClientContext(): { sdk: string; userAgentHint?: string } {
  const userAgentHint =
    typeof navigator !== 'undefined' ? String(navigator.userAgent || '').trim() : '';
  return {
    sdk: '@tatchi-xyz/sdk',
    ...(userAgentHint ? { userAgentHint } : {}),
  };
}

async function readJsonObject(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (!text) return {};
  try {
    const parsed: unknown = JSON.parse(text);
    return isObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

export async function prepareThresholdEd25519BootstrapRecoveryShareWithRelayServer(
  context: PasskeyManagerContext,
  nearAccountId: string,
  rpId: string,
  keyVersion: string,
): Promise<{ recoveryServerShareB64u: string; keyVersion: string }> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const registrationTransport = resolveRegistrationTransport(context);
  let response: Response;
  let result: ThresholdEd25519BootstrapRecoveryShareResponse;

  if (registrationTransport.mode === 'managed') {
    response = await fetch(
      joinUrlPath(registrationTransport.relayerUrl, '/v1/registration/recovery-share'),
      {
        method: 'POST',
        headers: {
          ...headers,
          Authorization: `Bearer ${registrationTransport.publishableKey}`,
        },
        body: JSON.stringify({
          nearAccountId,
          rpId,
          keyVersion,
          environmentId: registrationTransport.environmentId,
        }),
      },
    );
  } else {
    if (!registrationTransport.recoveryShareUrl) {
      throw new Error('Registration recovery share URL is required for passkey registration');
    }
    response = await fetch(registrationTransport.recoveryShareUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        nearAccountId,
        rpId,
        keyVersion,
      }),
    });
  }

  result = (await readJsonObject(response)) as unknown as ThresholdEd25519BootstrapRecoveryShareResponse;

  const responseCode = String(result.code || '').trim();
  const responseMessage =
    String(result.message || '').trim() || `HTTP ${response.status}: ${response.statusText}`;
  if (!response.ok || result.ok === false) {
    if (isRegistrationErrorCode(responseCode)) {
      throw new RelayRegistrationError({
        code: responseCode,
        status: response.status,
        message: responseMessage,
      });
    }
    throw new Error(responseMessage || 'Threshold Ed25519 recovery-share preparation failed');
  }

  const recoveryServerShareB64u = String(result.recoveryServerShareB64u || '').trim();
  if (!recoveryServerShareB64u) {
    throw new Error(
      'Threshold Ed25519 recovery-share preparation did not return recoveryServerShareB64u',
    );
  }

  return {
    recoveryServerShareB64u,
    keyVersion: String(result.keyVersion || '').trim() || keyVersion,
  };
}

/**
 * HTTP Request body for the relay server's /registration/bootstrap endpoint
 */
type ThresholdEd25519RegistrationSessionPolicy = Omit<Ed25519SessionPolicy, 'relayerKeyId'> & {
  relayerKeyId?: string;
};
type ThresholdEcdsaRegistrationSessionPolicy = Omit<EcdsaSessionPolicy, 'relayerKeyId'> & {
  relayerKeyId?: string;
};

export interface CreateAccountAndRegisterUserRequest {
  new_account_id: string;
  device_number: number;
  threshold_ed25519?: {
    key_version: string;
    recovery_export_capable: boolean;
    public_key: string;
    recovery_public_key: string;
    client_verifying_share_b64u: string;
    relayer_signing_share_b64u: string;
    relayer_verifying_share_b64u: string;
    session_policy: ThresholdEd25519RegistrationSessionPolicy;
    session_kind: 'jwt' | 'cookie';
  };
  threshold_ecdsa?: {
    client_verifying_share_b64u: string;
    session_policy: ThresholdEcdsaRegistrationSessionPolicy;
    session_kind: 'jwt' | 'cookie';
    smart_account_targets?: CreateAccountAndRegisterSmartAccountTarget[];
  };
  rp_id: string;
  webauthn_registration: WebAuthnRegistrationCredential;
  authenticator_options?: AuthenticatorOptions;
}

/**
 * Create account and register user using relay-server atomic endpoint
 * Makes a single call to the relay-server's /registration/bootstrap endpoint
 */
export async function createAccountAndRegisterWithRelayServer(
  context: PasskeyManagerContext,
  nearAccountId: string,
  credential: WebAuthnRegistrationCredential | PublicKeyCredential,
  rpId: string,
  authenticatorOptions?: AuthenticatorOptions,
  onEvent?: (event: RegistrationSSEEvent) => void,
  opts?: {
    thresholdEd25519?: {
      keyVersion: string;
      recoveryExportCapable: true;
      publicKey: string;
      recoveryPublicKey: string;
      clientVerifyingShareB64u: string;
      relayerSigningShareB64u: string;
      relayerVerifyingShareB64u: string;
      sessionPolicy: ThresholdEd25519RegistrationSessionPolicy;
      sessionKind: 'jwt' | 'cookie';
    };
    thresholdEcdsa?: {
      clientVerifyingShareB64u: string;
      sessionPolicy: ThresholdEcdsaRegistrationSessionPolicy;
      sessionKind: 'jwt' | 'cookie';
      smartAccountTargets?: CreateAccountAndRegisterSmartAccountTarget[];
    };
  },
): Promise<{
  success: boolean;
  transactionId?: string;
  thresholdEd25519?: {
    keyVersion: string;
    recoveryExportCapable: true;
    publicKey: string;
    recoveryPublicKey: string;
    relayerKeyId: string;
    relayerVerifyingShareB64u: string;
    clientParticipantId?: number;
    relayerParticipantId?: number;
    participantIds?: number[];
    session?: {
      sessionKind: 'jwt' | 'cookie';
      sessionId: string;
      expiresAtMs: number;
      expiresAt?: string;
      participantIds?: number[];
      remainingUses?: number;
      jwt?: string;
    };
  };
  thresholdEcdsa?: {
    relayerKeyId: string;
    groupPublicKeyB64u: string;
    ethereumAddress: string;
    relayerVerifyingShareB64u: string;
    participantIds?: number[];
    session?: {
      sessionKind: 'jwt' | 'cookie';
      sessionId: string;
      expiresAtMs: number;
      expiresAt?: string;
      participantIds?: number[];
      remainingUses?: number;
      jwt?: string;
    };
  };
  smartAccountDeployments?: CreateAccountAndRegisterSmartAccountDeployment[];
  error?: string;
  errorCode?: RegistrationErrorCode;
}> {
  const { configs } = context;

  if (!configs.network.relayer.url) {
    throw new Error('Relay server URL is required for atomic registration');
  }

  try {
    onEvent?.({
      step: 4,
      phase: RegistrationPhase.STEP_4_ACCESS_KEY_ADDITION,
      status: RegistrationStatus.PROGRESS,
      message: 'Creating account and adding access key...',
    });

    // Serialize the WebAuthn credential properly for the contract.
    // Accept both live PublicKeyCredential and already-serialized credentials from secureConfirm.
    const isSerialized = isSerializedRegistrationCredential(credential);

    // Ensure proper serialization + normalization regardless of source
    const serialized: WebAuthnRegistrationCredential = isSerialized
      ? normalizeRegistrationCredential(credential)
      : serializeRegistrationCredential(credential);

    // Strip PRF outputs before sending to relay/contract
    const serializedCredential =
      redactCredentialExtensionOutputs<WebAuthnRegistrationCredential>(serialized);
    // Normalize transports to an array (avoid null)
    if (!Array.isArray(serializedCredential?.response?.transports)) {
      serializedCredential.response.transports = [];
    }

    const requestData: CreateAccountAndRegisterUserRequest = {
      new_account_id: nearAccountId,
      device_number: 1, // First device gets device number 1 (1-indexed)
      ...(opts?.thresholdEd25519?.clientVerifyingShareB64u
        ? {
            threshold_ed25519: {
              key_version: opts.thresholdEd25519.keyVersion,
              recovery_export_capable: opts.thresholdEd25519.recoveryExportCapable,
              public_key: opts.thresholdEd25519.publicKey,
              recovery_public_key: opts.thresholdEd25519.recoveryPublicKey,
              client_verifying_share_b64u: opts.thresholdEd25519.clientVerifyingShareB64u,
              relayer_signing_share_b64u: opts.thresholdEd25519.relayerSigningShareB64u,
              relayer_verifying_share_b64u: opts.thresholdEd25519.relayerVerifyingShareB64u,
              session_policy: opts.thresholdEd25519.sessionPolicy,
              session_kind: opts.thresholdEd25519.sessionKind,
            },
          }
        : {}),
      ...(opts?.thresholdEcdsa?.clientVerifyingShareB64u
        ? {
            threshold_ecdsa: {
              client_verifying_share_b64u: opts.thresholdEcdsa.clientVerifyingShareB64u,
              session_policy: opts.thresholdEcdsa.sessionPolicy,
              session_kind: opts.thresholdEcdsa.sessionKind,
              ...(Array.isArray(opts.thresholdEcdsa.smartAccountTargets) &&
              opts.thresholdEcdsa.smartAccountTargets.length > 0
                ? { smart_account_targets: opts.thresholdEcdsa.smartAccountTargets }
                : {}),
            },
          }
        : {}),
      rp_id: String(rpId || '').trim(),
      webauthn_registration: serializedCredential,
      authenticator_options: cloneAuthenticatorOptions(
        authenticatorOptions ?? context.configs.webauthn.authenticatorOptions,
      ),
    };

    onEvent?.({
      step: 5,
      phase: RegistrationPhase.STEP_5_CONTRACT_REGISTRATION,
      status: RegistrationStatus.PROGRESS,
      message: 'Registering user with relay...',
    });

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const registrationTransport = resolveRegistrationTransport(context);
    let response: Response;
    let result: CreateAccountAndRegisterResult;

    if (registrationTransport.mode === 'managed') {
      const requestHashSha256 = await computeRegistrationBootstrapRequestHashSha256(requestData);
      const bootstrapGrantUrl = joinUrlPath(
        registrationTransport.relayerUrl,
        '/v1/registration/bootstrap-grants',
      );
      const brokerResponse = await fetch(bootstrapGrantUrl, {
        method: 'POST',
        headers: {
          ...headers,
          Authorization: `Bearer ${registrationTransport.publishableKey}`,
        },
        body: JSON.stringify({
          environmentId: registrationTransport.environmentId,
          newAccountId: nearAccountId,
          rpId: requestData.rp_id,
          requestHashSha256,
          clientContext: buildManagedClientContext(),
        }),
      });
      const brokerResult = await readJsonObject(brokerResponse);
      const brokerCode = String(brokerResult.code || '').trim();
      const brokerMessage =
        String(brokerResult.message || '').trim() ||
        `HTTP ${brokerResponse.status}: ${brokerResponse.statusText}`;
      if (!brokerResponse.ok || brokerResult.ok === false) {
        if (isRegistrationErrorCode(brokerCode)) {
          throw new RelayRegistrationError({
            code: brokerCode,
            status: brokerResponse.status,
            message: brokerMessage,
          });
        }
        throw new Error(brokerMessage || 'Managed bootstrap grant failed');
      }
      const bootstrapToken = String(
        (isObject(brokerResult.grant) ? brokerResult.grant.token : '') || '',
      ).trim();
      if (!bootstrapToken) {
        throw new Error('Managed bootstrap grant response did not include a bootstrap token');
      }
      const registrationBootstrapUrl = joinUrlPath(configs.network.relayer.url, '/registration/bootstrap');
      if (!registrationBootstrapUrl) {
        throw new Error('Relay server URL is required for managed passkey registration');
      }
      response = await fetch(registrationBootstrapUrl, {
        method: 'POST',
        headers: {
          ...headers,
          Authorization: `Bearer ${bootstrapToken}`,
        },
        body: JSON.stringify(requestData),
      });
      result = (await readJsonObject(response)) as unknown as CreateAccountAndRegisterResult;
    } else {
      if (!registrationTransport.bootstrapUrl) {
        throw new Error('Registration bootstrap URL is required for passkey registration');
      }
      response = await fetch(registrationTransport.bootstrapUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(requestData),
      });
      result = (await readJsonObject(response)) as unknown as CreateAccountAndRegisterResult;
    }

    const responseCode = String(result.code || '').trim();
    const responseMessage =
      result.error || result.message || `HTTP ${response.status}: ${response.statusText}`;

    if (!response.ok) {
      if (isRegistrationErrorCode(responseCode)) {
        throw new RelayRegistrationError({
          code: responseCode,
          status: response.status,
          message: responseMessage,
        });
      }
      throw new Error(
        improveAtomicRegistrationError({
          raw: responseMessage,
          nearAccountId,
          relayUrl: configs.network.relayer.url,
        }),
      );
    }

    if (!result.success) {
      if (isRegistrationErrorCode(responseCode)) {
        throw new RelayRegistrationError({
          code: responseCode,
          status: response.status,
          message: responseMessage,
        });
      }
      throw new Error(responseMessage || 'Atomic registration failed');
    }

    if (result.thresholdEd25519) {
      const thresholdKeyVersion = String(result.thresholdEd25519.keyVersion || '').trim();
      const thresholdRecoveryPublicKey = String(result.thresholdEd25519.recoveryPublicKey || '').trim();
      const thresholdRelayerVerifyingShare = String(
        result.thresholdEd25519.relayerVerifyingShareB64u || '',
      ).trim();
      if (!thresholdKeyVersion || result.thresholdEd25519.recoveryExportCapable !== true || !thresholdRecoveryPublicKey || !thresholdRelayerVerifyingShare) {
        throw new Error('Atomic registration returned an incomplete threshold-ed25519 Option B package');
      }
    }

    onEvent?.({
      step: 5,
      phase: RegistrationPhase.STEP_5_CONTRACT_REGISTRATION,
      status: RegistrationStatus.SUCCESS,
      message: 'User registered successfully',
    });

    return {
      success: true,
      transactionId: result.transactionHash,
      thresholdEd25519: result.thresholdEd25519
        ? {
            keyVersion: result.thresholdEd25519.keyVersion,
            recoveryExportCapable: true,
            publicKey: result.thresholdEd25519.publicKey,
            recoveryPublicKey: result.thresholdEd25519.recoveryPublicKey,
            relayerKeyId: result.thresholdEd25519.relayerKeyId,
            relayerVerifyingShareB64u: result.thresholdEd25519.relayerVerifyingShareB64u,
            clientParticipantId: result.thresholdEd25519.clientParticipantId,
            relayerParticipantId: result.thresholdEd25519.relayerParticipantId,
            participantIds: result.thresholdEd25519.participantIds,
            session: result.thresholdEd25519.session
              ? {
                  sessionKind: result.thresholdEd25519.session.sessionKind,
                  sessionId: result.thresholdEd25519.session.sessionId,
                  expiresAtMs: result.thresholdEd25519.session.expiresAtMs,
                  expiresAt: result.thresholdEd25519.session.expiresAt,
                  participantIds: result.thresholdEd25519.session.participantIds,
                  remainingUses: result.thresholdEd25519.session.remainingUses,
                  jwt: result.thresholdEd25519.session.jwt,
                }
              : undefined,
          }
        : undefined,
      thresholdEcdsa: result.thresholdEcdsa
        ? {
            relayerKeyId: result.thresholdEcdsa.relayerKeyId,
            groupPublicKeyB64u: result.thresholdEcdsa.groupPublicKeyB64u,
            ethereumAddress: result.thresholdEcdsa.ethereumAddress,
            relayerVerifyingShareB64u: result.thresholdEcdsa.relayerVerifyingShareB64u,
            participantIds: result.thresholdEcdsa.participantIds,
            session: result.thresholdEcdsa.session
              ? {
                  sessionKind: result.thresholdEcdsa.session.sessionKind,
                  sessionId: result.thresholdEcdsa.session.sessionId,
                  expiresAtMs: result.thresholdEcdsa.session.expiresAtMs,
                  expiresAt: result.thresholdEcdsa.session.expiresAt,
                  participantIds: result.thresholdEcdsa.session.participantIds,
                  remainingUses: result.thresholdEcdsa.session.remainingUses,
                  jwt: result.thresholdEcdsa.session.jwt,
                }
              : undefined,
          }
        : undefined,
      smartAccountDeployments: Array.isArray(result.smartAccountDeployments)
        ? result.smartAccountDeployments
        : undefined,
    };
  } catch (error: unknown) {
    console.error('Atomic registration failed:', error);
    const code = isRelayRegistrationError(error) ? error.code : undefined;

    onEvent?.({
      step: 0,
      phase: RegistrationPhase.REGISTRATION_ERROR,
      status: RegistrationStatus.ERROR,
      message: 'Registration failed',
      error: errorMessage(error),
    });

    return {
      success: false,
      error: errorMessage(error),
      ...(code ? { errorCode: code } : {}),
    };
  }
}
