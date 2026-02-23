import { RegistrationSSEEvent, RegistrationPhase, RegistrationStatus } from '../../types/sdkSentEvents';
import { PasskeyManagerContext } from '..';
import { serializeRegistrationCredential, normalizeRegistrationCredential } from '../../signingEngine/signers/webauthn/credentials/helpers';
import { redactCredentialExtensionOutputs } from '../../signingEngine/signers/webauthn/credentials';
import type { WebAuthnRegistrationCredential } from '../../types/webauthn';
import type { AuthenticatorOptions } from '../../types/authenticatorOptions';
import type { CreateAccountAndRegisterResult } from '@server/core/types';
import type {
  EcdsaSessionPolicy,
  Ed25519SessionPolicy,
} from '../../signingEngine/threshold/session/sessionPolicy';
import { isObject } from '@shared/utils/validation';
import { errorMessage } from '@shared/utils/errors';

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
  const mRelayer = /new_account_id must be a subaccount of relayer(?:\s+signer\s+)?account\s*\(([^)]+)\)/i.exec(raw);

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

/**
 * HTTP Request body for the relay server's /registration/bootstrap endpoint
 */
type ThresholdEd25519RegistrationSessionPolicy =
  Omit<Ed25519SessionPolicy, 'relayerKeyId'> & { relayerKeyId?: string };
type ThresholdEcdsaRegistrationSessionPolicy =
  Omit<EcdsaSessionPolicy, 'relayerKeyId'> & { relayerKeyId?: string };

export interface CreateAccountAndRegisterUserRequest {
  new_account_id: string;
  /**
   * Optional account access key to add during creation.
   * - Threshold-first registration flows omit this field (relay creates the account with threshold key material).
   * - Legacy local-signer flows provide a locally derived key.
   */
  new_public_key?: string;
  device_number: number;
  threshold_ed25519?: {
    client_verifying_share_b64u: string;
    session_policy: ThresholdEd25519RegistrationSessionPolicy;
    session_kind: 'jwt' | 'cookie';
  };
  threshold_ecdsa?: {
    client_verifying_share_b64u: string;
    session_policy: ThresholdEcdsaRegistrationSessionPolicy;
    session_kind: 'jwt' | 'cookie';
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
  publicKey: string | undefined,
  credential: WebAuthnRegistrationCredential | PublicKeyCredential,
  rpId: string,
  authenticatorOptions?: AuthenticatorOptions,
  onEvent?: (event: RegistrationSSEEvent) => void,
  opts?: {
    thresholdEd25519?: {
      clientVerifyingShareB64u: string;
      sessionPolicy: ThresholdEd25519RegistrationSessionPolicy;
      sessionKind: 'jwt' | 'cookie';
    };
    thresholdEcdsa?: {
      clientVerifyingShareB64u: string;
      sessionPolicy: ThresholdEcdsaRegistrationSessionPolicy;
      sessionKind: 'jwt' | 'cookie';
    };
  },
): Promise<{
  success: boolean;
  transactionId?: string;
  thresholdEd25519?: {
    publicKey: string;
    relayerKeyId: string;
    relayerVerifyingShareB64u?: string;
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
  error?: string;
}> {
  const { configs } = context;

  if (!configs.relayer.url) {
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
    const serializedCredential = redactCredentialExtensionOutputs<WebAuthnRegistrationCredential>(serialized);
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
            client_verifying_share_b64u: opts.thresholdEd25519.clientVerifyingShareB64u,
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
          },
        }
        : {}),
      rp_id: String(rpId || '').trim(),
      webauthn_registration: serializedCredential,
      authenticator_options: authenticatorOptions || context.configs.authenticatorOptions,
    };
    const pk = String(publicKey || '').trim();
    if (pk) {
      requestData.new_public_key = pk;
    }

    onEvent?.({
      step: 5,
      phase: RegistrationPhase.STEP_5_CONTRACT_REGISTRATION,
      status: RegistrationStatus.PROGRESS,
      message: 'Registering user with relay...',
    });

    // Call the atomic endpoint
    const response = await fetch(`${configs.relayer.url}/registration/bootstrap`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestData)
    });

    // Handle both successful and failed responses
    const result: CreateAccountAndRegisterResult = await response.json();

    if (!response.ok) {
      // Extract specific error message from relay server response
      const msg = result.error || result.message || `HTTP ${response.status}: ${response.statusText}`;
      throw new Error(improveAtomicRegistrationError({
        raw: msg,
        nearAccountId,
        relayUrl: configs.relayer.url,
      }));
    }

    if (!result.success) {
      throw new Error(result.error || 'Atomic registration failed');
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
          publicKey: result.thresholdEd25519.publicKey,
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
    };

  } catch (error: unknown) {
    console.error('Atomic registration failed:', error);

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
    };
  }
}
