import { base64UrlDecode } from '@shared/utils/encoders';
import {
  serializeAuthenticationCredentialWithPRF,
  getPrfFirstSaltV1,
  getPrfSecondSaltV1,
} from '../../webauthnAuth/credentials/helpers';
import type { WebAuthnAllowCredential } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { executeWebAuthnWithParentFallbacksSafari } from '../../webauthnAuth/fallbacks/safari-fallbacks';
import { type WalletId, walletIdFromString } from '@shared/utils/registrationIntent';
import {
  webAuthnPromptCoordinator,
  type RegistrationWebAuthnPromptOwner,
  type ReservedRegistrationWebAuthnPrompt,
  type WebAuthnPromptCancellation,
} from './webauthnPromptCoordinator';
import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import type { WalletRecoveryRegistrationOptions } from '@/core/rpcClients/relayer/walletRecoveryPrepare';
import type { WalletAddAuthMethodRegistrationOptions } from '@/core/rpcClients/relayer/walletRegistration';

function isRegistrableSuffix(host: string, cand: string): boolean {
  if (!host || !cand) return false;
  if (host === cand) return true;
  return host.endsWith('.' + cand);
}

function resolveRpId(override: string | undefined, host: string | undefined): string {
  const h = (host || '').toLowerCase();
  const ov = (override || '').toLowerCase();
  if ((h === 'localhost' || h === '127.0.0.1') && ov.endsWith('.localhost')) return ov;
  if (ov && h && isRegistrableSuffix(h, ov)) return ov;
  return h || ov || '';
}

function decodeChallengeB64u(challengeB64u: string): Uint8Array {
  const decoded = base64UrlDecode(String(challengeB64u || ''));
  if (decoded.length !== 32) {
    throw new Error(`Invalid WebAuthn challenge: expected 32 bytes, got ${decoded.length}`);
  }
  return decoded;
}

export type RegistrationCredentialPrompt =
  | {
      kind: 'immediate';
      requestId: string;
      cancellation: WebAuthnPromptCancellation;
      reservation?: never;
      owner?: never;
    }
  | {
      kind: 'reserved';
      reservation: ReservedRegistrationWebAuthnPrompt;
      owner: RegistrationWebAuthnPromptOwner;
      cancellation: WebAuthnPromptCancellation;
      requestId?: never;
    };

type RegisterCredentialsArgsCommon = {
  walletId: string;
  intendedUserName: string;
  prompt: RegistrationCredentialPrompt;
};

export type RegisterCredentialsArgs = RegisterCredentialsArgsCommon &
  (
    | {
        kind: 'wallet_registration';
        challengeB64u: string;
        signerSlot?: number;
        recoveryRegistration?: never;
      }
    | {
        kind: 'wallet_recovery';
        recoveryRegistration: WalletRecoveryRegistrationOptions;
        challengeB64u?: never;
        signerSlot?: never;
      }
    | {
        kind: 'wallet_add_auth_method';
        registration: WalletAddAuthMethodRegistrationOptions;
        challengeB64u?: never;
        signerSlot?: never;
      }
  );

type ExpectedPasskeyRegistrationUser = {
  walletId: WalletId;
};

function requireWalletRegistrationChallenge(args: RegisterCredentialsArgs): string {
  if (args.kind !== 'wallet_registration') {
    throw new Error('Wallet registration challenge is unavailable');
  }
  return args.challengeB64u;
}

function requireExpectedPasskeyRegistrationUser(input: {
  walletId: string;
  intendedUserName: string;
}): ExpectedPasskeyRegistrationUser {
  const walletId = walletIdFromString(String(input.walletId || '').trim());
  const intendedUserName = String(input.intendedUserName || '').trim();
  if (intendedUserName !== String(walletId)) {
    throw new Error('WebAuthn registration user.name must match walletId');
  }
  return { walletId };
}

interface AuthenticateCredentialsForChallengeB64uArgs {
  subjectId: string;
  /**
   * Base64url-encoded 32-byte challenge.
   *
   * For lite threshold sessions, this should be `sessionPolicyDigest32`.
   */
  challengeB64u: string;
  /**
   * Optional allowlist of credential IDs (base64url) to restrict the prompt.
   * When omitted or empty, the browser may display an account chooser for any
   * credential available for this rpId.
   */
  allowCredentials?: WebAuthnAllowCredential[];
  /**
   * When true, include PRF.second in the serialized credential.
   * Use only for explicit recovery/export flows (higher-friction paths).
   */
  includeSecondPrfOutput?: boolean;
  cancellation?: WebAuthnPromptCancellation;
}

/**
 * TouchIdPrompt prompts for touchID,
 * creates credentials,
 * manages WebAuthn touchID prompts,
 * and generates credentials, and PRF Outputs
 */
export class TouchIdPrompt {
  private rpIdOverride?: string;
  private safariGetWebauthnRegistrationFallback: boolean;
  // create() only: internal abort controller + cleanup hooks
  private abortController?: AbortController;
  private removePageAbortHandlers?: () => void;
  private removeExternalAbortListener?: () => void;

  constructor(rpIdOverride?: string, safariGetWebauthnRegistrationFallback = false) {
    this.rpIdOverride = rpIdOverride;
    this.safariGetWebauthnRegistrationFallback = safariGetWebauthnRegistrationFallback === true;
  }

  getRpId(): string {
    try {
      return resolveRpId(this.rpIdOverride, window?.location?.hostname);
    } catch {
      return this.rpIdOverride || '';
    }
  }

  // Utility helpers for cross‑origin fallback
  private static _inIframe(): boolean {
    try {
      return window.self !== window.top;
    } catch {
      return true;
    }
  }

  /**
   * Authenticate with a caller-provided 32-byte challenge (base64url string).
   *
   * This is the preferred entry point for WebAuthn-only flows where the challenge
   * is already a canonical digest (e.g. `sessionPolicyDigest32`).
   */
  getAuthenticationCredentialsSerializedForChallengeB64u(
    args: AuthenticateCredentialsForChallengeB64uArgs,
  ): Promise<WebAuthnAuthenticationCredential> {
    const requestId = `webauthn-get-${secureRandomBase36(12, 'WebAuthn get request IDs')}`;
    return webAuthnPromptCoordinator.runImmediate({
      owner: { kind: 'wallet_request', requestId, operation: 'authentication' },
      operation: this.executeAuthenticationCredential.bind(this, args),
    });
  }

  private async executeAuthenticationCredential({
    subjectId: _subjectId,
    challengeB64u,
    allowCredentials = [],
    includeSecondPrfOutput = false,
    cancellation = { kind: 'none' },
  }: AuthenticateCredentialsForChallengeB64uArgs): Promise<WebAuthnAuthenticationCredential> {
    // New controller per get() call
    this.abortController = new AbortController();
    this.removePageAbortHandlers = attachPageAbortHandlers(this.abortController);
    this.removeExternalAbortListener = attachExternalAbortSignal(
      this.abortController,
      cancellation,
    );
    const rpId = this.getRpId();

    const challengeBytes = decodeChallengeB64u(challengeB64u);

    const publicKey: PublicKeyCredentialRequestOptions = {
      challenge: challengeBytes as BufferSource,
      rpId,
      userVerification: 'preferred' as UserVerificationRequirement,
      timeout: 60000,
      extensions: {
        prf: {
          eval: {
            first: getPrfFirstSaltV1() as BufferSource,
            second: getPrfSecondSaltV1() as BufferSource,
          },
        },
      },
    };
    if (allowCredentials.length > 0) {
      publicKey.allowCredentials = allowCredentials.map((credential) => ({
        id: base64UrlDecode(credential.id) as BufferSource,
        type: 'public-key' as PublicKeyCredentialType,
        transports: credential.transports,
      }));
    }

    try {
      const credentialMaybe = (await executeWebAuthnWithParentFallbacksSafari('get', publicKey, {
        rpId,
        inIframe: TouchIdPrompt._inIframe(),
        timeoutMs: publicKey.timeout as number | undefined,
        permitGetBridgeOnAncestorError: this.safariGetWebauthnRegistrationFallback,
        abortSignal: this.abortController.signal,
      })) as unknown;

      // Support parent-bridge fallback returning an already-serialized credential.
      const serialized = isSerializedAuthenticationCredential(credentialMaybe)
        ? credentialMaybe
        : serializeAuthenticationCredentialWithPRF({
            credential: credentialMaybe as PublicKeyCredential,
            firstPrfOutput: true,
            secondPrfOutput: includeSecondPrfOutput,
          });
      assertSerializedAuthenticationCredentialChallenge(serialized, challengeB64u);
      return serialized;
    } finally {
      this.removePageAbortHandlers?.();
      this.removePageAbortHandlers = undefined;
      this.removeExternalAbortListener?.();
      this.removeExternalAbortListener = undefined;
      this.abortController = undefined;
    }
  }

  /**
   * Internal method for generating WebAuthn registration credentials with PRF output
   * @param walletId - Durable wallet identity used for WebAuthn user handles.
   * @param challenge - Random challenge bytes for the registration ceremony
   * @param signerSlot - Local signer slot for WebAuthn user-handle disambiguation.
   * @returns Credential with PRF output
   */
  generateRegistrationCredentialsInternal(
    args: RegisterCredentialsArgs,
  ): Promise<PublicKeyCredential> {
    switch (args.prompt.kind) {
      case 'reserved':
        return webAuthnPromptCoordinator.runReserved({
          reservation: args.prompt.reservation,
          owner: args.prompt.owner,
          operation: this.executeRegistrationCredential.bind(this, args),
        });
      case 'immediate':
        return webAuthnPromptCoordinator.runImmediate({
          owner: {
            kind: 'wallet_request',
            requestId: args.prompt.requestId,
            operation: 'registration',
          },
          operation: this.executeRegistrationCredential.bind(this, args),
        });
    }
  }

  private async executeRegistrationCredential(
    args: RegisterCredentialsArgs,
  ): Promise<PublicKeyCredential> {
    // New controller per create() call
    this.abortController = new AbortController();
    this.removePageAbortHandlers = attachPageAbortHandlers(this.abortController);
    this.removeExternalAbortListener = attachExternalAbortSignal(
      this.abortController,
      args.prompt.cancellation,
    );
    // Single source of truth for rpId: use getRpId().
    const configuredRpId = this.getRpId();
    const expectedUser = requireExpectedPasskeyRegistrationUser({
      walletId: args.walletId,
      intendedUserName: args.intendedUserName,
    });
    const recoveryRegistration = args.kind === 'wallet_recovery' ? args.recoveryRegistration : null;
    const addAuthMethodRegistration =
      args.kind === 'wallet_add_auth_method' ? args.registration : null;
    const serverRegistration = recoveryRegistration ?? addAuthMethodRegistration;
    const rpId = serverRegistration?.rpId ?? configuredRpId;
    if (serverRegistration && rpId !== configuredRpId) {
      throw new Error('Wallet recovery RP ID does not match the wallet origin');
    }
    const publicKey: PublicKeyCredentialCreationOptions = serverRegistration
      ? {
          challenge: decodeChallengeB64u(serverRegistration.challengeB64u) as BufferSource,
          rp: { name: 'Seams Wallet', id: rpId },
          user: {
            id: base64UrlDecode(serverRegistration.user.idB64u) as BufferSource,
            name: serverRegistration.user.name,
            displayName: serverRegistration.user.displayName,
          },
          pubKeyCredParams: serverRegistration.pubKeyCredParams.map((parameter) => ({
            ...parameter,
          })),
          authenticatorSelection: { ...serverRegistration.authenticatorSelection },
          timeout: serverRegistration.timeoutMs,
          attestation: serverRegistration.attestation,
          extensions: {
            prf: {
              eval: {
                first: base64UrlDecode(
                  serverRegistration.extensions.prf.eval.firstB64u,
                ) as BufferSource,
                second: base64UrlDecode(
                  serverRegistration.extensions.prf.eval.secondB64u,
                ) as BufferSource,
              },
            },
          },
          excludeCredentials: serverRegistration.excludeCredentials.map((descriptor) => ({
            type: descriptor.type,
            id: base64UrlDecode(descriptor.id) as BufferSource,
          })),
        }
      : {
          challenge: decodeChallengeB64u(requireWalletRegistrationChallenge(args)) as BufferSource,
          rp: {
            name: 'WebAuthn Passkey',
            id: rpId,
          },
          user: {
            id: new TextEncoder().encode(generateSignerSlotUserId(args.walletId, args.signerSlot)),
            name: expectedUser.walletId,
            displayName: expectedUser.walletId,
          },
          pubKeyCredParams: [
            { alg: -7, type: 'public-key' },
            { alg: -257, type: 'public-key' },
          ],
          authenticatorSelection: {
            residentKey: 'required',
            userVerification: 'preferred',
          },
          timeout: 60000,
          attestation: 'none',
          extensions: {
            prf: {
              eval: {
                // Fixed, versioned salts. Account-scoping happens at the HKDF derivation layer.
                first: getPrfFirstSaltV1() as BufferSource,
                second: getPrfSecondSaltV1() as BufferSource,
              },
            },
          },
        };
    try {
      const result = await executeWebAuthnWithParentFallbacksSafari('create', publicKey, {
        rpId,
        inIframe: TouchIdPrompt._inIframe(),
        registrationOriginPolicy: 'wallet_origin_only',
        timeoutMs: publicKey.timeout as number | undefined,
        // Pass AbortSignal through when supported; Safari bridge path may ignore it.
        abortSignal: this.abortController.signal,
      });
      return result as PublicKeyCredential;
    } finally {
      this.removePageAbortHandlers?.();
      this.removePageAbortHandlers = undefined;
      this.removeExternalAbortListener?.();
      this.removeExternalAbortListener = undefined;
      this.abortController = undefined;
    }
  }
}

function attachExternalAbortSignal(
  controller: AbortController,
  cancellation: WebAuthnPromptCancellation,
): (() => void) | undefined {
  if (cancellation.kind === 'none') return undefined;
  const signal = cancellation.signal;
  const abort = controller.abort.bind(controller);
  if (signal.aborted) {
    abort();
    return undefined;
  }
  signal.addEventListener('abort', abort, { once: true });
  return signal.removeEventListener.bind(signal, 'abort', abort);
}

// Type guard for already-serialized authentication credential
function isSerializedAuthenticationCredential(x: unknown): x is WebAuthnAuthenticationCredential {
  if (!x || typeof x !== 'object') return false;
  const obj = x as { response?: unknown };
  const resp = obj.response as { authenticatorData?: unknown } | undefined;
  return typeof resp?.authenticatorData === 'string';
}

function normalizeChallengeB64uForComparison(value: unknown): string {
  return String(value || '')
    .trim()
    .replace(/=+$/g, '');
}

function readSerializedAuthenticationChallenge(
  credential: WebAuthnAuthenticationCredential,
): string {
  const clientDataJsonB64u = String(credential.response?.clientDataJSON || '').trim();
  if (!clientDataJsonB64u) {
    throw new Error('WebAuthn authentication response missing clientDataJSON');
  }
  let decoded = '';
  try {
    decoded = new TextDecoder().decode(base64UrlDecode(clientDataJsonB64u));
  } catch (error) {
    throw new Error(
      `WebAuthn authentication response has invalid clientDataJSON encoding: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch (error) {
    throw new Error(
      `WebAuthn authentication response has invalid clientDataJSON JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  const challenge =
    parsed && typeof parsed === 'object'
      ? (parsed as { challenge?: unknown }).challenge
      : undefined;
  if (typeof challenge !== 'string' || !challenge.trim()) {
    throw new Error('WebAuthn authentication response clientDataJSON missing challenge');
  }
  return challenge;
}

function assertSerializedAuthenticationCredentialChallenge(
  credential: WebAuthnAuthenticationCredential,
  expectedChallengeB64u: string,
): void {
  const actual = normalizeChallengeB64uForComparison(
    readSerializedAuthenticationChallenge(credential),
  );
  const expected = normalizeChallengeB64uForComparison(expectedChallengeB64u);
  if (actual !== expected) {
    throw new Error(
      `Unexpected authentication response challenge "${actual}", expected "${expected}"`,
    );
  }
}

/**
 * Generate signer-slot-specific user ID to prevent Chrome sync conflicts
 * Creates technical identifiers with full wallet context.
 *
 * @param walletId - The wallet ID.
 * @param signerSlot - The signer slot (optional, undefined for signer slot 1, 2 for signer slot 2, etc.)
 * @returns Technical identifier:
 *   - Signer slot 1: "serp120.web3-authn.testnet"
 *   - Signer slot 2: "serp120.web3-authn.testnet (2)"
 *   - Signer slot 3: "serp120.web3-authn.testnet (3)"
 */
function generateSignerSlotUserId(walletId: string, signerSlot?: number): string {
  // The first signer slot keeps the historical wallet-scoped WebAuthn user ID.
  if (signerSlot === undefined || signerSlot === 1) {
    return walletId;
  }
  return `${walletId} (${signerSlot})`;
}

// Abort native WebAuthn when page is being hidden or unloaded.
function attachPageAbortHandlers(controller: AbortController): () => void {
  const onVisibility = () => {
    if (document.hidden) controller.abort();
  };
  const onPageHide = () => {
    controller.abort();
  };
  const onBeforeUnload = () => {
    controller.abort();
  };
  document.addEventListener('visibilitychange', onVisibility, { passive: true });
  window.addEventListener('pagehide', onPageHide, { passive: true });
  window.addEventListener('beforeunload', onBeforeUnload, { passive: true });
  return () => {
    document.removeEventListener('visibilitychange', onVisibility);
    window.removeEventListener('pagehide', onPageHide);
    window.removeEventListener('beforeunload', onBeforeUnload);
  };
}
