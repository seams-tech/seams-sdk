import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { RouterApiWebAuthnService } from '../authServicePort';
import {
  d1HostIsWithinWebAuthnRpId,
  d1WebAuthnCredentialIdB64uFromCredential,
  d1WebAuthnOriginHostnameOrEmpty,
  decodeD1WebAuthnBase64UrlOrBase64,
  parseD1WebAuthnAuthenticationCredential,
  parseD1WebAuthnClientDataJsonBase64url,
} from './d1WalletAuthMethodBoundary';
import {
  isRecordValue,
  nonNegativeSafeInteger,
  optionalNonNegativeInteger,
  parseD1BoundaryWalletId,
  parseD1BoundaryWalletIdResult,
  parseJsonObject,
} from './d1RouterApiAuthBoundary';
import { CloudflareD1WebAuthnStore } from './d1WebAuthnStore';
import {
  parseWebAuthnAuthenticatorRowDeviceInfo,
  webAuthnSyncWalletBindingFromCredentialBinding,
  type D1AuthenticatorRow,
  type WebAuthnLoginChallengeRecord,
  type WebAuthnSyncChallengeRecord,
  type WebAuthnSyncWalletBinding,
} from './d1WebAuthnRecords';

type ListWebAuthnAuthenticatorsInput = Parameters<
  RouterApiWebAuthnService['listWebAuthnAuthenticatorsForUser']
>[0];
type ListWebAuthnAuthenticatorsResult = Awaited<
  ReturnType<RouterApiWebAuthnService['listWebAuthnAuthenticatorsForUser']>
>;
type CreateWebAuthnLoginOptionsInput = Parameters<
  RouterApiWebAuthnService['createWebAuthnLoginOptions']
>[0];
type CreateWebAuthnLoginOptionsResult = Awaited<
  ReturnType<RouterApiWebAuthnService['createWebAuthnLoginOptions']>
>;
type CreateWebAuthnSyncAccountOptionsInput = Parameters<
  RouterApiWebAuthnService['createWebAuthnSyncAccountOptions']
>[0];
type CreateWebAuthnSyncAccountOptionsResult = Awaited<
  ReturnType<RouterApiWebAuthnService['createWebAuthnSyncAccountOptions']>
>;
type VerifyWebAuthnAuthenticationLiteInput = Parameters<
  RouterApiWebAuthnService['verifyWebAuthnAuthenticationLite']
>[0];
type VerifyWebAuthnAuthenticationLiteResult = Awaited<
  ReturnType<RouterApiWebAuthnService['verifyWebAuthnAuthenticationLite']>
>;
type VerifyWebAuthnLoginInput = Parameters<RouterApiWebAuthnService['verifyWebAuthnLogin']>[0];
type VerifyWebAuthnLoginResult = Awaited<
  ReturnType<RouterApiWebAuthnService['verifyWebAuthnLogin']>
>;
type VerifyWebAuthnSyncAccountInput = Parameters<
  RouterApiWebAuthnService['verifyWebAuthnSyncAccount']
>[0];
type VerifyWebAuthnSyncAccountResult = Awaited<
  ReturnType<RouterApiWebAuthnService['verifyWebAuthnSyncAccount']>
>;

type SimpleWebAuthnVerifier = (args: unknown) => Promise<unknown>;

type SimpleWebAuthnServerModule = {
  readonly verifyAuthenticationResponse?: SimpleWebAuthnVerifier;
};

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

export class CloudflareD1WebAuthnAuthService {
  private readonly webAuthnStore: CloudflareD1WebAuthnStore;

  constructor(input: { readonly webAuthnStore: CloudflareD1WebAuthnStore }) {
    this.webAuthnStore = input.webAuthnStore;
  }

  async listWebAuthnAuthenticatorsForUser(
    input: ListWebAuthnAuthenticatorsInput,
  ): Promise<ListWebAuthnAuthenticatorsResult> {
    try {
      const userId = parseD1BoundaryWalletIdResult(input.userId);
      if (!userId.ok) {
        return {
          ok: false,
          code: 'invalid_args',
          message: userId.code === 'missing' ? 'Missing userId' : 'Invalid userId',
        };
      }
      const rpId = toOptionalTrimmedString(input.rpId);
      const authRows = await this.webAuthnStore.readAuthenticatorRows(userId.value);
      const bindings = await this.webAuthnStore.readBindingRows({ userId: userId.value, rpId });
      const authByCredentialId = new Map<string, D1AuthenticatorRow>();
      for (const row of authRows) {
        const credentialId = toOptionalTrimmedString(row.credential_id_b64u);
        if (credentialId) authByCredentialId.set(credentialId, row);
      }
      const authenticators: NonNullable<ListWebAuthnAuthenticatorsResult['authenticators']> = [];
      for (const binding of bindings) {
        const authenticator = authByCredentialId.get(binding.credentialIdB64u);
        authenticators.push({
          credentialIdB64u: binding.credentialIdB64u,
          signerSlot: binding.signerSlot,
          publicKey: binding.publicKey,
          createdAtMs:
            optionalNonNegativeInteger(authenticator?.created_at_ms) ?? binding.createdAtMs,
          updatedAtMs:
            optionalNonNegativeInteger(authenticator?.updated_at_ms) ?? binding.updatedAtMs,
          device: parseWebAuthnAuthenticatorRowDeviceInfo(authenticator?.device_info_json),
        });
      }
      authenticators.sort(compareAuthenticatorSlots);
      return { ok: true, authenticators };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list authenticators',
      };
    }
  }

  async createWebAuthnLoginOptions(
    input: CreateWebAuthnLoginOptionsInput,
  ): Promise<CreateWebAuthnLoginOptionsResult> {
    try {
      const userId = parseD1BoundaryWalletIdResult(input.userId ?? input.user_id);
      const rpId = toOptionalTrimmedString(input.rpId ?? input.rp_id);
      if (!userId.ok) {
        return {
          ok: false,
          code: 'invalid_body',
          message: userId.code === 'missing' ? 'Missing userId' : 'Invalid userId',
        };
      }
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rpId' };

      const createdAtMs = Date.now();
      const expiresAtMs = createdAtMs + webAuthnLoginChallengeTtlMs(input.ttlMs ?? input.ttl_ms);
      const challengeId = secureRandomBase64Url(16, 'WebAuthn login challenge id');
      const challengeB64u = secureRandomBase64Url(32, 'WebAuthn login challenge');
      const record: WebAuthnLoginChallengeRecord = {
        version: 'webauthn_login_challenge_v1',
        challengeId,
        userId: userId.value,
        rpId,
        challengeB64u,
        createdAtMs,
        expiresAtMs,
      };

      await this.webAuthnStore.writeChallenge({
        challengeId,
        challengeKind: 'login',
        record,
        createdAtMs,
        expiresAtMs,
      });

      return { ok: true, challengeId, challengeB64u, expiresAtMs };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create login options',
      };
    }
  }

  async createWebAuthnSyncAccountOptions(
    input: CreateWebAuthnSyncAccountOptionsInput,
  ): Promise<CreateWebAuthnSyncAccountOptionsResult> {
    try {
      const rpId = toOptionalTrimmedString(input.rp_id);
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };

      const expectedUserIdRaw = toOptionalTrimmedString(input.account_id);
      const expectedUserId = expectedUserIdRaw ? parseD1BoundaryWalletId(expectedUserIdRaw) : null;
      if (expectedUserIdRaw && !expectedUserId) {
        return { ok: false, code: 'invalid_body', message: 'Invalid wallet account_id' };
      }

      const createdAtMs = Date.now();
      const expiresAtMs = createdAtMs + webAuthnLoginChallengeTtlMs(input.ttlMs ?? input.ttl_ms);
      const challengeId = secureRandomBase64Url(16, 'WebAuthn sync challenge id');
      const challengeB64u = secureRandomBase64Url(32, 'WebAuthn sync challenge');
      let credentialIds: string[] | undefined;
      let walletBinding: WebAuthnSyncWalletBinding | undefined;

      if (expectedUserId) {
        credentialIds = [];
        const seenCredentialIds = new Set<string>();
        const bindings = await this.webAuthnStore.readBindingRows({ userId: expectedUserId, rpId });
        for (const binding of bindings) {
          const credentialId = toOptionalTrimmedString(binding.credentialIdB64u);
          if (credentialId && !seenCredentialIds.has(credentialId)) {
            seenCredentialIds.add(credentialId);
            credentialIds.push(credentialId);
          }
          if (!walletBinding) {
            walletBinding = webAuthnSyncWalletBindingFromCredentialBinding(binding) || undefined;
          }
        }
      }

      const record: WebAuthnSyncChallengeRecord = {
        version: 'webauthn_sync_challenge_v1',
        challengeId,
        rpId,
        ...(expectedUserId ? { expectedUserId } : {}),
        challengeB64u,
        createdAtMs,
        expiresAtMs,
      };
      await this.webAuthnStore.writeChallenge({
        challengeId,
        challengeKind: 'sync',
        record,
        createdAtMs,
        expiresAtMs,
      });

      return {
        ok: true,
        challengeId,
        challengeB64u,
        ...(credentialIds ? { credentialIds } : {}),
        ...(walletBinding ? { walletBinding } : {}),
        expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create sync account options',
      };
    }
  }

  async verifyWebAuthnAuthenticationLite(
    input: VerifyWebAuthnAuthenticationLiteInput,
  ): Promise<VerifyWebAuthnAuthenticationLiteResult> {
    try {
      const userId = parseD1BoundaryWalletIdResult(input.userId);
      const rpId = parseWebAuthnRpId(input.rpId);
      const expectedChallenge = toOptionalTrimmedString(input.expectedChallenge);
      const expectedOrigin = toOptionalTrimmedString(input.expected_origin);
      const credential = parseD1WebAuthnAuthenticationCredential(input.webauthn_authentication);
      if (!userId.ok) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: userId.code === 'missing' ? 'Missing userId' : 'Invalid userId',
        };
      }
      if (!rpId.ok) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: rpId.error.message,
        };
      }
      if (!expectedChallenge) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing expectedChallenge',
        };
      }
      if (!expectedOrigin) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn authentication verification',
        };
      }
      if (!credential) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing webauthn_authentication',
        };
      }

      try {
        const clientData = parseD1WebAuthnClientDataJsonBase64url(
          toOptionalTrimmedString(parseJsonObject(credential.response)?.clientDataJSON),
        );
        if (
          !d1HostIsWithinWebAuthnRpId(
            d1WebAuthnOriginHostnameOrEmpty(clientData.origin),
            String(rpId.value),
          )
        ) {
          return {
            success: false,
            verified: false,
            code: 'invalid_origin',
            message: 'WebAuthn origin is not within rpId',
          };
        }
      } catch (error: unknown) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: errorMessage(error) || 'Invalid webauthn_authentication.response.clientDataJSON',
        };
      }

      const credentialId = d1WebAuthnCredentialIdB64uFromCredential(credential);
      if (!credentialId.ok) {
        return {
          success: false,
          verified: false,
          code: credentialId.code,
          message: credentialId.message,
        };
      }
      const authenticator = await this.webAuthnStore.readAuthenticator({
        userId: userId.value,
        credentialIdB64u: credentialId.credentialIdB64u,
      });
      if (!authenticator) {
        return {
          success: false,
          verified: false,
          code: 'unknown_credential',
          message: 'Credential is not registered for user',
        };
      }

      const mod = await loadSimpleWebAuthnServer();
      const verifyAuthenticationResponse = mod.verifyAuthenticationResponse;
      if (typeof verifyAuthenticationResponse !== 'function') {
        return {
          success: false,
          verified: false,
          code: 'unsupported',
          message: 'WebAuthn verifier is unavailable in this runtime',
        };
      }

      let credentialPublicKeyBytes: Uint8Array;
      try {
        credentialPublicKeyBytes = decodeD1WebAuthnBase64UrlOrBase64(
          authenticator.credentialPublicKeyB64u,
          'authenticator.credentialPublicKeyB64u',
        );
      } catch (error: unknown) {
        return {
          success: false,
          verified: false,
          code: 'internal',
          message: `Stored credential public key is invalid: ${
            errorMessage(error) || 'decode failed'
          }`,
        };
      }

      let verification: unknown;
      try {
        verification = await verifyAuthenticationResponse({
          response: credential,
          expectedChallenge,
          expectedOrigin,
          expectedRPID: rpId.value,
          credential: {
            id: credentialId.credentialIdB64u,
            publicKey: credentialPublicKeyBytes,
            counter: authenticator.counter,
          },
          requireUserVerification: false,
        });
      } catch (error: unknown) {
        return {
          success: false,
          verified: false,
          code: 'invalid_assertion',
          message: errorMessage(error) || 'Authentication assertion verification threw',
        };
      }

      const verificationRecord = isRecordValue(verification) ? verification : {};
      if (verificationRecord.verified !== true) {
        return {
          success: false,
          verified: false,
          code: 'not_verified',
          message: 'Authentication verification failed',
        };
      }
      const authenticationInfo = parseJsonObject(verificationRecord.authenticationInfo);
      const newCounter = nonNegativeSafeInteger(authenticationInfo?.newCounter);
      if (newCounter !== null) {
        await this.webAuthnStore.updateAuthenticatorCounter({
          userId: userId.value,
          credentialIdB64u: credentialId.credentialIdB64u,
          newCounter,
          updatedAtMs: Date.now(),
        });
      }
      return { success: true, verified: true };
    } catch (error: unknown) {
      return {
        success: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'Verification failed',
      };
    }
  }

  async verifyWebAuthnLogin(input: VerifyWebAuthnLoginInput): Promise<VerifyWebAuthnLoginResult> {
    try {
      const challengeId = toOptionalTrimmedString(input.challengeId ?? input.challenge_id);
      if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      const challenge = await this.webAuthnStore.consumeLoginChallenge(challengeId);
      if (!challenge) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Login challenge expired or invalid',
        };
      }
      const expectedOrigin = toOptionalTrimmedString(input.expected_origin);
      if (!expectedOrigin) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn authentication verification',
        };
      }
      const rpId = parseWebAuthnRpId(challenge.rpId);
      if (!rpId.ok) {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: `Stored login challenge rpId is invalid: ${rpId.error.message}`,
        };
      }
      const credential = parseD1WebAuthnAuthenticationCredential(input.webauthn_authentication);
      if (!credential) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing webauthn_authentication',
        };
      }
      const verification = await this.verifyWebAuthnAuthenticationLite({
        userId: challenge.userId,
        rpId: rpId.value,
        expectedChallenge: challenge.challengeB64u,
        webauthn_authentication: credential,
        expected_origin: expectedOrigin,
      });
      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          verified: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }
      return { ok: true, verified: true, userId: challenge.userId, rpId: challenge.rpId };
    } catch (error: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'Login verification failed',
      };
    }
  }

  async verifyWebAuthnSyncAccount(
    input: VerifyWebAuthnSyncAccountInput,
  ): Promise<VerifyWebAuthnSyncAccountResult> {
    try {
      const challengeId = toOptionalTrimmedString(input.challengeId ?? input.challenge_id);
      if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      const challenge = await this.webAuthnStore.consumeSyncChallenge(challengeId);
      if (!challenge) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Sync challenge expired or invalid',
        };
      }
      const credential = parseD1WebAuthnAuthenticationCredential(input.webauthn_authentication);
      if (!credential) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing webauthn_authentication',
        };
      }
      const credentialId = d1WebAuthnCredentialIdB64uFromCredential(credential);
      if (!credentialId.ok) {
        return {
          ok: false,
          verified: false,
          code: credentialId.code,
          message: credentialId.message,
        };
      }
      const binding = await this.webAuthnStore.readBindingByCredential({
        rpId: challenge.rpId,
        credentialIdB64u: credentialId.credentialIdB64u,
      });
      if (!binding) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_credential',
          message: 'Credential is not registered on this relay',
        };
      }
      if (challenge.expectedUserId && binding.userId !== challenge.expectedUserId) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_credential',
          message: `Credential is not registered for account ${challenge.expectedUserId}`,
        };
      }
      const expectedOrigin = toOptionalTrimmedString(input.expected_origin);
      if (!expectedOrigin) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn authentication verification',
        };
      }
      const rpId = parseWebAuthnRpId(binding.rpId);
      if (!rpId.ok) {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: `Stored sync credential binding rpId is invalid: ${rpId.error.message}`,
        };
      }
      const verification = await this.verifyWebAuthnAuthenticationLite({
        userId: binding.userId,
        rpId: rpId.value,
        expectedChallenge: challenge.challengeB64u,
        webauthn_authentication: credential,
        expected_origin: expectedOrigin,
      });
      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          verified: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }
      const authenticator = await this.webAuthnStore.readAuthenticator({
        userId: binding.userId,
        credentialIdB64u: credentialId.credentialIdB64u,
      });
      if (!authenticator) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_credential',
          message: 'Credential is not registered for user',
        };
      }
      const walletBinding = webAuthnSyncWalletBindingFromCredentialBinding(binding);
      if (!walletBinding) {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: 'Credential binding is missing wallet identity fields',
        };
      }
      const thresholdEd25519 =
        binding.relayerKeyId && binding.publicKey
          ? {
              relayerKeyId: binding.relayerKeyId,
              authorityScope: {
                kind: 'passkey_rp' as const,
                rpId: rpId.value,
              },
              publicKey: binding.publicKey,
              ...(binding.keyVersion ? { keyVersion: binding.keyVersion } : {}),
              ...(typeof binding.recoveryExportCapable === 'boolean'
                ? { recoveryExportCapable: binding.recoveryExportCapable }
                : {}),
              ...(typeof binding.clientParticipantId === 'number'
                ? { clientParticipantId: binding.clientParticipantId }
                : {}),
              ...(typeof binding.relayerParticipantId === 'number'
                ? { relayerParticipantId: binding.relayerParticipantId }
                : {}),
              ...(binding.participantIds ? { participantIds: binding.participantIds } : {}),
            }
          : undefined;
      return {
        ok: true,
        verified: true,
        accountId: walletBinding.walletId,
        walletId: walletBinding.walletId,
        nearAccountId: walletBinding.nearAccountId,
        nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
        walletBinding,
        rpId: walletBinding.rpId,
        signerSlot: walletBinding.signerSlot,
        ...(binding.publicKey ? { publicKey: binding.publicKey } : {}),
        ...(binding.relayerKeyId ? { relayerKeyId: binding.relayerKeyId } : {}),
        credentialIdB64u: credentialId.credentialIdB64u,
        credentialPublicKeyB64u: authenticator.credentialPublicKeyB64u,
        ...(thresholdEd25519 ? { thresholdEd25519 } : {}),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'Sync verification failed',
      };
    }
  }
}

async function loadSimpleWebAuthnServer(): Promise<SimpleWebAuthnServerModule> {
  try {
    return (await import('@simplewebauthn/server')) as SimpleWebAuthnServerModule;
  } catch (error: unknown) {
    throw new Error(
      `Server WebAuthn route selected but '@simplewebauthn/server' dependency is not available: ${
        errorMessage(error) || 'import failed'
      }`,
    );
  }
}

function webAuthnLoginChallengeTtlMs(input: unknown): number {
  const defaultTtlMs = 5 * 60_000;
  const minTtlMs = 10_000;
  const maxTtlMs = 10 * 60_000;
  if (input == null || input === '') return defaultTtlMs;
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value <= 0) return defaultTtlMs;
  return Math.min(Math.max(Math.floor(value), minTtlMs), maxTtlMs);
}

function compareAuthenticatorSlots(
  left: NonNullable<ListWebAuthnAuthenticatorsResult['authenticators']>[number],
  right: NonNullable<ListWebAuthnAuthenticatorsResult['authenticators']>[number],
): number {
  return (Number(left.signerSlot || 0) || 0) - (Number(right.signerSlot || 0) || 0);
}
