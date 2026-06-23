import { encryptEmailForOutlayer } from './emailEncryptor';
import {
  buildEncryptedEmailRecoveryActions,
  getOutlayerEncryptionPublicKey,
  sendEmailRecoveryTransaction,
} from './rpcCalls';
import { coerceLogger, type NormalizedLogger } from '../core/logger';
import type { EmailRecoveryRequest, EmailRecoveryResult, EmailRecoveryServiceDeps } from './types';

export * from './emailEncryptor';
export * from './emailParsers';
export * from './testHelpers';
export * from './types';

/**
 * EmailRecoveryService encapsulates encrypted email recovery logic for the relayer.
 *
 * It orchestrates:
 * - Fetching and caching the Outlayer X25519 public key from the global EmailDKIMVerifier,
 * - Encrypting raw RFC822 emails with encryptEmailForOutlayer, binding an AEAD context
 *   `{ account_id, network_id, payer_account_id }`,
 * - Building a canonical verified recovery request that binds the verified email payload
 *   to `{ nearAccountId, newNearPublicKey, newEvmOwnerAddress, recoverySessionId, deadlineEpochSeconds }`,
 * - Calling the per-account EmailRecoverer contract with
 *   `verify_encrypted_email_and_recover(encrypted_email_blob, aead_context, expected_hashed_email, expected_new_public_key, request_id)`.
 * - Binding those NEAR contract args to a canonical recovery payload that also
 *   includes the EVM owner, session id, and expiry used by EVM recovery.
 */
export class EmailRecoveryService {
  private readonly deps: EmailRecoveryServiceDeps;
  private readonly logger: NormalizedLogger;
  private cachedOutlayerPk: Uint8Array | null = null;

  constructor(deps: EmailRecoveryServiceDeps) {
    this.deps = deps;
    this.logger = coerceLogger(deps.logger);
  }

  private async getOutlayerEmailDkimPublicKey(): Promise<Uint8Array> {
    if (this.cachedOutlayerPk) {
      return this.cachedOutlayerPk;
    }
    const pk = await getOutlayerEncryptionPublicKey(this.deps);
    this.cachedOutlayerPk = pk;
    return pk;
  }

  /**
   * Top-level email recovery entrypoint.
   *
   * Expects `emailBlob` to contain the full raw RFC822 payload (headers + body).
   */
  async requestEmailRecovery(request: EmailRecoveryRequest): Promise<EmailRecoveryResult> {
    this.logger.debug('[email-recovery] requestEmailRecovery', {
      accountId: request.accountId,
    });

    return this.verifyEncryptedEmailAndRecover({
      accountId: request.accountId,
      emailBlob: request.emailBlob,
      recoveryPayload: request.recoveryPayload,
    });
  }

  /**
   * Helper for encrypted DKIM-based email recovery:
   * - Encrypts the raw email blob for the Outlayer worker.
   * - Calls the per-account EmailRecoverer contract's
   *   `verify_encrypted_email_and_recover` entrypoint on the user's account, deriving
   *   the NEAR args from the canonical verified recovery request.
   *
   * The per-account EmailRecoverer records a pollable attempt keyed by
   * `request_id` (parsed from the email Subject) so the frontend can observe
   * success/failure by polling `EmailRecoverer.get_recovery_attempt(request_id)`.
   */
  async verifyEncryptedEmailAndRecover(
    request: EmailRecoveryRequest,
  ): Promise<EmailRecoveryResult> {
    const accountId = (request.accountId || '').trim();
    const emailBlob = request.emailBlob;
    const recoveryPayload = request.recoveryPayload;

    if (!accountId) {
      const errMsg = 'accountId is required';
      return { success: false, error: errMsg, message: errMsg };
    }
    if (!emailBlob || typeof emailBlob !== 'string') {
      const errMsg = 'emailBlob (raw email) is required';
      return { success: false, error: errMsg, message: errMsg };
    }
    if (!recoveryPayload || recoveryPayload.nearAccountId !== accountId) {
      const errMsg = 'recoveryPayload must match accountId';
      return { success: false, error: errMsg, message: errMsg };
    }

    const { ensureSignerAndRelayerAccount } = this.deps;

    try {
      await ensureSignerAndRelayerAccount();
    } catch (e: any) {
      const msg = e?.message || 'Failed to initialize relayer account';
      return { success: false, error: msg, message: msg };
    }

    const recipientPk = await this.getOutlayerEmailDkimPublicKey();
    this.logger.debug('[email-recovery] encrypted using Outlayer public key', {
      accountId,
      outlayerPkLen: recipientPk.length,
    });

    const { actions, receiverId } = await buildEncryptedEmailRecoveryActions(this.deps, {
      accountId,
      emailBlob,
      recoveryPayload,
      recipientPk,
      encrypt: async ({ emailRaw, aeadContext, recipientPk: pk }) => {
        const { envelope } = await encryptEmailForOutlayer({
          emailRaw,
          aeadContext,
          recipientPk: pk,
        });

        this.logger.debug('[email-recovery] encrypted email envelope metadata', {
          accountId,
          aeadContextLen: aeadContext.length,
          envelope: {
            version: envelope.version,
            ephemeral_pub_len: envelope.ephemeral_pub?.length ?? 0,
            nonce_len: envelope.nonce?.length ?? 0,
            ciphertext_len: envelope.ciphertext?.length ?? 0,
          },
        });

        return { envelope };
      },
    });

    return sendEmailRecoveryTransaction(this.deps, {
      receiverId,
      actions,
      label: `Encrypted email verification requested for ${accountId}`,
    });
  }
}
