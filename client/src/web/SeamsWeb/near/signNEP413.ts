import type { SeamsWebContext } from '../index';
import type { SignNEP413HooksOptions } from '@/core/types/sdkSentEvents';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { AccountId } from '@/core/types/accountIds';
import { base64Encode } from '@shared/utils/encoders';
import { nearAccountRefFromAccountId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { emitNearSigningEvent } from './signingEventHelpers';

/**
 * NEP-413 message signing parameters
 */
export interface SignNEP413MessageParams {
  /** The message to sign */
  message: string;
  /** The recipient identifier */
  recipient: string;
  /** Optional state parameter */
  state?: string;
}

/**
 * NEP-413 message signing result
 */
export interface SignNEP413MessageResult {
  /** Success status */
  success: boolean;
  /** NEAR account ID that signed the message */
  accountId?: string;
  /** Base58-encoded public key */
  publicKey?: string;
  /** Base64-encoded signature */
  signature?: string;
  /** Base64-encoded 32-byte nonce used for signing */
  nonce?: string;
  /** Optional state parameter */
  state?: string;
  /** Error message if signing failed */
  error?: string;
}

/**
 * Sign a NEP-413 message using the user's passkey-derived private key
 *
 * This function implements the NEP-413 standard for off-chain message signing:
 * - Creates a payload with message, recipient, nonce, and state
 * - Serializes using Borsh
 * - Adds NEP-413 prefix (2^31 + 413)
 * - Hashes with SHA-256
 * - Signs with Ed25519
 * - Returns base64-encoded signature
 *
 * @param context - SeamsWeb context
 * @param nearAccountId - NEAR account ID to sign with
 * @param params - NEP-413 signing parameters
 * @param options - Action options for event handling
 * @returns Promise resolving to signing result
 */
export async function signNEP413Message(args: {
  context: SeamsWebContext;
  nearAccountId: AccountId;
  params: SignNEP413MessageParams;
  options: SignNEP413HooksOptions;
}): Promise<SignNEP413MessageResult> {
  const { context, nearAccountId, params, options } = args;
  const confirmerText = options?.confirmerText;
  const confirmationConfigOverride = options?.confirmationConfig;
  const { signingEngine } = context;
  const registrationAccounts = context.signingRuntime.services.registrationAccounts;
  const signerSlot = options?.signerSlot;
  const hasValidSignerSlot =
    typeof signerSlot === 'number' && Number.isSafeInteger(signerSlot) && signerSlot >= 1;

  try {
    // Emit preparation event
    emitNearSigningEvent(options?.onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_01_STARTED,
      status: 'started',
      message: 'Preparing NEP-413 message signing',
      interaction: { kind: 'none', overlay: 'none' },
    });

    // Get user data for NEP-413 signing.
    if (signerSlot !== undefined && !hasValidSignerSlot) {
      throw new Error(`Invalid signerSlot for NEP-413 signing: ${signerSlot}`);
    }
    const userData = hasValidSignerSlot
      ? await registrationAccounts.getUserBySignerSlot(nearAccountId, signerSlot)
      : await registrationAccounts.getLastUser();
    if (!userData || !userData.operationalPublicKey) {
      throw new Error(`Operational NEAR key data not found for ${nearAccountId}`);
    }

    // Generate a random 32-byte nonce (NEP-413 expects base64-encoded nonce bytes).
    const nonceBytes = new Uint8Array(32);
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      throw new Error('Secure random not available to generate NEP-413 nonce');
    }
    crypto.getRandomValues(nonceBytes);
    const nonce = base64Encode(nonceBytes);

    // Emit signing progress event
    emitNearSigningEvent(options?.onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_10_COMMIT_STARTED,
      status: 'running',
      message: 'Signing NEP-413 message',
      interaction: { kind: 'none', overlay: 'none' },
    });

    // Send to SigningEngine for signing.
    // Note: NEP-413 uses UserConfirm-driven confirmTxFlow; this call triggers
    // its own confirmation + WebAuthn authentication as needed.
    const result = await context.signingRuntime.services.nearSigning.signNear({
      chain: 'near',
      kind: 'nep413',
      args: {
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        message: params.message,
        recipient: params.recipient,
        nonce,
        state: params.state || null,
        signerSlot: hasValidSignerSlot ? signerSlot : undefined,
        title: confirmerText?.title,
        body: confirmerText?.body,
        confirmationConfigOverride,
      },
    });

    if (result.success) {
      // Emit completion event
      emitNearSigningEvent(options?.onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_15_COMPLETED,
        status: 'succeeded',
        message: 'NEP-413 message signed successfully',
        interaction: { kind: 'none', overlay: 'none' },
      });

      return {
        success: true,
        accountId: result.accountId,
        publicKey: result.publicKey,
        signature: result.signature,
        nonce,
        state: result.state,
      };
    } else {
      throw new Error(`NEP-413 signing failed: ${result.error || 'Unknown error'}`);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    // Emit error event
    emitNearSigningEvent(options?.onEvent, nearAccountId, {
      phase: SigningEventPhase.FAILED,
      status: 'failed',
      message: `NEP-413 signing failed: ${errorMessage}`,
      interaction: { kind: 'none', overlay: 'hide' },
      error: { message: errorMessage },
    });

    options?.onError?.(error instanceof Error ? error : new Error(errorMessage));

    return {
      success: false,
      error: errorMessage,
    };
  }
}
