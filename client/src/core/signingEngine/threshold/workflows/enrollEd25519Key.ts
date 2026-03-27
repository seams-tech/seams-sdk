import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { thresholdEd25519Keygen } from '@/core/rpcClients/near/rpcCalls';
import { ensureEd25519Prefix } from '@shared/utils/validation';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdWebAuthnPromptPort } from '../webauthn';

const DUAL_KEY_ED25519_KEY_VERSION_V1 = 'option-b-v1';

type DeriveThresholdBootstrapPackageResult =
  | {
      success: true;
      nearAccountId: string;
      keyVersion: string;
      recoveryExportCapable: true;
      clientParticipantId: number;
      relayerParticipantId: number;
      publicKey: string;
      recoveryPublicKey: string;
      clientVerifyingShareB64u: string;
      relayerSigningShareB64u: string;
      relayerVerifyingShareB64u: string;
    }
  | {
      success: false;
      nearAccountId: string;
      keyVersion: string;
      error?: string;
    };

export type EnrollThresholdEd25519KeyHandlerContext = {
  signingKeyOps: {
    deriveThresholdEd25519BootstrapPackage: (args: {
      sessionId: string;
      nearAccountId: AccountId;
      prfFirstB64u: string;
      rpId?: string;
      keyVersion: string;
      recoveryServerShareB64u?: string;
    }) => Promise<DeriveThresholdBootstrapPackageResult>;
  };
  touchIdPrompt: Pick<ThresholdWebAuthnPromptPort, 'getRpId'>;
  relayerUrl: string;
};

/**
 * Threshold keygen helper (2-of-2):
 * - derive deterministic bootstrap Ed25519 enrollment material from PRF.first
 * - run `/threshold-ed25519/keygen` to fetch relayer share + group public key
 */
export async function enrollEd25519KeyHandler(
  ctx: EnrollThresholdEd25519KeyHandlerContext,
  args: {
    sessionId: string;
    nearAccountId: AccountId | string;
    webauthnAuthentication: WebAuthnAuthenticationCredential;
    prfFirstB64u: string;
    wrapKeySalt: string;
    keygenSessionId?: string;
  },
): Promise<
  | {
      success: true;
      publicKey: string;
      recoveryPublicKey: string;
      keyVersion: string;
      recoveryExportCapable: true;
      clientParticipantId?: number;
      relayerParticipantId?: number;
      participantIds?: number[];
      clientVerifyingShareB64u: string;
      relayerKeyId: string;
      relayerVerifyingShareB64u: string;
    }
  | {
      success: false;
      error?: string;
    }
> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const sessionId = String(args.sessionId || '').trim();
  const relayerUrl = String(ctx.relayerUrl || '').trim();

  try {
    if (!sessionId) throw new Error('Missing sessionId');
    if (!relayerUrl) throw new Error('Missing relayer url (configs.network.relayer.url)');
    if (!args.webauthnAuthentication)
      throw new Error('Missing webauthnAuthentication for threshold keygen');
    if (!args.prfFirstB64u) throw new Error('Missing PRF.first output for threshold keygen');

    const derived = await ctx.signingKeyOps.deriveThresholdEd25519BootstrapPackage({
      sessionId,
      nearAccountId,
      prfFirstB64u: args.prfFirstB64u,
      rpId: ctx.touchIdPrompt.getRpId() || undefined,
      keyVersion: DUAL_KEY_ED25519_KEY_VERSION_V1,
    });
    if (!derived.success) {
      throw new Error(derived.error || 'Failed to derive Ed25519 Option B bootstrap package');
    }
    if (!derived.recoveryPublicKey || derived.recoveryExportCapable !== true) {
      throw new Error('Threshold Ed25519 bootstrap package is missing Option B recovery metadata');
    }
    if (
      !derived.clientVerifyingShareB64u ||
      !derived.publicKey ||
      !derived.relayerSigningShareB64u ||
      !derived.relayerVerifyingShareB64u
    ) {
      throw new Error('Threshold Ed25519 bootstrap package is incomplete');
    }

    const rpId = ctx.touchIdPrompt.getRpId();
    if (!rpId) throw new Error('Missing rpId for WebAuthn keygen challenge');

    const keygenSessionId = String((args.keygenSessionId || sessionId) ?? '').trim();
    if (!keygenSessionId) throw new Error('Missing keygenSessionId for threshold keygen');

    const keygen = await thresholdEd25519Keygen(relayerUrl, {
      clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
      nearAccountId,
      rpId,
      keygenSessionId,
      keyVersion: derived.keyVersion,
      recoveryExportCapable: true,
      publicKey: derived.publicKey,
      recoveryPublicKey: derived.recoveryPublicKey,
      relayerSigningShareB64u: derived.relayerSigningShareB64u,
      relayerVerifyingShareB64u: derived.relayerVerifyingShareB64u,
      webauthnAuthentication: args.webauthnAuthentication,
    });
    if (!keygen.ok) {
      throw new Error(keygen.error || keygen.message || keygen.code || 'Threshold keygen failed');
    }

    const publicKeyRaw = keygen.publicKey;
    const relayerKeyId = keygen.relayerKeyId;
    const relayerVerifyingShareB64u = keygen.relayerVerifyingShareB64u;
    if (!publicKeyRaw) throw new Error('Threshold keygen returned empty publicKey');
    if (!relayerKeyId) throw new Error('Threshold keygen returned empty relayerKeyId');
    if (!relayerVerifyingShareB64u)
      throw new Error('Threshold keygen returned empty relayerVerifyingShareB64u');
    if (String(keygen.recoveryPublicKey || '').trim() !== derived.recoveryPublicKey) {
      throw new Error('Threshold keygen returned an unexpected recoveryPublicKey');
    }
    if (keygen.recoveryExportCapable !== true) {
      throw new Error('Threshold keygen must return recoveryExportCapable=true');
    }

    const publicKey = ensureEd25519Prefix(publicKeyRaw);
    if (!publicKey) throw new Error('Threshold keygen returned empty publicKey');

    const clientParticipantId =
      typeof keygen.clientParticipantId === 'number' ? keygen.clientParticipantId : undefined;
    const relayerParticipantId =
      typeof keygen.relayerParticipantId === 'number' ? keygen.relayerParticipantId : undefined;

    return {
      success: true,
      publicKey,
      recoveryPublicKey: derived.recoveryPublicKey,
      keyVersion: keygen.keyVersion,
      recoveryExportCapable: true,
      clientParticipantId,
      relayerParticipantId,
      participantIds: Array.isArray(keygen.participantIds) ? keygen.participantIds : undefined,
      clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
      relayerKeyId,
      relayerVerifyingShareB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      error: message,
    };
  }
}
