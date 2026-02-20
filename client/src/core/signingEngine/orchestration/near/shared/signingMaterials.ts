import type {
  LocalNearSkV3Material,
  ThresholdEd25519_2p_V1Material,
} from '@/core/indexedDB/passkeyNearKeysDB.types';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import { getThresholdBehaviorFromSignerMode, type SignerMode } from '@/core/types/signer-worker';
import type { SigningRuntimeDeps } from '@/core/signingEngine/interfaces/runtime';
import {
  getPrfResultsFromCredential,
  redactCredentialExtensionOutputs,
} from '@/core/signingEngine/signers/webauthn/credentials/credentialExtensions';
import {
  getLastLoggedInDeviceNumber,
  parseDeviceNumber,
} from '@/core/signingEngine/signers/webauthn/device/getDeviceNumber';
import {
  isRelayerEd25519Configured,
  resolveSignerModeForThresholdSigning,
} from '@/core/signingEngine/threshold/session/ed25519RelayerHealth';

export const DUMMY_WRAP_KEY_SALT_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

export const PRF_MISSING_ERROR =
  'Missing PRF.first output from credential (requires a PRF-enabled passkey)';

export function generateSessionId(): string {
  return `sess-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

export function toCredentialForRelayJson(
  credential?: WebAuthnAuthenticationCredential,
): string | undefined {
  return credential ? JSON.stringify(redactCredentialExtensionOutputs(credential)) : undefined;
}

export function requirePrfFirstFromCredential(
  credential?: WebAuthnAuthenticationCredential,
): string {
  const prfFirstB64u = getPrfResultsFromCredential(credential).first;
  if (!prfFirstB64u) {
    throw new Error(PRF_MISSING_ERROR);
  }
  return prfFirstB64u;
}

export function isRuntimeSigningLocalKeyMaterial(
  value: LocalNearSkV3Material | null | undefined,
): value is LocalNearSkV3Material {
  return !!value && value.usage !== 'export-only';
}

export function assertRuntimeSigningLocalKeyMaterial(args: {
  nearAccountId: string;
  localKeyMaterial: LocalNearSkV3Material | null | undefined;
}): void {
  if (!args.localKeyMaterial) return;
  if (args.localKeyMaterial.usage !== 'export-only') return;
  throw new Error(
    `[SigningEngine] local key material for account ${args.nearAccountId} is export-only and cannot be used for runtime signing`,
  );
}

export type ResolvedNearSigningMaterials = {
  nearAccountId: AccountId;
  resolvedDeviceNumber: number;
  resolvedSignerMode: SignerMode['mode'];
  localKeyMaterial: LocalNearSkV3Material | null;
  thresholdKeyMaterial: ThresholdEd25519_2p_V1Material | null;
  localWrapKeySalt: string;
  thresholdWrapKeySalt: string;
  warnings: string[];
};

export async function resolveNearSigningMaterials(args: {
  ctx: SigningRuntimeDeps;
  nearAccountId: string;
  signerMode: SignerMode;
  deviceNumber?: number;
  operationLabel: string;
  warnings?: string[];
  allowThresholdOnlyUpgrade?: boolean;
}): Promise<ResolvedNearSigningMaterials> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const relayerUrl = args.ctx.relayerUrl;
  const warnings = args.warnings ?? [];

  const parsedDeviceNumber = parseDeviceNumber(args.deviceNumber, { min: 1 });
  if (args.deviceNumber !== undefined && parsedDeviceNumber === null) {
    throw new Error(`Invalid deviceNumber for ${args.operationLabel}: ${args.deviceNumber}`);
  }
  const resolvedDeviceNumber =
    parsedDeviceNumber ??
    (await getLastLoggedInDeviceNumber(nearAccountId, args.ctx.indexedDB.clientDB));

  const thresholdKeyMaterial = await args.ctx.indexedDB.getNearThresholdKeyMaterial(
    nearAccountId,
    resolvedDeviceNumber,
  );

  let resolvedSignerMode = await resolveSignerModeForThresholdSigning({
    nearAccountId,
    signerMode: args.signerMode,
    relayerUrl,
    hasThresholdKeyMaterial: !!thresholdKeyMaterial,
    warnings,
  });

  const thresholdBehavior = getThresholdBehaviorFromSignerMode(args.signerMode);
  const localKeyMaterialCandidate =
    resolvedSignerMode === 'local-signer' || thresholdBehavior === 'fallback'
      ? await args.ctx.indexedDB.getNearLocalKeyMaterial(nearAccountId, resolvedDeviceNumber)
      : null;

  if (localKeyMaterialCandidate && !isRuntimeSigningLocalKeyMaterial(localKeyMaterialCandidate)) {
    if (resolvedSignerMode === 'local-signer' && !thresholdKeyMaterial) {
      assertRuntimeSigningLocalKeyMaterial({
        nearAccountId: String(nearAccountId),
        localKeyMaterial: localKeyMaterialCandidate,
      });
    }
    const msg = `[SigningEngine] export-only local key material is excluded from runtime signing for account: ${nearAccountId}`;
    console.warn(msg);
    warnings.push(msg);
  }

  const localKeyMaterial = isRuntimeSigningLocalKeyMaterial(localKeyMaterialCandidate)
    ? localKeyMaterialCandidate
    : null;

  if (
    args.allowThresholdOnlyUpgrade &&
    resolvedSignerMode === 'local-signer' &&
    !localKeyMaterial &&
    !!thresholdKeyMaterial
  ) {
    const configured = await isRelayerEd25519Configured(relayerUrl).catch(() => false);
    if (!configured) {
      throw new Error(
        '[SigningEngine] local-signer requested but no local key material found and the relayer is not configured for threshold signing',
      );
    }

    const msg = `[SigningEngine] local-signer requested but no local key material found for account: ${nearAccountId}; using threshold-signer`;
    console.warn(msg);
    warnings.push(msg);
    resolvedSignerMode = 'threshold-signer';
  }

  const localWrapKeySalt = String(localKeyMaterial?.wrapKeySalt || '').trim();
  const thresholdWrapKeySalt =
    String(thresholdKeyMaterial?.wrapKeySalt || '').trim() || DUMMY_WRAP_KEY_SALT_B64U;

  if (resolvedSignerMode === 'local-signer') {
    if (!localKeyMaterial) {
      throw new Error(`No local key material found for account: ${nearAccountId}`);
    }
    if (!localWrapKeySalt) {
      throw new Error(`Missing wrapKeySalt for account: ${nearAccountId}`);
    }
  }

  return {
    nearAccountId,
    resolvedDeviceNumber,
    resolvedSignerMode,
    localKeyMaterial,
    thresholdKeyMaterial,
    localWrapKeySalt,
    thresholdWrapKeySalt,
    warnings,
  };
}
