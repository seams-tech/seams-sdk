import type { ThresholdEd25519_V1Material } from '@/core/indexedDB/passkeyNearKeysDB.types';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { SigningRuntimeDeps } from '@/core/signingEngine/interfaces/runtime';
import {
  getPrfResultsFromCredential,
  redactCredentialExtensionOutputs,
} from '@/core/signingEngine/signers/webauthn/credentials/credentialExtensions';
import {
  getLastLoggedInDeviceNumber,
  parseDeviceNumber,
} from '@/core/signingEngine/signers/webauthn/device/getDeviceNumber';

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

export type ResolvedNearSigningMaterials = {
  nearAccountId: AccountId;
  resolvedDeviceNumber: number;
  thresholdKeyMaterial: ThresholdEd25519_V1Material | null;
  warnings: string[];
};

export async function resolveNearSigningMaterials(args: {
  ctx: SigningRuntimeDeps;
  nearAccountId: string;
  deviceNumber?: number;
  operationLabel: string;
  warnings?: string[];
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
  if (!thresholdKeyMaterial) {
    throw new Error('[SigningEngine] threshold key material is unavailable');
  }

  return {
    nearAccountId,
    resolvedDeviceNumber,
    thresholdKeyMaterial,
    warnings,
  };
}
