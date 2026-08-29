import { buildRelayerJsonPostRequestInit, normalizeRelayerBaseUrl } from './relayerHttp';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import { redactedPasskeyRegistrationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import {
  parsePasskeyCustodyEnvelopeRecord,
  rejectUnknownFields,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import {
  parseWalletRecoveryEcdsaPossessionProofV1,
  type WalletRecoveryEcdsaPossessionProofV1,
} from '@shared/wallet-recovery/walletRecoveryEcdsaPossession';
import type { WalletRecoveryAttemptFailure } from './walletRecoveryPrepare';
import { parseDeviceId } from '@shared/authorization/capabilityKinds';
import type { ActiveRecoveredWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  parseWalletAuthorityId,
  parseWalletAuthMethodId,
  parseWalletId,
  parseWalletRecoveryOperationId,
} from '@shared/utils/domainIds';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import {
  parseWalletRecoveryCommittedProjectionV1,
  type WalletRecoveryCommittedProjectionExpectationV1,
} from '@shared/wallet-recovery/walletRecoveryCommittedProjection';

/**
 * Installing the replacement credential a recovery enrolled.
 *
 * Sent after activation, carrying an envelope this client sealed under the new
 * credential. The server cannot open that ciphertext because it has no seed.
 * It queries its signer registry and exact activation receipts before a
 * `promoted` reply can consume the code and retire old credentials.
 *
 * Promotion is atomic. The successful response carries the committed
 * credential projection; every source retirement is part of that same commit.
 */

const WALLET_RECOVERY_FINALIZE_PATH = '/wallets/recovery/finalize';

export type WalletRecoveryEcdsaMaterialPossessionProofInputV1 = {
  readonly keySetId: `evm_family_ecdsa:${string}`;
  readonly proof: WalletRecoveryEcdsaPossessionProofV1;
};

export type WalletRecoveryFinalizeResult =
  | {
      readonly kind: 'promoted';
      readonly storeVersion: string;
      readonly authority: ActiveRecoveredWalletAuthorityV1;
      readonly authMethod: Extract<
        WalletAuthMethodRecordV2,
        { readonly kind: 'passkey'; readonly status: 'active' }
      >;
    }
  | WalletRecoveryAttemptFailure;

export async function finalizeWalletRecovery(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly reservationId: string;
  readonly recoveryOperationId: string;
  readonly targetDeviceId: string;
  readonly targetAuthorityId: string;
  readonly targetWalletAuthMethodId: string;
  readonly challengeId: string;
  readonly replacementId: string;
  readonly webauthnRegistration: WebAuthnRegistrationCredential;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly ecdsaMaterialPossessionProofs: readonly WalletRecoveryEcdsaMaterialPossessionProofInputV1[];
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryFinalizeResult> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}${WALLET_RECOVERY_FINALIZE_PATH}`;
  const doFetch = args.fetchImpl || fetch;
  let webauthnRegistration: WebAuthnRegistrationCredential;
  try {
    webauthnRegistration = redactedPasskeyRegistrationCredential(args.webauthnRegistration);
  } catch {
    return { kind: 'refused' };
  }
  let ecdsaMaterialPossessionProofs: readonly WalletRecoveryEcdsaMaterialPossessionProofInputV1[];
  try {
    const seen = new Set<string>();
    ecdsaMaterialPossessionProofs = args.ecdsaMaterialPossessionProofs.map((entry) => {
      if (
        typeof entry.keySetId !== 'string' ||
        !entry.keySetId.startsWith('evm_family_ecdsa:') ||
        entry.keySetId.length <= 'evm_family_ecdsa:'.length
      ) {
        throw new Error('ECDSA possession proof key-set id is invalid');
      }
      if (seen.has(entry.keySetId)) {
        throw new Error('ECDSA possession proof key-set ids are duplicated');
      }
      seen.add(entry.keySetId);
      return {
        keySetId: entry.keySetId,
        proof: parseWalletRecoveryEcdsaPossessionProofV1(entry.proof),
      };
    });
  } catch {
    return { kind: 'refused' };
  }
  let replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  try {
    replacementEnvelope = parsePasskeyCustodyEnvelopeRecord(
      args.replacementEnvelope,
      'walletRecoveryFinalize.replacementEnvelope',
    );
    if (String(replacementEnvelope.walletId) !== String(args.walletId)) {
      throw new Error('replacement envelope changed the wallet identity');
    }
    if (String(replacementEnvelope.envelopeId) !== String(args.replacementId)) {
      throw new Error('replacement envelope changed the replacement identity');
    }
    if (replacementEnvelope.factor.kind !== 'passkey') {
      throw new Error('replacement envelope is not bound to a passkey');
    }
  } catch {
    return { kind: 'refused' };
  }

  let response: Response;
  try {
    response = await doFetch(
      url,
      buildRelayerJsonPostRequestInit({
        body: {
          walletId: args.walletId,
          reservationId: args.reservationId,
          recoveryOperationId: args.recoveryOperationId,
          targetDeviceId: args.targetDeviceId,
          targetAuthorityId: args.targetAuthorityId,
          targetWalletAuthMethodId: args.targetWalletAuthMethodId,
          challengeId: args.challengeId,
          replacementId: args.replacementId,
          webauthnRegistration,
          replacementEnvelope,
          ecdsaMaterialPossessionProofs,
        },
      }),
    );
  } catch {
    return { kind: 'transport_uncertain' };
  }

  const bodyUnknown: unknown = await response.json().catch(() => ({}));
  const body = isRecord(bodyUnknown) ? bodyUnknown : {};
  if (response.status === 200 && body.ok === true) {
    try {
      rejectUnknownFields(body, ['ok', 'projection'], 'walletRecoveryFinalize');
      const projection = await parseWalletRecoveryCommittedProjectionV1(
        body.projection,
        buildPasskeyProjectionExpectation(args, replacementEnvelope),
      );
      if (projection.kind !== 'passkey') throw new Error('recovery projection branch changed');
      return {
        kind: 'promoted',
        storeVersion: projection.storeVersion,
        authority: projection.authority,
        authMethod: projection.authMethod,
      };
    } catch {
      return { kind: 'transport_uncertain' };
    }
  }
  if (response.status === 409) {
    return { kind: 'retryable_conflict' };
  }
  if (response.status === 400 || response.status === 401) {
    return { kind: 'refused' };
  }
  return { kind: 'transport_uncertain' };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function buildPasskeyProjectionExpectation(
  args: {
    readonly walletId: string;
    readonly recoveryOperationId: string;
    readonly targetDeviceId: string;
    readonly targetAuthorityId: string;
    readonly targetWalletAuthMethodId: string;
  },
  replacementEnvelope: PasskeyCustodyEnvelopeRecord,
): WalletRecoveryCommittedProjectionExpectationV1 {
  if (replacementEnvelope.factor.kind !== 'passkey') {
    throw new Error('replacement envelope is not a passkey envelope');
  }
  return {
    kind: 'passkey',
    walletId: requireParsed(parseWalletId(args.walletId)),
    recoveryOperationId: requireParsed(parseWalletRecoveryOperationId(args.recoveryOperationId)),
    targetDeviceId: requireParsed(parseDeviceId(args.targetDeviceId)),
    targetAuthorityId: requireParsed(parseWalletAuthorityId(args.targetAuthorityId)),
    targetWalletAuthMethodId: requireParsed(parseWalletAuthMethodId(args.targetWalletAuthMethodId)),
    rpId: replacementEnvelope.factor.rpId,
    credentialIdB64u: replacementEnvelope.factor.credentialIdB64u,
  };
}

function requireParsed<T>(
  result: { readonly ok: true; readonly value: T } | { readonly ok: false },
): T {
  if (!result.ok) throw new Error('invalid recovery identity');
  return result.value;
}
