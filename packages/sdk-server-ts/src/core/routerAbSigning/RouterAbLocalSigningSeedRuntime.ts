import {
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
  parseSdkEcdsaDerivationThresholdKeyId,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { parseWalletId, parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import { parseEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { ThresholdEd25519AuthorityScope } from '../types';
import type { ThresholdEd25519KeyStore } from '../ThresholdService/stores/KeyStore';
import type {
  Ed25519WalletSessionStore,
  EcdsaWalletSessionStore,
} from '../ThresholdService/stores/WalletSessionStore';
import type { RouterAbNormalSigningRuntime } from './RouterAbNormalSigningRuntime';

const THRESHOLD_ECDSA_DERIVATION_VERSION_V1 = 1;

export type LocalRouterAbEd25519NormalSigningSeedInput = {
  readonly relayerKeyId: string;
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly rpId: string;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly publicKey: string;
  readonly relayerSigningShareB64u: string;
  readonly relayerVerifyingShareB64u: string;
  readonly keyVersion: string;
  readonly thresholdExpiresAtMs: number;
  readonly participantIds: readonly number[];
  readonly remainingUses: number;
  readonly recoveryExportCapable: true;
};

export type LocalRouterAbEd25519NormalSigningSeedResult =
  | {
      readonly ok: true;
      readonly relayerKeyId: string;
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly remainingUses: number;
    }
  | { readonly ok: false; readonly code: string; readonly message: string };

export type LocalRouterAbEcdsaDerivationNormalSigningSeedInput = {
  readonly walletId: string;
  readonly evmFamilySigningKeySlotId: string;
  readonly ecdsaThresholdKeyId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly walletKeyVersion: string;
  readonly derivationVersion: number;
  readonly relayerKeyId: string;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly thresholdExpiresAtMs: number;
  readonly participantIds: readonly number[];
  readonly remainingUses: number;
};

export type LocalRouterAbEcdsaDerivationNormalSigningSeedResult =
  | {
      readonly ok: true;
      readonly relayerKeyId: string;
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly remainingUses: number;
    }
  | { readonly ok: false; readonly code: string; readonly message: string };

function passkeyRpAuthorityScope(rpId: WebAuthnRpId): ThresholdEd25519AuthorityScope {
  return { kind: 'passkey_rp', rpId };
}

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || '',
  );
}

export class RouterAbLocalSigningSeedRuntime {
  private readonly ed25519KeyStore: ThresholdEd25519KeyStore;
  private readonly ed25519WalletSessionStore: Ed25519WalletSessionStore;
  private readonly ecdsaWalletSessionStore: EcdsaWalletSessionStore;
  private readonly normalSigningRuntime: RouterAbNormalSigningRuntime;

  constructor(input: {
    readonly ed25519KeyStore: ThresholdEd25519KeyStore;
    readonly ed25519WalletSessionStore: Ed25519WalletSessionStore;
    readonly ecdsaWalletSessionStore: EcdsaWalletSessionStore;
    readonly normalSigningRuntime: RouterAbNormalSigningRuntime;
  }) {
    this.ed25519KeyStore = input.ed25519KeyStore;
    this.ed25519WalletSessionStore = input.ed25519WalletSessionStore;
    this.ecdsaWalletSessionStore = input.ecdsaWalletSessionStore;
    this.normalSigningRuntime = input.normalSigningRuntime;
  }

  async seedLocalRouterAbEd25519NormalSigningSession(
    input: LocalRouterAbEd25519NormalSigningSeedInput,
  ): Promise<LocalRouterAbEd25519NormalSigningSeedResult> {
    const relayerKeyId = toOptionalTrimmedString(input.relayerKeyId);
    const walletId = toOptionalTrimmedString(input.walletId);
    const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
    const nearEd25519SigningKeyId = toOptionalTrimmedString(input.nearEd25519SigningKeyId);
    const thresholdSessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const publicKey = toOptionalTrimmedString(input.publicKey);
    const relayerSigningShareB64u = toOptionalTrimmedString(input.relayerSigningShareB64u);
    const relayerVerifyingShareB64u = toOptionalTrimmedString(input.relayerVerifyingShareB64u);
    const keyVersion = toOptionalTrimmedString(input.keyVersion);
    const participantIds = normalizeThresholdEd25519ParticipantIds(input.participantIds);
    const remainingUses = Math.floor(Number(input.remainingUses));
    const thresholdExpiresAtMs = Number(input.thresholdExpiresAtMs);
    const rpId = parseWebAuthnRpId(input.rpId);
    if (
      !relayerKeyId ||
      !walletId ||
      !nearAccountId ||
      !nearEd25519SigningKeyId ||
      !thresholdSessionId ||
      !signingGrantId ||
      !publicKey ||
      !relayerSigningShareB64u ||
      !relayerVerifyingShareB64u ||
      !keyVersion ||
      !participantIds ||
      participantIds.length !== 2 ||
      participantIds[0] === participantIds[1] ||
      !Number.isSafeInteger(remainingUses) ||
      remainingUses <= 0 ||
      !Number.isFinite(thresholdExpiresAtMs) ||
      thresholdExpiresAtMs <= Date.now() ||
      !rpId.ok ||
      input.recoveryExportCapable !== true
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'local Router A/B Ed25519 seed is invalid',
      };
    }

    try {
      const ttlMs = Math.max(1, Math.floor(thresholdExpiresAtMs - Date.now()));
      const authorityScope = passkeyRpAuthorityScope(rpId.value);
      await this.ed25519KeyStore.put(relayerKeyId, {
        kind: 'ready',
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        authorityScope,
        publicKey,
        routerMaterial: {
          signingShareB64u: relayerSigningShareB64u,
          verifyingShareB64u: relayerVerifyingShareB64u,
        },
        keyVersion,
        recoveryExportCapable: true,
      });
      await this.ed25519WalletSessionStore.putSession(
        thresholdSessionId,
        {
          expiresAtMs: thresholdExpiresAtMs,
          relayerKeyId,
          userId: walletId,
          walletId,
          nearAccountId,
          nearEd25519SigningKeyId,
          authorityScope,
          participantIds,
        },
        { ttlMs, remainingUses },
      );
      const walletBudget = await this.normalSigningRuntime.ensureSigningGrantBudget({
        signingGrantId,
        curve: 'ed25519',
        thresholdSessionId,
        userId: walletId,
        authorityScope,
        participantIds,
        ttlMs,
        remainingUses,
        operation: 'provision_curve_binding',
      });
      if (!walletBudget.ok) return walletBudget;
      return { ok: true, relayerKeyId, thresholdSessionId, signingGrantId, remainingUses };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'local Router A/B Ed25519 seed failed',
      };
    }
  }

  async seedLocalRouterAbEcdsaDerivationNormalSigningSession(
    input: LocalRouterAbEcdsaDerivationNormalSigningSeedInput,
  ): Promise<LocalRouterAbEcdsaDerivationNormalSigningSeedResult> {
    const walletId = parseWalletId(input.walletId);
    const evmFamilySigningKeySlotId = parseEvmFamilySigningKeySlotId(
      input.evmFamilySigningKeySlotId,
    );
    let ecdsaThresholdKeyId = '';
    let signingRootId = '';
    let signingRootVersion = '';
    try {
      ecdsaThresholdKeyId = parseSdkEcdsaDerivationThresholdKeyId(input.ecdsaThresholdKeyId);
      signingRootId = parseSdkEcdsaDerivationSigningRootId(input.signingRootId);
      signingRootVersion = parseSdkEcdsaDerivationSigningRootVersion(input.signingRootVersion);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'local Router A/B ECDSA derivation seed is invalid',
      };
    }
    const walletKeyVersion = toOptionalTrimmedString(input.walletKeyVersion);
    const relayerKeyId = toOptionalTrimmedString(input.relayerKeyId);
    const thresholdSessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const derivationVersion = Math.floor(Number(input.derivationVersion));
    const participantIds = normalizeThresholdEd25519ParticipantIds(input.participantIds);
    const remainingUses = Math.floor(Number(input.remainingUses));
    const thresholdExpiresAtMs = Number(input.thresholdExpiresAtMs);
    if (
      !walletId.ok ||
      !evmFamilySigningKeySlotId.ok ||
      !ecdsaThresholdKeyId ||
      !signingRootId ||
      !signingRootVersion ||
      !walletKeyVersion ||
      !relayerKeyId ||
      !thresholdSessionId ||
      !signingGrantId ||
      derivationVersion !== THRESHOLD_ECDSA_DERIVATION_VERSION_V1 ||
      !participantIds ||
      participantIds.length !== 2 ||
      participantIds[0] === participantIds[1] ||
      !Number.isSafeInteger(remainingUses) ||
      remainingUses <= 0 ||
      !Number.isFinite(thresholdExpiresAtMs) ||
      thresholdExpiresAtMs <= Date.now()
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'local Router A/B ECDSA derivation seed is invalid',
      };
    }

    try {
      const ttlMs = Math.max(1, Math.floor(thresholdExpiresAtMs - Date.now()));
      const walletBudget = await this.normalSigningRuntime.ensureSigningGrantBudget({
        signingGrantId,
        curve: 'ecdsa',
        thresholdSessionId,
        userId: walletId.value,
        evmFamilySigningKeySlotId: evmFamilySigningKeySlotId.value,
        participantIds,
        ttlMs,
        remainingUses,
        operation: 'provision_curve_binding',
      });
      if (!walletBudget.ok) return walletBudget;
      await this.ecdsaWalletSessionStore.putSession(
        thresholdSessionId,
        {
          expiresAtMs: thresholdExpiresAtMs,
          relayerKeyId,
          walletId: walletId.value,
          evmFamilySigningKeySlotId: evmFamilySigningKeySlotId.value,
          signingRootId,
          signingRootVersion,
          walletKeyVersion,
          derivationVersion,
          participantIds,
        },
        { ttlMs, remainingUses },
      );
      return { ok: true, relayerKeyId, thresholdSessionId, signingGrantId, remainingUses };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'local Router A/B ECDSA derivation seed failed',
      };
    }
  }
}
