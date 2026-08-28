/**
 * Strict terminal response parsing for wallet registration.
 *
 * The registration RPC orchestration remains in `walletRegistration.ts`; this
 * module owns the response boundary validators and the terminal finalize
 * projection used by registration activation and provisioning.
 */

import {
  parseNearEd25519SigningKeyId,
  parseWalletAuthMethodRecordV2,
  walletIdFromString,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { parseWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import { parseImplicitNearAccountId, parseNamedNearAccountId } from '@shared/utils/near';
import { base64UrlDecode } from '@shared/utils/base64';
import {
  parseWebAuthnRpId,
  parseThresholdEd25519SessionId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { parseRouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  isPasskeyWalletAuthAuthority,
  parseWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  normalizeThresholdRuntimePolicyScope,
  type Ed25519AuthorityScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import { requireRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { parseWalletCustodyRegistrationOutcome } from '@shared/passkey-custody';
import type {
  RegistrationNearAccountProvisioning,
  ResolvedRegistrationNearAccount,
} from '@shared/utils/registrationIntent';
import type {
  FinalizeWalletRegistrationArgs,
  WalletEd25519YaoSignerPublicResult,
  WalletRegistrationEcdsaWalletKey,
  WalletRegistrationEd25519YaoPublicResult,
  WalletRegistrationFinalizeAuthMethod,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationRouteDiagnostics,
  WalletRegistrationRouteTimingName,
} from './walletRegistration';

export function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function requireResponseString(args: {
  responseName: string;
  field: string;
  value: unknown;
}): string {
  const value = String(args.value || '').trim();
  if (!value) {
    throw new Error(`${args.responseName} response missing ${args.field}`);
  }
  return value;
}

export function requireResponseRecord(args: {
  responseName: string;
  field: string;
  value: unknown;
}): Record<string, unknown> {
  if (!isRecord(args.value)) {
    throw new Error(`${args.responseName} response missing ${args.field}`);
  }
  return args.value;
}

export function assertExactResponseKeys(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
  responseName: string,
): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      throw new Error(`${responseName} response contains unexpected ${key}`);
    }
  }
}

export function requireResponseSafeInteger(args: {
  responseName: string;
  field: string;
  value: unknown;
  minimum: number;
}): number {
  const value = Number(args.value);
  if (!Number.isSafeInteger(value) || value < args.minimum) {
    throw new Error(`${args.responseName} response has invalid ${args.field}`);
  }
  return value;
}

export function requireResponseParticipantPair(
  value: unknown,
  responseName: string,
): readonly [number, number] {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new Error(`${responseName} response has invalid participantIds`);
  }
  const first = requireResponseSafeInteger({
    responseName,
    field: 'participantIds[0]',
    value: value[0],
    minimum: 1,
  });
  const second = requireResponseSafeInteger({
    responseName,
    field: 'participantIds[1]',
    value: value[1],
    minimum: 1,
  });
  if (first === second) {
    throw new Error(`${responseName} response has duplicate participantIds`);
  }
  if (first !== 1 || second !== 2) {
    throw new Error(`${responseName} response has unsupported participantIds`);
  }
  return [first, second];
}

export function requireResponseRpId(value: unknown, responseName: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(`${responseName} response has invalid rpId`);
  return parsed.value;
}

function parseWalletRegistrationEd25519AuthorityScope(
  value: unknown,
  responseName: string,
): Ed25519AuthorityScope {
  const authorityScope = requireResponseRecord({
    responseName,
    field: 'authorityScope',
    value,
  });
  switch (authorityScope.kind) {
    case 'passkey_rp':
      assertExactResponseKeys(authorityScope, ['kind', 'rpId'], responseName);
      return {
        kind: 'passkey_rp',
        rpId: requireResponseRpId(authorityScope.rpId, responseName),
      };
    case 'email_otp': {
      assertExactResponseKeys(authorityScope, ['kind', 'provider', 'providerUserId'], responseName);
      if (authorityScope.provider !== 'google' && authorityScope.provider !== 'email') {
        throw new Error(`${responseName} response has invalid authorityScope provider`);
      }
      return {
        kind: 'email_otp',
        provider: authorityScope.provider,
        providerUserId: requireResponseString({
          responseName,
          field: 'authorityScope.providerUserId',
          value: authorityScope.providerUserId,
        }),
      };
    }
    default:
      throw new Error(`${responseName} response has invalid authorityScope`);
  }
}

export function parseWalletEd25519YaoSignerPublicResult(
  value: unknown,
  responseName: string,
): WalletEd25519YaoSignerPublicResult {
  const ed25519 = requireResponseRecord({ responseName, field: 'ed25519', value });
  assertExactResponseKeys(
    ed25519,
    [
      'signerSlot',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'publicKey',
      'relayerKeyId',
      'keyVersion',
      'recoveryExportCapable',
      'participantIds',
    ],
    responseName,
  );
  if (ed25519.recoveryExportCapable !== true) {
    throw new Error(`${responseName} response is not recovery/export capable`);
  }
  return {
    signerSlot: requireResponseSafeInteger({
      responseName,
      field: 'ed25519.signerSlot',
      value: ed25519.signerSlot,
      minimum: 1,
    }),
    nearAccountId: requireResponseString({
      responseName,
      field: 'ed25519.nearAccountId',
      value: ed25519.nearAccountId,
    }),
    nearEd25519SigningKeyId: requireResponseString({
      responseName,
      field: 'ed25519.nearEd25519SigningKeyId',
      value: ed25519.nearEd25519SigningKeyId,
    }),
    publicKey: requireResponseString({
      responseName,
      field: 'ed25519.publicKey',
      value: ed25519.publicKey,
    }),
    relayerKeyId: requireResponseString({
      responseName,
      field: 'ed25519.relayerKeyId',
      value: ed25519.relayerKeyId,
    }),
    keyVersion: requireResponseString({
      responseName,
      field: 'ed25519.keyVersion',
      value: ed25519.keyVersion,
    }),
    recoveryExportCapable: true,
    participantIds: requireResponseParticipantPair(ed25519.participantIds, responseName),
  };
}

function parseWalletRegistrationEd25519Result(
  value: unknown,
  responseName: string,
): WalletRegistrationEd25519YaoPublicResult {
  const ed25519 = requireResponseRecord({ responseName, field: 'ed25519', value });
  assertExactResponseKeys(
    ed25519,
    [
      'signerSlot',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'publicKey',
      'relayerKeyId',
      'keyVersion',
      'recoveryExportCapable',
      'participantIds',
      'thresholdSessionId',
      'runtimePolicyScope',
      'routerAbNormalSigning',
    ],
    responseName,
  );
  const publicResult = parseWalletEd25519YaoSignerPublicResult(
    {
      signerSlot: ed25519.signerSlot,
      nearAccountId: ed25519.nearAccountId,
      nearEd25519SigningKeyId: ed25519.nearEd25519SigningKeyId,
      publicKey: ed25519.publicKey,
      relayerKeyId: ed25519.relayerKeyId,
      keyVersion: ed25519.keyVersion,
      recoveryExportCapable: ed25519.recoveryExportCapable,
      participantIds: ed25519.participantIds,
    },
    responseName,
  );
  const thresholdSessionId = parseThresholdEd25519SessionId(ed25519.thresholdSessionId);
  if (!thresholdSessionId.ok) {
    throw new Error(`${responseName} response has invalid ed25519.thresholdSessionId`);
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(ed25519.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error(`${responseName} response has invalid ed25519.runtimePolicyScope`);
  }
  return {
    ...publicResult,
    thresholdSessionId: thresholdSessionId.value,
    runtimePolicyScope,
    routerAbNormalSigning: requireRouterAbEd25519NormalSigningState(ed25519.routerAbNormalSigning),
  };
}

export function parseWalletAddSignerChainTarget(
  value: unknown,
  responseName: string,
): ThresholdEcdsaChainTarget {
  const target = requireResponseRecord({ responseName, field: 'chainTarget', value });
  switch (target.kind) {
    case 'evm':
      assertExactResponseKeys(
        target,
        ['kind', 'namespace', 'chainId', 'networkSlug'],
        responseName,
      );
      return thresholdEcdsaChainTargetFromRequest(target);
    case 'tempo':
      assertExactResponseKeys(target, ['kind', 'chainId', 'networkSlug'], responseName);
      return thresholdEcdsaChainTargetFromRequest(target);
    default:
      throw new Error(`${responseName} response has invalid chainTarget kind`);
  }
}

export function parseWalletAddSignerEcdsaWalletKey(
  value: unknown,
  responseName: string,
): WalletRegistrationEcdsaWalletKey {
  const key = requireResponseRecord({ responseName, field: 'ecdsa.walletKeys[]', value });
  assertExactResponseKeys(
    key,
    [
      'keyScope',
      'chainTarget',
      'walletId',
      'evmFamilySigningKeySlotId',
      'keyHandle',
      'ecdsaThresholdKeyId',
      'signingRootId',
      'signingRootVersion',
      'thresholdEcdsaPublicKeyB64u',
      'thresholdOwnerAddress',
      'relayerKeyId',
      'relayerVerifyingShareB64u',
      'contextBinding32B64u',
      'derivationClientSharePublicKey33B64u',
      'clientShareRetryCounter',
      'relayerShareRetryCounter',
      'participantIds',
      'publicCapability',
    ],
    responseName,
  );
  if (key.keyScope !== 'evm-family') {
    throw new Error(`${responseName} response has invalid keyScope`);
  }
  return {
    keyScope: 'evm-family',
    chainTarget: parseWalletAddSignerChainTarget(key.chainTarget, responseName),
    walletId: requireResponseString({ responseName, field: 'walletId', value: key.walletId }),
    evmFamilySigningKeySlotId: requireResponseString({
      responseName,
      field: 'evmFamilySigningKeySlotId',
      value: key.evmFamilySigningKeySlotId,
    }),
    keyHandle: requireResponseString({ responseName, field: 'keyHandle', value: key.keyHandle }),
    ecdsaThresholdKeyId: requireResponseString({
      responseName,
      field: 'ecdsaThresholdKeyId',
      value: key.ecdsaThresholdKeyId,
    }),
    signingRootId: requireResponseString({
      responseName,
      field: 'signingRootId',
      value: key.signingRootId,
    }),
    signingRootVersion: requireResponseString({
      responseName,
      field: 'signingRootVersion',
      value: key.signingRootVersion,
    }),
    thresholdEcdsaPublicKeyB64u: requireResponseString({
      responseName,
      field: 'thresholdEcdsaPublicKeyB64u',
      value: key.thresholdEcdsaPublicKeyB64u,
    }),
    thresholdOwnerAddress: requireResponseString({
      responseName,
      field: 'thresholdOwnerAddress',
      value: key.thresholdOwnerAddress,
    }),
    relayerKeyId: requireResponseString({
      responseName,
      field: 'relayerKeyId',
      value: key.relayerKeyId,
    }),
    relayerVerifyingShareB64u: requireResponseString({
      responseName,
      field: 'relayerVerifyingShareB64u',
      value: key.relayerVerifyingShareB64u,
    }),
    contextBinding32B64u: requireResponseString({
      responseName,
      field: 'contextBinding32B64u',
      value: key.contextBinding32B64u,
    }),
    derivationClientSharePublicKey33B64u: requireResponseString({
      responseName,
      field: 'derivationClientSharePublicKey33B64u',
      value: key.derivationClientSharePublicKey33B64u,
    }),
    clientShareRetryCounter: requireResponseSafeInteger({
      responseName,
      field: 'clientShareRetryCounter',
      value: key.clientShareRetryCounter,
      minimum: 0,
    }),
    relayerShareRetryCounter: requireResponseSafeInteger({
      responseName,
      field: 'relayerShareRetryCounter',
      value: key.relayerShareRetryCounter,
      minimum: 0,
    }),
    participantIds: requireResponseParticipantPair(key.participantIds, responseName),
    publicCapability: parseRouterAbEcdsaDerivationPublicCapabilityV1(key.publicCapability),
  };
}

function parseWalletRegistrationRouteTimingName(value: unknown): WalletRegistrationRouteTimingName {
  switch (value) {
    case 'registrationIntentLoadMs':
    case 'registrationIntentDigestMs':
    case 'registrationIntentConsumeMs':
    case 'registrationAttemptGateMs':
    case 'registrationPreparationPersistMs':
    case 'registrationPreparationLoadMs':
    case 'registrationPreparationConsumeMs':
    case 'registrationPreparationScopeCheckMs':
    case 'registrationAuthorityVerifyMs':
    case 'registrationEcdsaPrepareMs':
    case 'registrationCeremonyPersistMs':
    case 'registerPrepareTotalMs':
    case 'registerStartTotalMs':
    case 'registrationEcdsaRespondMs':
    case 'registrationFinalizeReplayLoadMs':
    case 'registrationCeremonyLoadMs':
    case 'registrationEcdsaBootstrapVerifyMs':
    case 'sponsoredNearAccountCreateMs':
    case 'registrationKeygenMs':
    case 'registrationEmailOtpEnrollmentPlanMs':
    case 'relaySessionMintMs':
    case 'relayGoogleEmailOtpActivationPlanMs':
    case 'relayPersistenceMs':
    case 'registrationFinalizeReplayCacheMs':
    case 'registerFinalizeTotalMs':
      return value;
    default:
      throw new Error('Wallet registration finalize response has invalid diagnostics timing name');
  }
}

export function parseWalletRegistrationFinalizeDiagnostics(
  value: unknown,
): WalletRegistrationRouteDiagnostics {
  const responseName = 'Wallet registration finalize';
  const diagnostics = requireResponseRecord({
    responseName,
    field: 'registrationDiagnostics',
    value,
  });
  assertExactResponseKeys(diagnostics, ['kind', 'route', 'entries'], responseName);
  if (
    diagnostics.kind !== 'wallet_registration_route_diagnostics_v1' ||
    diagnostics.route !== 'wallets_register_finalize' ||
    !Array.isArray(diagnostics.entries)
  ) {
    throw new Error(`${responseName} response has invalid registrationDiagnostics`);
  }
  return {
    kind: 'wallet_registration_route_diagnostics_v1',
    route: 'wallets_register_finalize',
    entries: diagnostics.entries.map((entryValue) => {
      const entry = requireResponseRecord({
        responseName,
        field: 'registrationDiagnostics.entries[]',
        value: entryValue,
      });
      assertExactResponseKeys(entry, ['name', 'durationMs'], responseName);
      if (
        typeof entry.durationMs !== 'number' ||
        !Number.isFinite(entry.durationMs) ||
        entry.durationMs < 0
      ) {
        throw new Error(`${responseName} response has invalid diagnostics durationMs`);
      }
      return {
        name: parseWalletRegistrationRouteTimingName(entry.name),
        durationMs: entry.durationMs,
      };
    }),
  };
}

export function parseWalletRegistrationFinalizeAuthority(value: unknown): WalletAuthAuthority {
  const responseName = 'Wallet registration finalize';
  const authority = requireResponseRecord({ responseName, field: 'authority', value });
  assertExactResponseKeys(authority, ['walletId', 'factor', 'verifier', 'bindingId'], responseName);
  const factor = requireResponseRecord({
    responseName,
    field: 'authority.factor',
    value: authority.factor,
  });
  const verifier = requireResponseRecord({
    responseName,
    field: 'authority.verifier',
    value: authority.verifier,
  });
  switch (factor.kind) {
    case 'passkey':
      assertExactResponseKeys(factor, ['kind', 'credentialIdB64u'], responseName);
      assertExactResponseKeys(verifier, ['kind', 'rpId'], responseName);
      break;
    case 'email_otp':
      assertExactResponseKeys(factor, ['kind', 'provider', 'providerUserId'], responseName);
      assertExactResponseKeys(verifier, ['kind', 'emailHashHex'], responseName);
      break;
    default:
      throw new Error(`${responseName} response has invalid authority factor`);
  }
  const parsed = parseWalletAuthAuthority(authority);
  if (!parsed) {
    throw new Error(`${responseName} response has invalid authority`);
  }
  return parsed;
}

type ParsedWalletRegistrationFinalizeAuthorityBranch =
  | {
      kind: 'passkey';
      rpId: string;
      authMethod: Extract<WalletRegistrationFinalizeAuthMethod, { kind: 'passkey' }>;
    }
  | {
      kind: 'email_otp';
      authMethod: Extract<WalletRegistrationFinalizeAuthMethod, { kind: 'email_otp' }>;
      rpId?: never;
    };

export function parseWalletRegistrationFinalizeAuthorityBranch(args: {
  response: Record<string, unknown>;
  walletId: WalletId;
  authority: WalletAuthAuthority;
}): ParsedWalletRegistrationFinalizeAuthorityBranch {
  const responseName = 'Wallet registration finalize';
  const authMethod = requireResponseRecord({
    responseName,
    field: 'authMethod',
    value: args.response.authMethod,
  });
  if (String(args.authority.walletId) !== String(args.walletId)) {
    throw new Error(`${responseName} response authority wallet mismatch`);
  }
  switch (authMethod.kind) {
    case 'passkey': {
      assertExactResponseKeys(
        authMethod,
        ['kind', 'credentialIdB64u', 'credentialPublicKeyB64u'],
        responseName,
      );
      if (!isPasskeyWalletAuthAuthority(args.authority)) {
        throw new Error(`${responseName} response has inconsistent passkey authority`);
      }
      const rpId = requireResponseRpId(args.response.rpId, responseName);
      const credentialIdB64u = requireResponseString({
        responseName,
        field: 'authMethod.credentialIdB64u',
        value: authMethod.credentialIdB64u,
      });
      if (
        String(args.authority.factor.credentialIdB64u) !== credentialIdB64u ||
        String(args.authority.verifier.rpId) !== String(rpId)
      ) {
        throw new Error(`${responseName} response passkey authority binding mismatch`);
      }
      return {
        kind: 'passkey',
        rpId,
        authMethod: {
          kind: 'passkey',
          credentialIdB64u,
          credentialPublicKeyB64u: requireResponseString({
            responseName,
            field: 'authMethod.credentialPublicKeyB64u',
            value: authMethod.credentialPublicKeyB64u,
          }),
        },
      };
    }
    case 'email_otp':
      assertExactResponseKeys(authMethod, ['kind', 'registrationAuthorityId'], responseName);
      if (isPasskeyWalletAuthAuthority(args.authority) || args.response.rpId !== undefined) {
        throw new Error(`${responseName} response has inconsistent email OTP authority`);
      }
      return {
        kind: 'email_otp',
        authMethod: {
          kind: 'email_otp',
          registrationAuthorityId: requireResponseString({
            responseName,
            field: 'authMethod.registrationAuthorityId',
            value: authMethod.registrationAuthorityId,
          }),
        },
      };
    default:
      throw new Error(`${responseName} response has invalid authMethod`);
  }
}

function parseWalletRegistrationNearAccountProvisioning(
  value: unknown,
): RegistrationNearAccountProvisioning {
  const responseName = 'Wallet registration finalize';
  const provisioning = requireResponseRecord({
    responseName,
    field: 'accountProvisioning',
    value,
  });
  switch (provisioning.kind) {
    case 'implicit_account':
      assertExactResponseKeys(provisioning, ['kind', 'accountIdSource'], responseName);
      if (provisioning.accountIdSource !== 'ed25519_public_key') {
        throw new Error(`${responseName} response has invalid implicit account provisioning`);
      }
      return {
        kind: 'implicit_account',
        accountIdSource: 'ed25519_public_key',
      };
    case 'sponsored_named_account': {
      assertExactResponseKeys(
        provisioning,
        ['kind', 'requestedAccountId', 'sponsor'],
        responseName,
      );
      const requestedAccountId = parseNamedNearAccountId(provisioning.requestedAccountId);
      if (!requestedAccountId.ok || provisioning.sponsor !== 'relayer') {
        throw new Error(`${responseName} response has invalid named account provisioning`);
      }
      return {
        kind: 'sponsored_named_account',
        requestedAccountId: requestedAccountId.value,
        sponsor: 'relayer',
      };
    }
    default:
      throw new Error(`${responseName} response has invalid accountProvisioning kind`);
  }
}

function parseWalletRegistrationResolvedNearAccount(
  value: unknown,
): ResolvedRegistrationNearAccount {
  const responseName = 'Wallet registration finalize';
  const resolved = requireResponseRecord({
    responseName,
    field: 'resolvedAccount',
    value,
  });
  switch (resolved.kind) {
    case 'implicit_account': {
      assertExactResponseKeys(
        resolved,
        ['kind', 'nearAccountId', 'nearEd25519SigningKeyId'],
        responseName,
      );
      const nearAccountId = parseImplicitNearAccountId(resolved.nearAccountId);
      if (!nearAccountId.ok) {
        throw new Error(`${responseName} response has invalid implicit nearAccountId`);
      }
      return {
        kind: 'implicit_account',
        nearAccountId: nearAccountId.value,
        nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(resolved.nearEd25519SigningKeyId),
      };
    }
    case 'sponsored_named_account': {
      assertExactResponseKeys(
        resolved,
        ['kind', 'nearAccountId', 'nearEd25519SigningKeyId', 'transactionHash'],
        responseName,
      );
      const nearAccountId = parseNamedNearAccountId(resolved.nearAccountId);
      if (!nearAccountId.ok) {
        throw new Error(`${responseName} response has invalid named nearAccountId`);
      }
      return {
        kind: 'sponsored_named_account',
        nearAccountId: nearAccountId.value,
        nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(resolved.nearEd25519SigningKeyId),
        transactionHash: requireResponseString({
          responseName,
          field: 'resolvedAccount.transactionHash',
          value: resolved.transactionHash,
        }),
      };
    }
    default:
      throw new Error(`${responseName} response has invalid resolvedAccount kind`);
  }
}

function parseWalletRegistrationFinalizeEcdsaResult(args: { value: unknown; walletId: WalletId }): {
  walletKeys: WalletRegistrationEcdsaWalletKey[];
} {
  const responseName = 'Wallet registration finalize';
  const ecdsa = requireResponseRecord({ responseName, field: 'ecdsa', value: args.value });
  assertExactResponseKeys(ecdsa, ['walletKeys'], responseName);
  if (!Array.isArray(ecdsa.walletKeys) || ecdsa.walletKeys.length === 0) {
    throw new Error(`${responseName} response has invalid walletKeys`);
  }
  const targetKeys = new Set<string>();
  const walletKeys = ecdsa.walletKeys.map((value) => {
    const walletKey = parseWalletAddSignerEcdsaWalletKey(value, responseName);
    if (walletKey.walletId !== String(args.walletId)) {
      throw new Error(`${responseName} response ECDSA walletId mismatch`);
    }
    if (
      String(walletKey.publicCapability.client_id) !== String(args.walletId) ||
      walletKey.publicCapability.public_identity.context_binding_b64u !==
        walletKey.contextBinding32B64u ||
      walletKey.publicCapability.public_identity.derivation_client_share_public_key33_b64u !==
        walletKey.derivationClientSharePublicKey33B64u ||
      walletKey.publicCapability.public_identity.threshold_public_key33_b64u !==
        walletKey.thresholdEcdsaPublicKeyB64u ||
      walletKey.publicCapability.public_identity.client_share_retry_counter !==
        walletKey.clientShareRetryCounter ||
      walletKey.publicCapability.public_identity.server_share_retry_counter !==
        walletKey.relayerShareRetryCounter
    ) {
      throw new Error(`${responseName} response ECDSA public capability mismatch`);
    }
    const targetKey = thresholdEcdsaChainTargetKey(walletKey.chainTarget);
    if (targetKeys.has(targetKey)) {
      throw new Error(`${responseName} response has duplicate ECDSA target ${targetKey}`);
    }
    targetKeys.add(targetKey);
    return walletKey;
  });
  return { walletKeys };
}

function parseWalletRegistrationFinalizeNearResult(args: {
  response: Record<string, unknown>;
  walletId: WalletId;
  authority: WalletAuthAuthority;
}): {
  authorityScope: Ed25519AuthorityScope;
  accountProvisioning: RegistrationNearAccountProvisioning;
  resolvedAccount: ResolvedRegistrationNearAccount;
  ed25519: WalletRegistrationEd25519YaoPublicResult;
} {
  const responseName = 'Wallet registration finalize';
  const authorityScope = parseWalletRegistrationEd25519AuthorityScope(
    args.response.authorityScope,
    responseName,
  );
  const accountProvisioning = parseWalletRegistrationNearAccountProvisioning(
    args.response.accountProvisioning,
  );
  const resolvedAccount = parseWalletRegistrationResolvedNearAccount(args.response.resolvedAccount);
  const ed25519 = parseWalletRegistrationEd25519Result(args.response.ed25519, responseName);
  if (
    accountProvisioning.kind !== resolvedAccount.kind ||
    resolvedAccount.nearAccountId !== ed25519.nearAccountId ||
    resolvedAccount.nearEd25519SigningKeyId !== ed25519.nearEd25519SigningKeyId
  ) {
    throw new Error(`${responseName} response has inconsistent Ed25519 identity`);
  }
  if (
    (authorityScope.kind === 'passkey_rp' &&
      (!isPasskeyWalletAuthAuthority(args.authority) ||
        String(args.authority.verifier.rpId) !== String(authorityScope.rpId))) ||
    (authorityScope.kind === 'email_otp' &&
      (isPasskeyWalletAuthAuthority(args.authority) ||
        args.authority.factor.provider !== authorityScope.provider ||
        String(args.authority.factor.providerUserId) !== authorityScope.providerUserId))
  ) {
    throw new Error(`${responseName} response authorityScope mismatch`);
  }
  return {
    authorityScope,
    accountProvisioning,
    resolvedAccount,
    ed25519,
  };
}

export function parseWalletRegistrationFinalizeResponse(args: {
  value: unknown;
  expectedKind: FinalizeWalletRegistrationArgs['kind'];
}): WalletRegistrationFinalizeResponse {
  const responseName = 'Wallet registration finalize';
  const response = requireResponseRecord({
    responseName,
    field: 'body',
    value: args.value,
  });
  assertExactResponseKeys(
    response,
    [
      'ok',
      'walletId',
      'authority',
      'foundingAuthority',
      'foundingAuthMethod',
      'registrationDiagnostics',
      'rpId',
      'authMethod',
      'walletCustody',
      'custodyKeyManifestDigestB64u',
      'kind',
      'authorityScope',
      'accountProvisioning',
      'resolvedAccount',
      'ed25519',
      'ecdsa',
    ],
    responseName,
  );
  if (response.ok !== true || response.kind !== args.expectedKind) {
    throw new Error(`${responseName} response substituted signer branch`);
  }
  const walletId = walletIdFromString(
    requireResponseString({
      responseName,
      field: 'walletId',
      value: response.walletId,
    }),
  );
  const authority = parseWalletRegistrationFinalizeAuthority(response.authority);
  const foundingAuthority = parseWalletAuthorityV1(response.foundingAuthority);
  const foundingAuthMethod = parseWalletAuthMethodRecordV2(response.foundingAuthMethod);
  if (!foundingAuthority.ok) {
    throw new Error(
      `${responseName} response has an invalid founding authority: ${foundingAuthority.error.message}`,
    );
  }
  if (foundingAuthority.value.state !== 'active') {
    throw new Error(`${responseName} response has an inactive founding authority`);
  }
  if (!foundingAuthMethod) {
    throw new Error(`${responseName} response has an invalid founding auth method`);
  }
  if (foundingAuthMethod.status !== 'active') {
    throw new Error(`${responseName} response has an inactive founding auth method`);
  }
  if (foundingAuthority.value.walletId !== walletId || foundingAuthMethod.walletId !== walletId) {
    throw new Error(`${responseName} response changed the founding wallet identity`);
  }
  if (foundingAuthMethod.walletAuthorityId !== foundingAuthority.value.authorityId) {
    throw new Error(`${responseName} response has mismatched founding authority identities`);
  }
  if (foundingAuthMethod.walletAuthMethodId !== authority.bindingId) {
    throw new Error(`${responseName} response has mismatched founding auth-method identities`);
  }
  const authorityBranch = parseWalletRegistrationFinalizeAuthorityBranch({
    response,
    walletId,
    authority,
  });
  const registrationDiagnostics =
    response.registrationDiagnostics === undefined
      ? undefined
      : parseWalletRegistrationFinalizeDiagnostics(response.registrationDiagnostics);
  /* Absent is a real state — no custody payload rode this leg — and distinct
     from every reported outcome. It must not be conflated with `committed`. */
  const walletCustody =
    response.walletCustody === undefined
      ? {}
      : {
          walletCustody: parseWalletCustodyRegistrationOutcome(
            response.walletCustody,
            responseName,
          ),
        };
  const custodyKeyManifestDigestB64u =
    response.custodyKeyManifestDigestB64u === undefined
      ? undefined
      : requireResponseString({
          responseName,
          field: 'custodyKeyManifestDigestB64u',
          value: response.custodyKeyManifestDigestB64u,
        });
  if (
    custodyKeyManifestDigestB64u !== undefined &&
    base64UrlDecode(custodyKeyManifestDigestB64u).byteLength !== 32
  ) {
    throw new Error(`${responseName} response has invalid custodyKeyManifestDigestB64u`);
  }
  const manifest =
    custodyKeyManifestDigestB64u === undefined ? {} : { custodyKeyManifestDigestB64u };

  switch (response.kind) {
    case 'near_ed25519': {
      if (response.ecdsa !== undefined) {
        throw new Error(`${responseName} response mixed signer branches`);
      }
      const near = parseWalletRegistrationFinalizeNearResult({
        response,
        walletId,
        authority,
      });
      if (authorityBranch.kind === 'passkey') {
        return {
          ok: true,
          walletId,
          authority,
          foundingAuthority: foundingAuthority.value,
          foundingAuthMethod,
          ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
          ...walletCustody,
          ...manifest,
          rpId: authorityBranch.rpId,
          authMethod: authorityBranch.authMethod,
          kind: 'near_ed25519',
          authorityScope: near.authorityScope,
          accountProvisioning: near.accountProvisioning,
          resolvedAccount: near.resolvedAccount,
          ed25519: near.ed25519,
        };
      }
      return {
        ok: true,
        walletId,
        authority,
        foundingAuthority: foundingAuthority.value,
        foundingAuthMethod,
        ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
        ...walletCustody,
        ...manifest,
        authMethod: authorityBranch.authMethod,
        kind: 'near_ed25519',
        authorityScope: near.authorityScope,
        accountProvisioning: near.accountProvisioning,
        resolvedAccount: near.resolvedAccount,
        ed25519: near.ed25519,
      };
    }
    case 'evm_family_ecdsa': {
      if (
        response.authorityScope !== undefined ||
        response.accountProvisioning !== undefined ||
        response.resolvedAccount !== undefined ||
        response.ed25519 !== undefined
      ) {
        throw new Error(`${responseName} response mixed signer branches`);
      }
      const ecdsa = parseWalletRegistrationFinalizeEcdsaResult({
        value: response.ecdsa,
        walletId,
      });
      if (authorityBranch.kind === 'passkey') {
        return {
          ok: true,
          walletId,
          authority,
          foundingAuthority: foundingAuthority.value,
          foundingAuthMethod,
          ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
          ...walletCustody,
          ...manifest,
          rpId: authorityBranch.rpId,
          authMethod: authorityBranch.authMethod,
          kind: 'evm_family_ecdsa',
          ecdsa,
        };
      }
      return {
        ok: true,
        walletId,
        authority,
        foundingAuthority: foundingAuthority.value,
        foundingAuthMethod,
        ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
        ...walletCustody,
        ...manifest,
        authMethod: authorityBranch.authMethod,
        kind: 'evm_family_ecdsa',
        ecdsa,
      };
    }
    default:
      throw new Error(`${responseName} response has invalid kind`);
  }
}
