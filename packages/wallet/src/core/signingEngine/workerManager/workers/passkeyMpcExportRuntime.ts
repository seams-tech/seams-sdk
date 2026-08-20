import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
  RouterAbEd25519YaoExportWorkerPayloadV1,
} from '@/core/types/secure-confirm-worker';
import { ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1 } from '@/core/types/secure-confirm-worker';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { bytesToHex } from '../../chains/evm/bytes';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationRef,
  parseWalletId,
} from '@shared/utils/domainIds';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { base58Encode } from '@shared/utils/base58';
import {
  normalizeOptionalTrimmedString,
  normalizeOptionalNonEmptyString,
  normalizePositiveInteger,
  normalizeNonNegativeInteger,
} from '@shared/utils/normalize';
import { awaitUserConfirmationV2 } from '../../uiConfirm/awaitUserConfirmation';
import {
  UserConfirmationType,
  type ExportPrivateKeyDisplayEntry,
  type LocalOnlyExportSubject,
  type UserConfirmRequest,
} from '../../stepUpConfirmation/channel/confirmTypes';
import initEvmCrypto, {
  derive_secp256k1_keypair_from_prf_second,
  init_evm_crypto,
} from '../../../../../../../wasm/evm_crypto/pkg/evm_crypto.js';
import {
  RouterAbEd25519YaoClientV1,
  RouterAbEd25519YaoHttpActivationTransportV1,
} from '../../threshold/ed25519/yaoClient';
import {
  deriveRouterAbEd25519YaoExportAuthorizationDigestV1,
  deriveRouterAbEd25519YaoExportConfirmationDigestV1,
  deriveRouterAbEd25519YaoRuntimePolicyBindingV1,
  parseRouterAbEd25519YaoExportAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoExportAuthorizationIdentityV1,
} from '@shared/utils/routerAbEd25519Yao';
import { normalizeThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import { normalizeAuthenticationCredential } from '../../webauthnAuth/credentials/helpers';
import { parsePasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import { walletCustodyCacheEnvelopeFromRecordV1 } from '../../walletCustody/openCustodyCache';

type EcdsaDerivationThresholdExportWorkerPayload = Extract<
  ExportPrivateKeysWithUiWorkerPayload,
  { artifactKind: 'ecdsa-derivation-secp256k1-export' }
>;
type ExportWorkerTarget = {
  kind: 'ecdsa';
  scheme: 'secp256k1';
  chainTarget: ThresholdEcdsaChainTarget;
};
type Secp256k1ExportPrivateKeyDisplayEntry = ExportPrivateKeyDisplayEntry & { scheme: 'secp256k1' };
type Ed25519ExportPrivateKeyDisplayEntry = ExportPrivateKeyDisplayEntry & { scheme: 'ed25519' };

const evmCryptoWasmUrl = resolveWasmUrl('evm_crypto.wasm', 'Eth Signer');
let evmCryptoWasmInitPromise: Promise<void> | null = null;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
function asRecord(value: unknown): Record<string, unknown> | null {
  return isRecord(value) ? value : null;
}
function nowMs(): number {
  return Date.now();
}
function toSessionId(prefix: string): string {
  return `${String(prefix || '').trim() || 'session'}:${secureRandomBase64Url(32, 'passkey MPC export worker session IDs')}`;
}

function isCancellationLikeError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  const lowered = message.toLowerCase();
  return (
    lowered.includes('notallowederror') ||
    lowered.includes('aborterror') ||
    lowered.includes('user cancelled') ||
    lowered.includes('user canceled') ||
    lowered.includes('user aborted') ||
    lowered.includes('rejected')
  );
}

function messageFromError(error: unknown, fallback: string): string {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.trim() || fallback;
}

function coerceTheme(value: unknown): 'dark' | 'light' | undefined {
  return value === 'dark' || value === 'light' ? value : undefined;
}

function coerceVariant(value: unknown): 'drawer' | 'modal' | undefined {
  return value === 'drawer' || value === 'modal' ? value : undefined;
}

function parseExportWorkerTarget(payload: Record<string, unknown>): ExportWorkerTarget | null {
  const rawChainTarget = asRecord(payload.chainTarget);
  if (!rawChainTarget) return null;
  try {
    return {
      kind: 'ecdsa',
      scheme: 'secp256k1',
      chainTarget: thresholdEcdsaChainTargetFromRequest(rawChainTarget),
    };
  } catch {
    return null;
  }
}

function secp256k1LabelForExportTarget(chainTarget: ThresholdEcdsaChainTarget): string {
  return chainTarget.kind === 'tempo' ? 'Tempo secp256k1' : 'EVM secp256k1';
}

function labelForExportTarget(target: ExportWorkerTarget): string {
  return secp256k1LabelForExportTarget(target.chainTarget);
}

function parseWorkerBytes32(value: unknown): readonly number[] | null {
  if (!Array.isArray(value) || value.length !== 32) return null;
  const bytes: number[] = [];
  for (const entry of value) {
    if (!Number.isInteger(entry) || entry < 0 || entry > 255) return null;
    bytes.push(entry);
  }
  return bytes;
}

function custodyEnvelopeInputForExport(
  record: RouterAbEd25519YaoExportWorkerPayloadV1['walletCustodyEnvelope'],
) {
  if (record.binding.kind !== 'wallet_custody_seed_v1' && record.binding.kind !== 'ed25519_yao_client_root_v1') {
    throw new Error('Ed25519 export requires a wallet seed or Client-root envelope');
  }
  if (record.lifecycle.state !== 'active') {
    throw new Error('Ed25519 export requires an active factor-sealed envelope');
  }
  const envelope =
    record.binding.kind === 'wallet_custody_seed_v1'
      ? walletCustodyCacheEnvelopeFromRecordV1(record)
      : {
          bindingJson: JSON.stringify({
            walletId: record.walletId,
            envelopeId: record.envelopeId,
            factor: record.factor,
            envelopeRevision: record.envelopeRevision,
            binding: record.binding,
          }),
          nonceB64u: record.nonceB64u,
          ciphertextB64u: record.sealedCustodySecretB64u,
          aadHashB64u: record.aadHashB64u,
          ciphertextDigestB64u: record.ciphertextDigestB64u,
        };
  return {
    bindingJson: envelope.bindingJson,
    nonce: base64UrlDecode(envelope.nonceB64u),
    ciphertext: base64UrlDecode(envelope.ciphertextB64u),
    aadHash: base64UrlDecode(envelope.aadHashB64u),
    ciphertextDigest: base64UrlDecode(envelope.ciphertextDigestB64u),
  };
}

function parseEd25519YaoExportWorkerPayload(
  payload: Record<string, unknown>,
): RouterAbEd25519YaoExportWorkerPayloadV1 | null {
  if (payload.artifactKind !== ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1) return null;
  const parsedWalletId = parseWalletId(payload.walletId);
  if (!parsedWalletId.ok) return null;
  const nearAccountId = normalizeOptionalNonEmptyString(payload.nearAccountId);
  const relayerUrl = normalizeOptionalNonEmptyString(payload.relayerUrl);
  const flowId = normalizeOptionalNonEmptyString(payload.flowId);
  const viewerSessionId = normalizeOptionalNonEmptyString(payload.viewerSessionId);
  const exactLane = asRecord(payload.exactLane);
  const authorization = asRecord(payload.authorization);
  const capability = asRecord(payload.capability);
  if (
    !nearAccountId ||
    !relayerUrl ||
    !flowId ||
    !viewerSessionId ||
    !exactLane ||
    !authorization ||
    authorization.kind !== 'opaque_wallet_session' ||
    !capability
  ) {
    return null;
  }
  const nearEd25519SigningKeyId = normalizeOptionalNonEmptyString(
    exactLane.nearEd25519SigningKeyId,
  );
  const credentialIdB64u = normalizeOptionalNonEmptyString(exactLane.credentialIdB64u);
  const walletSessionToken = normalizeOptionalNonEmptyString(authorization.walletSessionToken);
  const materialActivationResult = parseMpcMaterialActivationRef(exactLane.materialActivation);
  const capabilityMaterialActivationResult = parseMpcMaterialActivationRef(
    capability.materialActivation,
  );
  const signerSlot = normalizePositiveInteger(exactLane.signerSlot);
  const registeredPublicKey = parseWorkerBytes32(capability.registeredPublicKey);
  const activeCapabilityBinding = parseWorkerBytes32(capability.activeCapabilityBinding);
  const stateEpoch = normalizeNonNegativeInteger(capability.stateEpoch);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(capability.runtimePolicyScope);
  let walletCustodyEnvelope: RouterAbEd25519YaoExportWorkerPayloadV1['walletCustodyEnvelope'];
  try {
    walletCustodyEnvelope = parsePasskeyCustodyEnvelopeRecord(payload.walletCustodyEnvelope);
  } catch {
    return null;
  }
  const activationIdentity = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
    scope: capability.scope,
    application_binding: capability.applicationBinding,
    participant_ids: capability.participantIds,
  });
  if (
    !nearEd25519SigningKeyId ||
    !credentialIdB64u ||
    !walletSessionToken ||
    !materialActivationResult.ok ||
    !capabilityMaterialActivationResult.ok ||
    signerSlot == null ||
    !registeredPublicKey ||
    !activeCapabilityBinding ||
    stateEpoch == null ||
    !runtimePolicyScope ||
    !activationIdentity.ok ||
    String(walletCustodyEnvelope.walletId) !== String(parsedWalletId.value) ||
    walletCustodyEnvelope.lifecycle.state !== 'active' ||
    walletCustodyEnvelope.factor.kind !== 'passkey' ||
    String(walletCustodyEnvelope.factor.credentialIdB64u) !== credentialIdB64u ||
    (walletCustodyEnvelope.binding.kind === 'ed25519_yao_client_root_v1' &&
      (walletCustodyEnvelope.binding.targetFactor.kind !== 'passkey_prf' ||
        walletCustodyEnvelope.binding.registeredPublicKeyB64u !==
          base64UrlEncode(Uint8Array.from(registeredPublicKey)))) ||
    (walletCustodyEnvelope.binding.kind !== 'wallet_custody_seed_v1' &&
      walletCustodyEnvelope.binding.kind !== 'ed25519_yao_client_root_v1')
  ) {
    return null;
  }
  return {
    artifactKind: ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1,
    walletId: String(parsedWalletId.value),
    nearAccountId,
    relayerUrl,
    authorization: {
      kind: 'opaque_wallet_session',
      walletSessionToken,
    },
    flowId,
    viewerSessionId,
    exactLane: {
      nearEd25519SigningKeyId,
      signerSlot,
      credentialIdB64u,
      materialActivation: materialActivationResult.value,
    },
    walletCustodyEnvelope,
    capability: {
      materialActivation: capabilityMaterialActivationResult.value,
      scope: activationIdentity.value.scope,
      applicationBinding: activationIdentity.value.application_binding,
      participantIds: activationIdentity.value.participant_ids,
      registeredPublicKey,
      stateEpoch,
      activeCapabilityBinding,
      runtimePolicyScope,
    },
    variant: coerceVariant(payload.variant),
    theme: coerceTheme(payload.theme),
  };
}

export function parsePasskeyMpcExportRequestPayload(
  value: unknown,
): ExportPrivateKeysWithUiWorkerPayload | null {
  const payload = asRecord(value);
  if (!payload) return null;
  if (payload.artifactKind === ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1) {
    return parseEd25519YaoExportWorkerPayload(payload);
  }
  const target = parseExportWorkerTarget(payload);
  const artifactKind = normalizeOptionalNonEmptyString(payload.artifactKind);
  if (!target) return null;
  const variant = coerceVariant(payload.variant);
  const theme = coerceTheme(payload.theme);
  const parsedWalletId = parseWalletId(payload.walletId);
  if (!parsedWalletId.ok) return null;
  const walletId = String(parsedWalletId.value);
  const credentialIdB64u = normalizeOptionalNonEmptyString(payload.credentialIdB64u);
  if (!credentialIdB64u) return null;
  if (artifactKind === 'ecdsa-derivation-secp256k1-export') {
    const publicKeyHex = normalizeOptionalNonEmptyString(payload.publicKeyHex);
    const privateKeyHex = normalizeOptionalNonEmptyString(payload.privateKeyHex);
    const ethereumAddress = normalizeOptionalNonEmptyString(payload.ethereumAddress);
    if (!publicKeyHex || !privateKeyHex || !ethereumAddress) {
      return null;
    }
    return {
      walletId,
      credentialIdB64u,
      chainTarget: target.chainTarget,
      artifactKind,
      publicKeyHex,
      privateKeyHex,
      ethereumAddress,
      variant,
      theme,
    };
  }
  if (artifactKind) {
    return null;
  }
  return {
    walletId,
    credentialIdB64u,
    chainTarget: target.chainTarget,
    variant,
    theme,
  };
}

function isRouterAbEd25519YaoExportWorkerPayload(
  payload: ExportPrivateKeysWithUiWorkerPayload,
): payload is RouterAbEd25519YaoExportWorkerPayloadV1 {
  return (
    'artifactKind' in payload &&
    payload.artifactKind === ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1
  );
}

function requireEcdsaDerivationThresholdExportPayload(
  payload: ExportPrivateKeysWithUiWorkerPayload,
): EcdsaDerivationThresholdExportWorkerPayload {
  if (
    !('artifactKind' in payload) ||
    payload.artifactKind !== 'ecdsa-derivation-secp256k1-export'
  ) {
    throw new Error('ecdsa-derivation secp256k1 export artifact metadata missing or invalid');
  }
  return payload;
}

function exportSubjectIdForPayload(payload: ExportPrivateKeysWithUiWorkerPayload): string {
  return payload.walletId;
}

function requireExportWalletId(raw: string): string {
  const parsed = parseWalletId(raw);
  if (!parsed.ok) {
    throw new Error('ECDSA export requires wallet identity');
  }
  return String(parsed.value);
}

function localOnlyExportSubjectForTarget(args: {
  exportTarget: ExportWorkerTarget;
  exportSubjectId: string;
}): LocalOnlyExportSubject {
  return {
    kind: 'evm_wallet',
    walletId: requireExportWalletId(args.exportSubjectId),
  };
}

function exportIntentDigestForPayload(args: {
  payload: ExportPrivateKeysWithUiWorkerPayload;
  exportSubjectId: string;
  exportTarget: ExportWorkerTarget;
}): string {
  return `export-keys:${args.exportSubjectId}:${thresholdEcdsaChainTargetKey(args.exportTarget.chainTarget)}:secp256k1`;
}

function requirePrfB64uFromCredential(
  credential: WebAuthnAuthenticationCredential,
  output: 'first' | 'second',
): string {
  const results = asRecord(credential.clientExtensionResults);
  const prf = asRecord(results?.prf);
  const prfResults = asRecord(prf?.results);
  const value = normalizeOptionalTrimmedString(prfResults?.[output]);
  if (!value) {
    throw new Error(
      `Missing PRF.${output} output from credential (requires a PRF-enabled passkey)`,
    );
  }
  return value;
}

async function ensureEvmCryptoWasmReady(): Promise<void> {
  if (evmCryptoWasmInitPromise) return evmCryptoWasmInitPromise;
  evmCryptoWasmInitPromise = (async () => {
    try {
      await initEvmCrypto({ module_or_path: evmCryptoWasmUrl });
      init_evm_crypto();
    } catch (error: unknown) {
      evmCryptoWasmInitPromise = null;
      throw error;
    }
  })();
  return evmCryptoWasmInitPromise;
}

async function deriveSecp256k1FromPrfSecondInWorker(args: {
  prfSecondB64u: string;
  derivationSubjectId: string;
}): Promise<{ privateKeyHex: string; publicKeyHex: string; ethereumAddress: string }> {
  await ensureEvmCryptoWasmReady();
  const prfSecond = base64UrlDecode(args.prfSecondB64u);
  try {
    const out = derive_secp256k1_keypair_from_prf_second(prfSecond, args.derivationSubjectId);
    if (out.length !== 85) {
      throw new Error(
        `derive_secp256k1_keypair_from_prf_second must return 85 bytes (got ${out.length})`,
      );
    }
    const privateKey32 = out.slice(0, 32);
    const publicKey33 = out.slice(32, 65);
    const ethereumAddress20 = out.slice(65, 85);
    return {
      privateKeyHex: bytesToHex(privateKey32),
      publicKeyHex: bytesToHex(publicKey33),
      ethereumAddress: bytesToHex(ethereumAddress20),
    };
  } finally {
    prfSecond.fill(0);
  }
}

function freshExportNonce32(): Uint8Array {
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  return nonce;
}

function ed25519ExportCredentialMatches(
  credential: WebAuthnAuthenticationCredential,
  credentialIdB64u: string,
): boolean {
  return credential.id === credentialIdB64u || credential.rawId === credentialIdB64u;
}

function clearEd25519ExportDisplayEntries(entries: Ed25519ExportPrivateKeyDisplayEntry[]): void {
  for (const entry of entries) entry.privateKey = '';
}

function ignoreExportViewerError(): undefined {
  return undefined;
}

function assertExactEd25519ExportWorkerBinding(
  payload: RouterAbEd25519YaoExportWorkerPayloadV1,
): void {
  const capability = payload.capability;
  const application = capability.applicationBinding;
  const scope = capability.scope;
  const scopeMaterialActivation = routerAbMpcMaterialActivationRefFromWire(
    scope.material_activation,
  );
  if (
    application.wallet_id !== payload.walletId ||
    application.near_ed25519_signing_key_id !== payload.exactLane.nearEd25519SigningKeyId ||
    application.key_creation_signer_slot !== payload.exactLane.signerSlot ||
    scope.account_id !== payload.walletId ||
    !mpcMaterialActivationRefsEqual(capability.materialActivation, payload.exactLane.materialActivation) ||
    !mpcMaterialActivationRefsEqual(scopeMaterialActivation, payload.exactLane.materialActivation)
  ) {
    throw new Error('Ed25519 Yao export capability does not match the exact requested lane');
  }
}

async function buildEd25519ExportAuthorizationIdentity(
  payload: RouterAbEd25519YaoExportWorkerPayloadV1,
): Promise<RouterAbEd25519YaoExportAuthorizationIdentityV1> {
  const runtimePolicyBinding = await deriveRouterAbEd25519YaoRuntimePolicyBindingV1(
    payload.capability.runtimePolicyScope,
  );
  return {
    scope: payload.capability.scope,
    application_binding: payload.capability.applicationBinding,
    participant_ids: payload.capability.participantIds,
    registered_public_key: payload.capability.registeredPublicKey,
    state_epoch: payload.capability.stateEpoch,
    runtime_policy_binding: runtimePolicyBinding,
  };
}

async function runEd25519YaoExportWithUi(
  payload: RouterAbEd25519YaoExportWorkerPayloadV1,
): Promise<ExportPrivateKeysWithUiWorkerResult> {
  assertExactEd25519ExportWorkerBinding(payload);
  const publicKey = `ed25519:${base58Encode(Uint8Array.from(payload.capability.registeredPublicKey))}`;
  const subject = { kind: 'near_wallet' as const, nearAccountId: payload.nearAccountId };
  const requestId = toSessionId('export-ed25519-yao');
  const viewerSessionId = payload.viewerSessionId;
  const issuedAtMs = nowMs();
  const expiresAtMs = issuedAtMs + 60_000;
  const nonce = freshExportNonce32();
  const identity = await buildEd25519ExportAuthorizationIdentity(payload);
  const confirmationDigest = await deriveRouterAbEd25519YaoExportConfirmationDigestV1({
    identity,
    nonce: [...nonce],
    issuedAtMs,
    expiresAtMs,
  });
  const intentDigest = `export-keys:${payload.walletId}:near:${payload.nearAccountId}:ed25519:${base64UrlEncode(Uint8Array.from(confirmationDigest))}`;
  const loadingKeys: Ed25519ExportPrivateKeyDisplayEntry[] = [
    {
      scheme: 'ed25519',
      label: 'NEAR Ed25519 private key',
      publicKey,
      privateKey: '',
    },
  ];
  let prfFirst = new Uint8Array(0);
  let artifact: { publicKey: string; privateKey: string } | null = null;
  let exportKeys: Ed25519ExportPrivateKeyDisplayEntry[] = [];
  let loadingViewerOpened = false;
  try {
    const decision = await awaitUserConfirmationV2({
      requestId,
      type: UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
      summary: {
        operation: 'Export Private Key',
        accountId: payload.nearAccountId,
        publicKey,
        warning: 'Confirm to reveal your NEAR Ed25519 private key export.',
      },
      payload: {
        subject,
        credentialIdB64u: payload.exactLane.credentialIdB64u,
        publicKey,
        challengeB64u: base64UrlEncode(Uint8Array.from(confirmationDigest)),
      },
      intentDigest,
    } satisfies UserConfirmRequest);
    if (!decision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: payload.nearAccountId,
        exportedSchemes: [],
        error: decision.error || 'User cancelled Ed25519 export request',
      };
    }
    if (!decision.credential) {
      throw new Error('Ed25519 export confirmation did not return a WebAuthn credential');
    }
    const credential = normalizeAuthenticationCredential(decision.credential);
    if (!ed25519ExportCredentialMatches(credential, payload.exactLane.credentialIdB64u)) {
      throw new Error('Ed25519 export confirmation used a different passkey credential');
    }
    prfFirst = base64UrlDecode(requirePrfB64uFromCredential(credential, 'first'));
    if (prfFirst.length !== 32) {
      throw new Error('Ed25519 export requires a 32-byte PRF.first output');
    }
    const authorizationDigest = await deriveRouterAbEd25519YaoExportAuthorizationDigestV1({
      identity,
      confirmationDigest,
      nonce: [...nonce],
      issuedAtMs,
      expiresAtMs,
      authority: {
        kind: 'passkey',
        credentialIdB64u: payload.exactLane.credentialIdB64u,
      },
    });
    const request = parseRouterAbEd25519YaoExportAdmissionRequestV1({
      ...identity,
      authorization: {
        confirmation_digest: confirmationDigest,
        authorization_digest: authorizationDigest,
        nonce: [...nonce],
        issued_at_ms: issuedAtMs,
        expires_at_ms: expiresAtMs,
      },
    });
    if (!request.ok) {
      throw new Error(`Invalid Ed25519 export admission: ${request.message}`);
    }

    const loadingDecision = await awaitUserConfirmationV2({
      requestId: `${requestId}-show-loading`,
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: 'Export Private Key',
        accountId: payload.nearAccountId,
        publicKey,
        warning: 'Preparing your NEAR Ed25519 private key export.',
      },
      payload: {
        subject,
        viewerSessionId,
        publicKey,
        keys: loadingKeys,
        variant: payload.variant,
        theme: payload.theme,
        loading: true,
      },
      intentDigest,
    } satisfies UserConfirmRequest);
    if (!loadingDecision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: payload.nearAccountId,
        exportedSchemes: [],
        error: loadingDecision.error || 'User cancelled Ed25519 export viewer',
      };
    }
    loadingViewerOpened = true;

    const client = await RouterAbEd25519YaoClientV1.initializeBundled();
    const result = await client.exportSeed({
      request: request.value,
      custodyEnvelope: {
        factorSecret: prfFirst,
        ...custodyEnvelopeInputForExport(payload.walletCustodyEnvelope),
      },
      authorization: { kind: 'passkey', webauthnAuthentication: credential },
      transport: new RouterAbEd25519YaoHttpActivationTransportV1({
        routerOrigin: new URL(payload.relayerUrl).origin,
        authorization: `Bearer ${payload.authorization.walletSessionToken}`,
        fetch: globalThis.fetch.bind(globalThis),
      }),
    });
    prfFirst = new Uint8Array(0);
    if (!result.ok) throw new Error(result.message);
    artifact = result.artifact;
    if (artifact.publicKey !== publicKey) {
      throw new Error('Exported Ed25519 seed does not match the active registered public key');
    }
    exportKeys = [
      {
        scheme: 'ed25519',
        label: 'NEAR Ed25519 private key',
        publicKey: artifact.publicKey,
        privateKey: artifact.privateKey,
      },
    ];
    const showDecision = await awaitUserConfirmationV2({
      requestId: `${requestId}-show-ready`,
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: 'Export Private Key',
        accountId: payload.nearAccountId,
        publicKey: artifact.publicKey,
        warning: 'Anyone with your private key can fully control your account. Never share it.',
      },
      payload: {
        subject,
        viewerSessionId,
        publicKey: artifact.publicKey,
        privateKey: artifact.privateKey,
        keys: exportKeys,
        variant: payload.variant,
        theme: payload.theme,
        loading: false,
      },
      intentDigest,
    } satisfies UserConfirmRequest);
    clearEd25519ExportDisplayEntries(exportKeys);
    if (!showDecision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: payload.nearAccountId,
        exportedSchemes: [],
        error: showDecision.error || 'User cancelled Ed25519 export viewer',
      };
    }
    return { ok: true, accountId: payload.nearAccountId, exportedSchemes: ['ed25519'] };
  } catch (error: unknown) {
    if (loadingViewerOpened) {
      const message = messageFromError(error, 'Failed to prepare Ed25519 export');
      await awaitUserConfirmationV2({
        requestId: `${requestId}-show-error`,
        type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
        summary: {
          operation: 'Export Private Key',
          accountId: payload.nearAccountId,
          publicKey,
          warning: 'Private key export failed.',
        },
        payload: {
          subject,
          viewerSessionId,
          publicKey,
          keys: loadingKeys,
          variant: payload.variant,
          theme: payload.theme,
          loading: false,
          errorMessage: message,
        },
        intentDigest,
      } satisfies UserConfirmRequest).catch(ignoreExportViewerError);
    }
    if (isCancellationLikeError(error)) {
      return {
        ok: false,
        cancelled: true,
        accountId: payload.nearAccountId,
        exportedSchemes: [],
        error: messageFromError(error, 'User cancelled Ed25519 export request'),
      };
    }
    throw error;
  } finally {
    prfFirst.fill(0);
    nonce.fill(0);
    clearEd25519ExportDisplayEntries(exportKeys);
    if (artifact) {
      artifact.privateKey = '';
    }
  }
}

export async function runPasskeyMpcExportWithUi(
  payload: ExportPrivateKeysWithUiWorkerPayload,
): Promise<ExportPrivateKeysWithUiWorkerResult> {
  if (isRouterAbEd25519YaoExportWorkerPayload(payload)) {
    return await runEd25519YaoExportWithUi(payload);
  }
  // Worker-owned export flow boundary:
  // only this runtime initiates export confirmations via awaitUserConfirmationV2.
  const exportTarget = {
    kind: 'ecdsa' as const,
    scheme: 'secp256k1' as const,
    chainTarget: payload.chainTarget,
  };
  const exportSubjectId = exportSubjectIdForPayload(payload);
  const exportScheme = exportTarget.scheme;
  const ecdsaDerivationExportPayload =
    'artifactKind' in payload && payload.artifactKind === 'ecdsa-derivation-secp256k1-export'
      ? requireEcdsaDerivationThresholdExportPayload(payload)
      : null;
  const exportOperation = 'Export Private Key';
  const exportPublicKey = ecdsaDerivationExportPayload?.publicKeyHex || '';
  const loadingKeys: Secp256k1ExportPrivateKeyDisplayEntry[] = exportPublicKey
    ? [
        {
          scheme: exportScheme,
          label: labelForExportTarget(exportTarget),
          publicKey: exportPublicKey,
          privateKey: '',
        },
      ]
    : [];
  const requestId = toSessionId('export-keys');
  const viewerSessionId = `${requestId}-viewer`;
  const intentDigest = exportIntentDigestForPayload({
    payload,
    exportSubjectId,
    exportTarget,
  });
  const localOnlySubject = localOnlyExportSubjectForTarget({
    exportTarget,
    exportSubjectId,
  });

  let prfSecondB64u = '';
  const exportKeys: Secp256k1ExportPrivateKeyDisplayEntry[] = [];
  let loadingViewerOpened = false;
  try {
    const decision = await awaitUserConfirmationV2({
      requestId,
      type: UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
      summary: {
        operation: exportOperation,
        accountId: exportSubjectId,
        publicKey: exportPublicKey || '(threshold export key)',
        warning: ecdsaDerivationExportPayload
          ? 'Confirm to reveal your EVM private key export.'
          : 'Authenticate with your passkey to prepare export keys.',
      },
      payload: {
        subject: localOnlySubject,
        credentialIdB64u: payload.credentialIdB64u,
        publicKey: exportPublicKey,
      },
      intentDigest,
    } satisfies UserConfirmRequest);

    if (!decision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: exportSubjectId,
        exportedSchemes: [],
        error: decision.error || 'User cancelled export request',
      };
    }
    const credential = decision.credential
      ? normalizeAuthenticationCredential(decision.credential)
      : undefined;
    if (!ecdsaDerivationExportPayload) {
      if (!credential) {
        throw new Error('Export confirmation did not return a WebAuthn authentication credential');
      }
      prfSecondB64u = requirePrfB64uFromCredential(credential, 'second');
    }

    const loadingDecision = await awaitUserConfirmationV2({
      requestId: `${requestId}-show-loading`,
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: exportOperation,
        accountId: exportSubjectId,
        publicKey: exportPublicKey || '(threshold export key)',
        warning: 'Preparing your private key export.',
      },
      payload: {
        subject: localOnlySubject,
        viewerSessionId,
        publicKey: exportPublicKey,
        keys: loadingKeys,
        variant: payload.variant,
        theme: payload.theme,
        loading: true,
      },
      intentDigest,
    } satisfies UserConfirmRequest);

    if (!loadingDecision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: exportSubjectId,
        exportedSchemes: [],
        error: loadingDecision.error || 'User cancelled export viewer',
      };
    }
    loadingViewerOpened = true;

    if (ecdsaDerivationExportPayload) {
      exportKeys.push({
        scheme: 'secp256k1',
        label: secp256k1LabelForExportTarget(exportTarget.chainTarget),
        publicKey: ecdsaDerivationExportPayload.publicKeyHex,
        privateKey: ecdsaDerivationExportPayload.privateKeyHex,
        address: ecdsaDerivationExportPayload.ethereumAddress,
      });
    }

    if (!ecdsaDerivationExportPayload) {
      const derived = await deriveSecp256k1FromPrfSecondInWorker({
        prfSecondB64u,
        derivationSubjectId: exportSubjectId,
      });
      exportKeys.push({
        scheme: 'secp256k1',
        label: secp256k1LabelForExportTarget(exportTarget.chainTarget),
        publicKey: derived.publicKeyHex,
        privateKey: derived.privateKeyHex,
        address: derived.ethereumAddress,
      });
    }

    if (!exportKeys.length) {
      throw new Error('No exportable keys were produced');
    }

    const first = exportKeys[0]!;
    const showDecision = await awaitUserConfirmationV2({
      requestId: `${requestId}-show-ready`,
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: exportOperation,
        accountId: exportSubjectId,
        publicKey: first.publicKey,
        warning: 'Anyone with your private key can fully control your account. Never share it.',
      },
      payload: {
        subject: localOnlySubject,
        viewerSessionId,
        publicKey: first.publicKey,
        privateKey: first.privateKey,
        keys: exportKeys,
        variant: payload.variant,
        theme: payload.theme,
        loading: false,
      },
      intentDigest,
    } satisfies UserConfirmRequest);

    if (!showDecision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: exportSubjectId,
        exportedSchemes: [],
        error: showDecision.error || 'User cancelled export viewer',
      };
    }

    return {
      ok: true,
      accountId: exportSubjectId,
      exportedSchemes: exportKeys.map((entry) => entry.scheme),
    };
  } catch (error: unknown) {
    if (isCancellationLikeError(error)) {
      return {
        ok: false,
        cancelled: true,
        accountId: exportSubjectId,
        exportedSchemes: [],
        error:
          error instanceof Error ? error.message : String(error || 'User cancelled export request'),
      };
    }
    if (loadingViewerOpened) {
      const message = messageFromError(error, 'Failed to prepare export keys');
      await awaitUserConfirmationV2({
        requestId: `${requestId}-show-error`,
        type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
        summary: {
          operation: exportOperation,
          accountId: exportSubjectId,
          publicKey: exportPublicKey || '(threshold export key)',
          warning: 'Private key export failed.',
        },
        payload: {
          subject: localOnlySubject,
          viewerSessionId,
          publicKey: exportPublicKey,
          keys: loadingKeys,
          variant: payload.variant,
          theme: payload.theme,
          loading: false,
          errorMessage: message,
        },
        intentDigest,
      } satisfies UserConfirmRequest).catch(() => undefined);
    }
    throw error;
  } finally {
    prfSecondB64u = '';
    for (const key of exportKeys) {
      key.privateKey = '';
    }
    exportKeys.length = 0;
  }
}
