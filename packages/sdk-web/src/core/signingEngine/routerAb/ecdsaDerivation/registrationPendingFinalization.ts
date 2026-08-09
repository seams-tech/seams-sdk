import type { EcdsaRoleLocalPendingStateBlob } from '@/core/platform/types';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  assertRouterAbEcdsaRegistrationFactsMatchRequestV1,
  parseRouterAbEcdsaRegistrationRequestFactsV1,
  parseRouterAbEcdsaRegistrationRequestV1,
  parseRouterAbEcdsaVerifiedClientActivationFactsV1,
  type RouterAbEcdsaRegistrationRequestFactsV1,
  type RouterAbEcdsaRegistrationRequestV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';

const PENDING_FINALIZATION_KIND = 'router_ab_ecdsa_registration_pending_finalization_v1';
const WALLET_CUSTODY_PENDING_FINALIZATION_KIND =
  'router_ab_ecdsa_registration_wallet_custody_pending_finalization_v1';

export type LegacyRouterAbEcdsaRegistrationPendingFinalizationV1 = {
  readonly kind: typeof PENDING_FINALIZATION_KIND;
  readonly pendingStateBlob: EcdsaRoleLocalPendingStateBlob;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly registrationFacts: RouterAbEcdsaRegistrationRequestFactsV1;
  readonly registrationRequest: RouterAbEcdsaRegistrationRequestV1;
  readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
};

export type WalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1 = {
  readonly kind: typeof WALLET_CUSTODY_PENDING_FINALIZATION_KIND;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly registrationFacts: RouterAbEcdsaRegistrationRequestFactsV1;
  readonly registrationRequest: RouterAbEcdsaRegistrationRequestV1;
  readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
  readonly pendingStateBlob?: never;
};

export type RouterAbEcdsaRegistrationPendingFinalizationV1 =
  | LegacyRouterAbEcdsaRegistrationPendingFinalizationV1
  | WalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1;

type BuildRouterAbEcdsaRegistrationPendingFinalizationV1Input = Omit<
  LegacyRouterAbEcdsaRegistrationPendingFinalizationV1,
  'kind'
> & {
  readonly kind?: never;
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(
  record: Record<string, unknown>,
  label: string,
  expectedKeys: readonly string[],
): void {
  const actualKeys = Object.keys(record).sort();
  const sortedExpectedKeys = [...expectedKeys].sort();
  if (
    actualKeys.length !== sortedExpectedKeys.length ||
    actualKeys.some((key, index) => key !== sortedExpectedKeys[index])
  ) {
    throw new Error(`${label} has an invalid field set`);
  }
}

function parsePendingStateBlob(value: unknown): EcdsaRoleLocalPendingStateBlob {
  const label = 'Router A/B ECDSA pending finalization state blob';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['kind', 'curve', 'encoding', 'producer', 'stateBlobB64u']);
  if (
    record.kind !== 'ecdsa_role_local_pending_state_blob_v1' ||
    record.curve !== 'secp256k1' ||
    record.encoding !== 'base64url' ||
    record.producer !== 'signer_core'
  ) {
    throw new Error(`${label} has invalid metadata`);
  }
  const stateBlobB64u = requireCanonicalBase64Url(record.stateBlobB64u, `${label}.stateBlobB64u`);
  return {
    kind: 'ecdsa_role_local_pending_state_blob_v1',
    curve: 'secp256k1',
    encoding: 'base64url',
    producer: 'signer_core',
    stateBlobB64u,
  };
}

function requireCanonicalBase64Url(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} must be non-empty unpadded base64url`);
  }
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(value);
  } catch {
    throw new Error(`${label} must be valid base64url`);
  }
  if (bytes.length === 0 || base64UrlEncode(bytes) !== value) {
    throw new Error(`${label} must be canonical base64url`);
  }
  return value;
}

function parsePendingFinalization(value: unknown): RouterAbEcdsaRegistrationPendingFinalizationV1 {
  const label = 'Router A/B ECDSA registration pending finalization';
  const record = requireRecord(value, label);
  if (record.kind === WALLET_CUSTODY_PENDING_FINALIZATION_KIND) {
    requireExactKeys(record, label, [
      'kind',
      'runtimePolicyScope',
      'registrationFacts',
      'registrationRequest',
      'clientActivation',
    ]);
    const registrationFacts = parseRouterAbEcdsaRegistrationRequestFactsV1(
      record.registrationFacts,
    );
    const registrationRequest = parseRouterAbEcdsaRegistrationRequestV1(record.registrationRequest);
    assertRouterAbEcdsaRegistrationFactsMatchRequestV1({
      facts: registrationFacts,
      request: registrationRequest,
    });
    return {
      kind: WALLET_CUSTODY_PENDING_FINALIZATION_KIND,
      runtimePolicyScope: normalizeRuntimePolicyScope(record.runtimePolicyScope),
      registrationFacts,
      registrationRequest,
      clientActivation: parseRouterAbEcdsaVerifiedClientActivationFactsV1(record.clientActivation),
    };
  }
  requireExactKeys(record, label, [
    'kind',
    'pendingStateBlob',
    'runtimePolicyScope',
    'registrationFacts',
    'registrationRequest',
    'clientActivation',
  ]);
  if (record.kind !== PENDING_FINALIZATION_KIND) {
    throw new Error(`${label}.kind is invalid`);
  }
  const registrationFacts = parseRouterAbEcdsaRegistrationRequestFactsV1(record.registrationFacts);
  const registrationRequest = parseRouterAbEcdsaRegistrationRequestV1(record.registrationRequest);
  assertRouterAbEcdsaRegistrationFactsMatchRequestV1({
    facts: registrationFacts,
    request: registrationRequest,
  });
  return {
    kind: PENDING_FINALIZATION_KIND,
    pendingStateBlob: parsePendingStateBlob(record.pendingStateBlob),
    runtimePolicyScope: normalizeRuntimePolicyScope(record.runtimePolicyScope),
    registrationFacts,
    registrationRequest,
    clientActivation: parseRouterAbEcdsaVerifiedClientActivationFactsV1(record.clientActivation),
  };
}

export function buildRouterAbEcdsaRegistrationPendingFinalizationV1(
  input: BuildRouterAbEcdsaRegistrationPendingFinalizationV1Input,
): RouterAbEcdsaRegistrationPendingFinalizationV1 {
  return parsePendingFinalization({
    kind: PENDING_FINALIZATION_KIND,
    pendingStateBlob: input.pendingStateBlob,
    runtimePolicyScope: input.runtimePolicyScope,
    registrationFacts: input.registrationFacts,
    registrationRequest: input.registrationRequest,
    clientActivation: input.clientActivation,
  });
}

export function buildWalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1(
  input: Omit<WalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1, 'kind'>,
): WalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1 {
  const parsed = parsePendingFinalization({
    kind: WALLET_CUSTODY_PENDING_FINALIZATION_KIND,
    runtimePolicyScope: input.runtimePolicyScope,
    registrationFacts: input.registrationFacts,
    registrationRequest: input.registrationRequest,
    clientActivation: input.clientActivation,
  });
  if (parsed.kind !== WALLET_CUSTODY_PENDING_FINALIZATION_KIND) {
    throw new Error('Wallet custody pending finalization parsed as legacy state');
  }
  return parsed;
}

export function encodeRouterAbEcdsaRegistrationPendingFinalizationV1(
  payload: RouterAbEcdsaRegistrationPendingFinalizationV1,
): string {
  const parsed = parsePendingFinalization(payload);
  return base64UrlEncode(new TextEncoder().encode(alphabetizeStringify(parsed)));
}

export function decodeRouterAbEcdsaRegistrationPendingFinalizationV1(
  encoded: unknown,
): RouterAbEcdsaRegistrationPendingFinalizationV1 {
  const canonicalEncoded = requireCanonicalBase64Url(
    encoded,
    'Router A/B ECDSA pending finalization payload',
  );
  let json: string;
  try {
    json = new TextDecoder('utf-8', { fatal: true }).decode(base64UrlDecode(canonicalEncoded));
  } catch {
    throw new Error('Router A/B ECDSA pending finalization payload must be UTF-8');
  }
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    throw new Error('Router A/B ECDSA pending finalization payload must be JSON');
  }
  if (alphabetizeStringify(raw) !== json) {
    throw new Error('Router A/B ECDSA pending finalization payload must be canonical JSON');
  }
  return parsePendingFinalization(raw);
}
