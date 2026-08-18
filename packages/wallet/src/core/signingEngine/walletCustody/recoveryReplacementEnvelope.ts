import {
  WALLET_CUSTODY_ENVELOPE_VERSION_V2,
  parsePasskeyCustodyEnvelopeRecord,
  rejectUnknownFields,
  requireRecord,
  type PasskeyCustodyEnvelopeRecord,
  type RecoveryReplacementEnvelopePayload,
} from '@shared/passkey-custody';

const RECOVERY_BINDING_FIELDS = [
  'walletId',
  'envelopeId',
  'factor',
  'envelopeRevision',
  'binding',
] as const;

/**
 * Promotes ceremony ciphertext into the exact envelope record finalization
 * accepts. The binding JSON is authoritative because it is what Rust used as
 * AEAD AAD; every loose field is reconstructed from it and parsed once here.
 */
export function buildRecoveredPasskeyCustodyEnvelopeRecord(args: {
  readonly expectedWalletId: string;
  readonly replacement: RecoveryReplacementEnvelopePayload;
  readonly activatedAtMs: number;
}): PasskeyCustodyEnvelopeRecord {
  const binding = parseReplacementBinding(args.replacement.envelopeBindingJson);
  if (binding.walletId !== args.expectedWalletId) {
    throw new Error('recovery replacement envelope changed the wallet identity');
  }
  if (binding.envelopeId !== args.replacement.envelopeId) {
    throw new Error('recovery replacement envelope changed the envelope identity');
  }
  const record = parsePasskeyCustodyEnvelopeRecord(
    {
      kind: WALLET_CUSTODY_ENVELOPE_VERSION_V2,
      envelopeId: binding.envelopeId,
      walletId: binding.walletId,
      binding: binding.binding,
      factor: binding.factor,
      envelopeVersion: WALLET_CUSTODY_ENVELOPE_VERSION_V2,
      envelopeRevision: binding.envelopeRevision,
      nonceB64u: args.replacement.envelopeNonceB64u,
      sealedCustodySecretB64u: args.replacement.sealedCustodySecretB64u,
      ciphertextDigestB64u: args.replacement.envelopeCiphertextDigestB64u,
      aadHashB64u: args.replacement.envelopeAadHashB64u,
      lifecycle: { state: 'active', activatedAtMs: args.activatedAtMs },
      createdAtMs: args.activatedAtMs,
      updatedAtMs: args.activatedAtMs,
    },
    'recoveryReplacementEnvelope',
  );
  if (record.factor.kind !== 'passkey') {
    throw new Error('credential replacement must reseal under a passkey factor');
  }
  if (record.binding.kind !== 'wallet_custody_seed_v1') {
    throw new Error('credential replacement must seal the wallet custody seed');
  }
  return record;
}

function parseReplacementBinding(rawJson: string): Record<string, unknown> {
  let raw: unknown;
  try {
    raw = JSON.parse(rawJson);
  } catch {
    throw new Error('recovery replacement envelope binding is not JSON');
  }
  const binding = requireRecord(raw, 'recoveryReplacementEnvelope.binding');
  rejectUnknownFields(binding, RECOVERY_BINDING_FIELDS, 'recoveryReplacementEnvelope.binding');
  return binding;
}
