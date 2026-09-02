import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { expect, test } from '@playwright/test';
import type {
  RouterAbEd25519YaoCeremonyBindingV1,
  RouterAbEd25519YaoCeremonyIdentityV1,
  RouterAbEd25519YaoInputPairBindingV1,
  RouterAbEd25519YaoOperationV1,
  RouterAbEd25519YaoPrimitiveRequestKindV1,
  RouterAbEd25519YaoWorkKindV1,
} from '@shared/utils/routerAbEd25519Yao';

type PairDigestVectorCase = {
  caseId: string;
  pairBinding: RouterAbEd25519YaoInputPairBindingV1;
};

type PairDigestVectorFixture = {
  version: string;
  cases: readonly PairDigestVectorCase[];
};

const FIXTURE_PATH = fileURLToPath(
  new URL(
    '../../crates/router-ab-core/fixtures/protocol/ed25519-yao/pair-digest-vectors-v1.json',
    import.meta.url,
  ),
);
const BACKEND_PATH = fileURLToPath(
  new URL(
    '../../packages/wallet-server/src/router/domains/ed25519Yao/registration/routerAbEd25519YaoHttpRegistrationBackend.ts',
    import.meta.url,
  ),
);

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} is required`);
  return value;
}

function requireBytes32(value: unknown, label: string): readonly number[] {
  const record = requireRecord(value, label);
  const bytes = record.bytes;
  if (!Array.isArray(bytes) || bytes.length !== 32) {
    throw new Error(`${label}.bytes must contain exactly 32 bytes`);
  }
  for (const [index, byte] of bytes.entries()) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`${label}.bytes[${index}] must be a byte`);
    }
  }
  if (bytes.every((byte) => byte === 0)) throw new Error(`${label}.bytes must be nonzero`);
  return bytes;
}

function requireRawBytes32(value: unknown, label: string): readonly number[] {
  if (!Array.isArray(value) || value.length !== 32) {
    throw new Error(`${label} must contain exactly 32 bytes`);
  }
  for (const [index, byte] of value.entries()) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`${label}[${index}] must be a byte`);
    }
  }
  if (value.every((byte) => byte === 0)) throw new Error(`${label} must be nonzero`);
  return value;
}

function parseOperation(value: unknown, label: string): RouterAbEd25519YaoOperationV1 {
  switch (value) {
    case 'registration':
    case 'recovery':
    case 'refresh':
    case 'export':
      return value;
    default:
      throw new Error(`${label} is invalid`);
  }
}

function parseWorkKind(value: unknown, label: string): RouterAbEd25519YaoWorkKindV1 {
  switch (value) {
    case 'registration_prepare':
    case 'key_export':
    case 'recovery':
    case 'server_share_refresh':
      return value;
    default:
      throw new Error(`${label} is invalid`);
  }
}

function parsePrimitiveRequestKind(
  value: unknown,
  label: string,
): RouterAbEd25519YaoPrimitiveRequestKindV1 {
  switch (value) {
    case 'registration':
    case 'recovery':
    case 'export':
    case 'refresh':
      return value;
    default:
      throw new Error(`${label} is invalid`);
  }
}

function parseCeremonyIdentity(value: unknown): RouterAbEd25519YaoCeremonyIdentityV1 {
  const identity = requireRecord(value, 'pair_binding.ceremony');
  const binding = requireRecord(identity.binding, 'pair_binding.ceremony.binding');
  const lifecycle = requireRecord(binding.lifecycle, 'pair_binding.ceremony.binding.lifecycle');
  const operation = parseOperation(binding.operation, 'pair_binding.ceremony.binding.operation');
  const workKind = parseWorkKind(lifecycle.work_kind, 'pair_binding.ceremony.binding.work_kind');
  const primitiveRequestKind = parsePrimitiveRequestKind(
    lifecycle.primitive_request_kind,
    'pair_binding.ceremony.binding.primitive_request_kind',
  );
  if (
    (operation === 'registration' &&
      (workKind !== 'registration_prepare' || primitiveRequestKind !== 'registration')) ||
    (operation === 'recovery' &&
      (workKind !== 'recovery' || primitiveRequestKind !== 'recovery')) ||
    (operation === 'refresh' &&
      (workKind !== 'server_share_refresh' || primitiveRequestKind !== 'refresh')) ||
    (operation === 'export' && (workKind !== 'key_export' || primitiveRequestKind !== 'export'))
  ) {
    throw new Error('pair-binding operation does not match its lifecycle');
  }
  const circuit = requireString(identity.circuit, 'pair_binding.ceremony.circuit');
  const expectedCircuit: 'activation_v1' | 'export_v1' =
    operation === 'export' ? 'export_v1' : 'activation_v1';
  if (circuit !== expectedCircuit || identity.protocol !== 'v1') {
    throw new Error('pair-binding ceremony identity is inconsistent');
  }
  const ceremonyBinding: RouterAbEd25519YaoCeremonyBindingV1 = {
    lifecycle: {
      lifecycle_id: requireString(lifecycle.lifecycle_id, 'lifecycle_id'),
      work_kind: workKind,
      primitive_request_kind: primitiveRequestKind,
      root_share_epoch: requireString(lifecycle.root_share_epoch, 'root_share_epoch'),
      account_id: requireString(lifecycle.account_id, 'account_id'),
      session_id: requireString(lifecycle.session_id, 'session_id'),
      signer_set_id: requireString(lifecycle.signer_set_id, 'signer_set_id'),
      selected_server_id: requireString(lifecycle.selected_server_id, 'selected_server_id'),
    },
    operation,
    session_id: requireRawBytes32(binding.session_id, 'pair_binding.ceremony.binding.session_id'),
    stable_key_context_binding: requireRawBytes32(
      binding.stable_key_context_binding,
      'pair_binding.ceremony.binding.stable_key_context_binding',
    ),
  };
  return { binding: ceremonyBinding, circuit: expectedCircuit, protocol: 'v1' };
}

function parsePairBinding(value: unknown): RouterAbEd25519YaoInputPairBindingV1 {
  const record = requireRecord(value, 'pair_binding');
  const pairBinding = {
    ceremony: parseCeremonyIdentity(record.ceremony),
    deriver_a_input_digest: {
      bytes: requireBytes32(record.deriver_a_input_digest, 'pair_binding.deriver_a_input_digest'),
    },
    deriver_b_input_digest: {
      bytes: requireBytes32(record.deriver_b_input_digest, 'pair_binding.deriver_b_input_digest'),
    },
    recipient_set_digest: {
      bytes: requireBytes32(record.recipient_set_digest, 'pair_binding.recipient_set_digest'),
    },
    authorization_digest: {
      bytes: requireBytes32(record.authorization_digest, 'pair_binding.authorization_digest'),
    },
    pair_digest: { bytes: requireBytes32(record.pair_digest, 'pair_binding.pair_digest') },
  };
  return pairBinding;
}

function parseFixture(value: unknown): PairDigestVectorFixture {
  const record = requireRecord(value, 'pair-digest fixture');
  if (record.version !== 'router_ab_core_ed25519_yao_pair_digest_vectors_v1') {
    throw new Error('pair-digest fixture version is unsupported');
  }
  if (!Array.isArray(record.cases) || record.cases.length === 0) {
    throw new Error('pair-digest fixture cases are required');
  }
  const cases = record.cases.map((value, index) => {
    const vector = requireRecord(value, `pair-digest fixture case ${index}`);
    return {
      caseId: requireString(vector.case_id, `pair-digest fixture case ${index}.case_id`),
      pairBinding: parsePairBinding(vector.pair_binding),
    };
  });
  return { version: record.version, cases };
}

function hex(value: readonly number[]): string {
  return value.map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

test('Rust-generated pair-digest vectors retain the complete Router binding', async () => {
  const fixture = parseFixture(JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')));
  expect(fixture.cases.map((vector) => vector.caseId)).toEqual(['registration_v1', 'export_v1']);

  for (const vector of fixture.cases) {
    const pairBinding = vector.pairBinding;
    expect(hex(pairBinding.pair_digest.bytes), vector.caseId).toMatch(/^[0-9a-f]{64}$/);
    expect(hex(pairBinding.recipient_set_digest.bytes), vector.caseId).toMatch(/^[0-9a-f]{64}$/);
    expect(hex(pairBinding.authorization_digest.bytes), vector.caseId).toMatch(/^[0-9a-f]{64}$/);
  }
});

test('Gateway adapter does not reimplement Router-owned digest preimages', () => {
  const source = readFileSync(BACKEND_PATH, 'utf8');
  expect(source).not.toContain('router-ab-ed25519-yao/input-pair/v1');
  expect(source).not.toContain('router-ab-ed25519-yao/authorization/v1');
  expect(source).not.toContain('recipient_set_digest');
  expect(source).not.toContain('pair_binding');
});
