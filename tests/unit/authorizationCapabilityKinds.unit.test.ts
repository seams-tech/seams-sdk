import { expect, test } from '@playwright/test';
import {
  CAPABILITY_KINDS,
  AUTHORIZATION_EVIDENCE_KINDS,
  buildAuthorizationEvidenceRequirement,
  isAuthorizationEvidenceKind,
  parseCapabilityOperationRef,
} from '@shared/authorization/capabilityKinds';

test('capability operation parsing enforces exact capability ownership', () => {
  expect(
    parseCapabilityOperationRef({
      capabilityKind: CAPABILITY_KINDS.vaultAccess,
      operationKind: 'vault.proxy_use',
    }),
  ).toEqual({
    ok: true,
    value: {
      capabilityKind: 'vault_access',
      operationKind: 'vault.proxy_use',
    },
  });

  expect(
    parseCapabilityOperationRef({
      capabilityKind: CAPABILITY_KINDS.vaultAccess,
      operationKind: 'near.sign_transaction',
    }),
  ).toEqual({
    ok: false,
    error: {
      code: 'invalid',
      message: 'vault capability operation is unsupported',
    },
  });
});

test('authorization evidence requirements are flat, canonical, and current-scope only', () => {
  expect(
    buildAuthorizationEvidenceRequirement({
      mode: 'any',
      evidenceKinds: [
        AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion,
        AUTHORIZATION_EVIDENCE_KINDS.emailOtp,
        AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion,
      ],
    }),
  ).toEqual({
    mode: 'any',
    evidenceKinds: ['email_otp', 'passkey_assertion'],
  });
  expect(isAuthorizationEvidenceKind('mpc_signer_proof')).toBe(false);
});
