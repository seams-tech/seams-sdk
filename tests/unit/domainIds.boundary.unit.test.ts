import { expect, test } from '@playwright/test';
import {
  parseAppSessionVersion,
  parseCapabilityInstanceRef,
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseEmailOtpRegistrationAttemptId,
  parseMpcCapabilityRuntimeRef,
  parseMpcKeyBindingRef,
  parseMpcLifecycleBindingRef,
  parseMpcMaterialActivationId,
  parseMpcMaterialActivationRef,
  parseMpcMaterialOwnerRef,
  parseMpcReauthorizationPolicyRef,
  parseMpcRegisteredPublicKeyBindingRef,
  parseMpcSigningWorkerRef,
  parseOrgId,
  parseProviderSubject,
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  parseThresholdSessionId,
  parseWalletId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseD1BoundaryWalletIdResult } from '../../packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthBoundary';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const parsers = [
  { name: 'walletId', parse: parseWalletId },
  { name: 'providerSubject', parse: parseProviderSubject },
  { name: 'challengeSubjectId', parse: parseChallengeSubjectId },
  { name: 'emailOtpChallengeId', parse: parseEmailOtpChallengeId },
  { name: 'emailOtpRegistrationAttemptId', parse: parseEmailOtpRegistrationAttemptId },
  { name: 'orgId', parse: parseOrgId },
  { name: 'appSessionVersion', parse: parseAppSessionVersion },
  { name: 'thresholdEd25519SessionId', parse: parseThresholdEd25519SessionId },
  { name: 'thresholdEcdsaSessionId', parse: parseThresholdEcdsaSessionId },
  { name: 'thresholdSessionId', parse: parseThresholdSessionId },
  { name: 'capabilityInstanceRef', parse: parseCapabilityInstanceRef },
  { name: 'mpcMaterialOwnerRef', parse: parseMpcMaterialOwnerRef },
  { name: 'mpcCapabilityRuntimeRef', parse: parseMpcCapabilityRuntimeRef },
  { name: 'mpcMaterialActivationId', parse: parseMpcMaterialActivationId },
  { name: 'mpcSigningWorkerRef', parse: parseMpcSigningWorkerRef },
  { name: 'mpcKeyBindingRef', parse: parseMpcKeyBindingRef },
  { name: 'mpcLifecycleBindingRef', parse: parseMpcLifecycleBindingRef },
  { name: 'mpcReauthorizationPolicyRef', parse: parseMpcReauthorizationPolicyRef },
  {
    name: 'mpcRegisteredPublicKeyBindingRef',
    parse: parseMpcRegisteredPublicKeyBindingRef,
  },
] as const;

test.describe('domain id boundary parsers', () => {
  for (const parser of parsers) {
    test(`${parser.name} trims valid strings`, () => {
      expect(parser.parse(`  ${parser.name}:value  `)).toEqual({
        ok: true,
        value: `${parser.name}:value`,
      });
    });

    test(`${parser.name} rejects blank and non-string values`, () => {
      expect(parser.parse('')).toEqual({
        ok: false,
        error: { code: 'missing', message: `${parser.name} is required` },
      });
      expect(parser.parse(42)).toEqual({
        ok: false,
        error: { code: 'invalid', message: `${parser.name} must be a string` },
      });
    });
  }

  test('public wallet-id boundary helpers normalize through the canonical parser', () => {
    expect(walletIdFromString('  wallet.testnet  ')).toBe('wallet.testnet');
    expect(toWalletId('  wallet.testnet  ')).toBe('wallet.testnet');
  });

  test('public wallet-id boundary helpers reject invalid raw values', () => {
    expect(() => walletIdFromString('')).toThrow('walletId is required');
    expect(() => walletIdFromString('alice testnet')).toThrow(
      'walletId must not contain whitespace or control characters',
    );
    expect(() => toWalletId(42)).toThrow('walletId must be a string');
    expect(() => toWalletId('alice\ntestnet')).toThrow(
      'walletId must not contain whitespace or control characters',
    );
  });

  test('wallet-id parser rejects embedded whitespace and control characters', () => {
    expect(parseWalletId('wallet:alice')).toEqual({
      ok: true,
      value: 'wallet:alice',
    });
    expect(parseWalletId('alice testnet')).toEqual({
      ok: false,
      error: {
        code: 'invalid',
        message: 'walletId must not contain whitespace or control characters',
      },
    });
    expect(parseWalletId('alice\u0000testnet')).toEqual({
      ok: false,
      error: {
        code: 'invalid',
        message: 'walletId must not contain whitespace or control characters',
      },
    });
  });

  test('material activation parser accepts only the exact persisted reference shape', () => {
    const raw = {
      kind: 'mpc_material_activation_ref',
      activationId: 'activation:1',
      capability: 'capability:1',
      materialOwner: 'material-owner:1',
      keyBinding: 'key-binding:1',
      lifecycleBinding: 'lifecycle-binding:1',
      signingWorker: 'signing-worker:1',
    };
    const parsed = parseMpcMaterialActivationRef(raw);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) throw new Error(parsed.error.message);
    expect(parsed.value).toMatchObject(raw);
    expect(parseMpcMaterialActivationRef(JSON.parse(JSON.stringify(parsed.value))).ok).toBe(true);

    expect(parseMpcMaterialActivationRef({ ...raw, unexpected: 'field' })).toEqual({
      ok: false,
      error: {
        code: 'invalid',
        message: 'mpcMaterialActivationRef has invalid fields',
      },
    });
    const { signingWorker, ...missingSigningWorker } = raw;
    void signingWorker;
    expect(parseMpcMaterialActivationRef(missingSigningWorker)).toEqual({
      ok: false,
      error: {
        code: 'invalid',
        message: 'mpcMaterialActivationRef has invalid fields',
      },
    });
  });

  test('D1 wallet-id boundary accepts wallet-scoped ids without NEAR account validation', () => {
    expect(parseD1BoundaryWalletIdResult('frost-vermillion-k7p9m2')).toEqual({
      ok: true,
      value: 'frost-vermillion-k7p9m2',
    });
    expect(parseD1BoundaryWalletIdResult('wallet:alice')).toEqual({
      ok: true,
      value: 'wallet:alice',
    });
    expect(parseD1BoundaryWalletIdResult('alice testnet')).toEqual({
      ok: false,
      code: 'invalid',
    });
  });
});
