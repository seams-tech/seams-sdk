import { expect, test } from '@playwright/test';
import {
  parseAppSessionVersion,
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseEmailOtpRegistrationAttemptId,
  parseOrgId,
  parseProviderSubject,
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  parseThresholdSessionId,
  parseWalletId,
  parseWalletSigningSessionId,
} from '../../shared/src/utils/domainIds';
import { walletIdFromString } from '../../shared/src/utils/registrationIntent';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const parsers = [
  { name: 'walletId', parse: parseWalletId },
  { name: 'providerSubject', parse: parseProviderSubject },
  { name: 'challengeSubjectId', parse: parseChallengeSubjectId },
  { name: 'emailOtpChallengeId', parse: parseEmailOtpChallengeId },
  { name: 'emailOtpRegistrationAttemptId', parse: parseEmailOtpRegistrationAttemptId },
  { name: 'orgId', parse: parseOrgId },
  { name: 'appSessionVersion', parse: parseAppSessionVersion },
  { name: 'walletSigningSessionId', parse: parseWalletSigningSessionId },
  { name: 'thresholdEd25519SessionId', parse: parseThresholdEd25519SessionId },
  { name: 'thresholdEcdsaSessionId', parse: parseThresholdEcdsaSessionId },
  { name: 'thresholdSessionId', parse: parseThresholdSessionId },
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
    expect(() => toWalletId(42)).toThrow('walletId must be a string');
  });
});
