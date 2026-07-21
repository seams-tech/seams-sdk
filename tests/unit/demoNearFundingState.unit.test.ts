import { expect, test } from '@playwright/test';
import {
  canSignDemoNearDelegate,
  canStartDemoNearTransaction,
  demoNearFundingStatusText,
  resolveDemoNearFundingCheck,
} from '../../apps/seams-site/src/flows/demo/demoNearAccountFundingState';

const NEAR_ACCOUNT_ID = 'frost-vermillion-k7p9m2.testnet';
const NEAR_PUBLIC_KEY = 'ed25519:demo-near-public-key';

test('mixed logged-in wallet keeps a complete NEAR funding-check identity', () => {
  expect(
    resolveDemoNearFundingCheck({
      isLoggedIn: true,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearPublicKey: NEAR_PUBLIC_KEY,
    }),
  ).toEqual({
    kind: 'check',
    nearAccountId: NEAR_ACCOUNT_ID,
    nearPublicKey: NEAR_PUBLIC_KEY,
  });
});

test('logged-in wallet with a missing NEAR public key has visible blocked readiness', () => {
  const resolution = resolveDemoNearFundingCheck({
    isLoggedIn: true,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearPublicKey: null,
  });
  expect(resolution).toEqual({
    kind: 'skip',
    status: {
      kind: 'identity_unavailable',
      missing: 'near_public_key',
      nearAccountId: NEAR_ACCOUNT_ID,
    },
  });
  if (resolution.kind !== 'skip') throw new Error('expected blocked NEAR readiness');
  expect(demoNearFundingStatusText(resolution.status)).toContain('public key is unavailable');
  expect(canStartDemoNearTransaction(resolution.status)).toBe(false);
});

test('transient checking status renders no text so the status slot never jolts the buttons', () => {
  /* A "Checking..." line that mounts and unmounts a beat later shifts the
     buttons below it on every card load — 'checking' must stay silent. */
  expect(
    demoNearFundingStatusText({ kind: 'checking', nearAccountId: NEAR_ACCOUNT_ID }),
  ).toBeNull();
  expect(demoNearFundingStatusText({ kind: 'ready', nearAccountId: NEAR_ACCOUNT_ID })).toBeNull();
  expect(demoNearFundingStatusText({ kind: 'signed_out' })).toBeNull();
});

test('funding readiness controls NEAR transaction and delegate actions independently', () => {
  const funded = { kind: 'ready' as const, nearAccountId: NEAR_ACCOUNT_ID };
  const needsFunding = { kind: 'needs_funding' as const, nearAccountId: NEAR_ACCOUNT_ID };

  expect(canStartDemoNearTransaction(funded)).toBe(true);
  expect(canSignDemoNearDelegate(funded)).toBe(true);
  expect(canStartDemoNearTransaction(needsFunding)).toBe(true);
  expect(canSignDemoNearDelegate(needsFunding)).toBe(false);
});
