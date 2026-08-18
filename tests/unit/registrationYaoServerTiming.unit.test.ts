import { expect, test } from '@playwright/test';
import { parseYaoServerTimingBuckets } from '../../packages/wallet/src/SeamsWeb/operations/registration/registration';

test('parses the Router Yao Server-Timing breakdown into timing buckets', () => {
  const header = [
    'yao_credential_digest;dur=1.5',
    'yao_request_digest;dur=2',
    'yao_d1_claim;dur=120',
    'yao_router_execution;dur=1800',
    'yao_result_reconstruction;dur=8',
    'yao_d1_terminal_commit;dur=95',
    'yao_router_prepare_pair;dur=210',
    'yao_router_verify_readiness;dur=60',
    'yao_router_role_execution;dur=1400',
    'yao_router_signing_worker_delivery;dur=130',
  ].join(', ');

  expect(parseYaoServerTimingBuckets(header)).toEqual([
    ['yaoServerCredentialDigestMs', 1.5],
    ['yaoServerRequestDigestMs', 2],
    ['yaoServerD1ClaimMs', 120],
    ['yaoServerRouterExecutionMs', 1800],
    ['yaoServerResultReconstructionMs', 8],
    ['yaoServerD1TerminalCommitMs', 95],
    ['yaoServerRouterPreparePairMs', 210],
    ['yaoServerRouterVerifyReadinessMs', 60],
    ['yaoServerRouterRoleExecutionMs', 1400],
    ['yaoServerRouterSigningWorkerDeliveryMs', 130],
  ]);
});

test('Server-Timing parsing is absent-tolerant and never throws', () => {
  // A missing Access-Control-Expose-Headers on the Router yields null here.
  expect(parseYaoServerTimingBuckets(null)).toEqual([]);
  expect(parseYaoServerTimingBuckets(undefined)).toEqual([]);
  expect(parseYaoServerTimingBuckets('')).toEqual([]);
  // Unknown metrics (e.g. a Router-side rename) are ignored, not fatal.
  expect(parseYaoServerTimingBuckets('cf-cache;desc="HIT", yao_unknown_metric;dur=5')).toEqual([]);
  // Malformed durations are skipped rather than recorded as NaN.
  expect(parseYaoServerTimingBuckets('yao_d1_claim;dur=abc')).toEqual([]);
  expect(parseYaoServerTimingBuckets('yao_d1_claim;dur=-4')).toEqual([]);
  expect(parseYaoServerTimingBuckets('yao_d1_claim')).toEqual([]);
});

test('recognised metrics survive alongside unrelated Server-Timing entries', () => {
  const header = 'cfRequestDuration;dur=42.1, yao_router_execution;dur=1750, cfL4;desc="?"';
  expect(parseYaoServerTimingBuckets(header)).toEqual([['yaoServerRouterExecutionMs', 1750]]);
});
