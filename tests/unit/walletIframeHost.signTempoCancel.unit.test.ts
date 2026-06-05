import { expect, test } from '@playwright/test';
import { createWalletIframeHandlers } from '@/web/SeamsWeb/walletIframe/host/wallet-iframe-handlers';
import {
  resolveWalletBoundaryErrorCode,
  resolveWalletBoundaryErrorMessage,
} from '@/web/SeamsWeb/walletIframe/host/canonicalSignerErrorCode';
import type { ChildToParentEnvelope } from '@/web/SeamsWeb/walletIframe/shared/messages';

function makeTempoRequest(requestId: string): any {
  return {
    type: 'PM_SIGN_TEMPO',
    requestId,
    payload: {
      nearAccountId: 'alice.testnet',
      request: {
        chain: 'evm',
        kind: 'eip1559',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {},
      },
      options: {},
    },
  };
}

test.describe('wallet iframe host PM_SIGN_TEMPO cancellation guards', () => {
  test('returns early when request is already cancelled before signing starts', async () => {
    const posts: ChildToParentEnvelope[] = [];
    let signCalls = 0;
    let cancelChecks = 0;

    const handlers = createWalletIframeHandlers({
      getSeamsWeb: () =>
        ({
          tempo: {
            signTempo: async () => {
              signCalls += 1;
              return { chain: 'evm', txHashHex: '0x1', rawTxHex: '0x2' } as any;
            },
          },
        }) as any,
      post: (msg) => posts.push(msg),
      postProgress: () => undefined,
      isCancelled: () => true,
      respondIfCancelled: () => {
        cancelChecks += 1;
        return true;
      },
    });

    await handlers.PM_SIGN_TEMPO!(makeTempoRequest('req-cancelled') as any);

    expect(cancelChecks).toBe(1);
    expect(signCalls).toBe(0);
    expect(posts.length).toBe(0);
  });

  test('forwards shouldAbort probe into signTempo call', async () => {
    const posts: ChildToParentEnvelope[] = [];
    let cancelled = false;
    let signCalls = 0;

    const handlers = createWalletIframeHandlers({
      getSeamsWeb: () =>
        ({
          tempo: {
            signTempo: async (args: any) => {
              signCalls += 1;
              const shouldAbort = args?.options?.shouldAbort;
              expect(typeof shouldAbort).toBe('function');
              expect(shouldAbort()).toBe(false);
              cancelled = true;
              expect(shouldAbort()).toBe(true);
              cancelled = false;
              return { chain: 'evm', txHashHex: '0x1', rawTxHex: '0x2' } as any;
            },
          },
        }) as any,
      post: (msg) => posts.push(msg),
      postProgress: () => undefined,
      isCancelled: () => cancelled,
      respondIfCancelled: () => cancelled,
    });

    await handlers.PM_SIGN_TEMPO!(makeTempoRequest('req-active') as any);

    expect(signCalls).toBe(1);
    expect(posts.some((msg) => msg.type === 'PM_RESULT')).toBe(true);
  });
});

test.describe('wallet iframe host canonical signer error mapping', () => {
  test('maps threshold commit queue overflow to canonical code', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      rawCode: 'commit_queue_overflow',
      message: '[SigningEngine] threshold ECDSA commit queue overflow for alice.testnet (max=8)',
    });
    expect(code).toBe('commit_queue_overflow');
  });

  test('maps threshold commit queue timeout to canonical code', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      rawCode: 'commit_queue_timeout',
      message: '[SigningEngine] threshold ECDSA commit queue timeout for alice.testnet',
    });
    expect(code).toBe('commit_queue_timeout');
  });

  test('maps nonce-conflict raw code to canonical code', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      rawCode: 'nonce_conflict_retryable',
      message:
        '[SigningEngine] EVM nonce conflict (nonce_too_low) on arc-testnet. Refresh nonce context and retry.',
    });
    expect(code).toBe('nonce_conflict_retryable');
  });

  test('maps nonce-conflict message to canonical code', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      message: 'replacement transaction underpriced',
    });
    expect(code).toBe('nonce_conflict_retryable');
  });

  test('maps nonce-lane-blocked raw code to canonical code', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      rawCode: 'nonce_lane_blocked',
      message:
        '[SigningEngine] EVM nonce lane blocked on arc-testnet (nonce=15). Reconcile lane and retry.',
    });
    expect(code).toBe('nonce_lane_blocked');
  });

  test('maps nonce-lane-blocked message to canonical code', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_RECONCILE_TEMPO_NONCE_LANE',
      message: 'nonce lane blocked',
    });
    expect(code).toBe('nonce_lane_blocked');
  });

  test('maps nonce-conflict message for broadcast-report boundary request', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_REPORT_TEMPO_BROADCAST_REJECTED',
      message: 'nonce too low',
    });
    expect(code).toBe('nonce_conflict_retryable');
  });

  test('maps threshold session auth errors to threshold_ecdsa_session_not_ready', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      message: 'relayer threshold session expired',
    });
    expect(code).toBe('threshold_ecdsa_session_not_ready');
  });

  test('maps missing canonical session wording to threshold_ecdsa_session_not_ready', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      message:
        '[SigningEngine] missing canonical threshold ECDSA session for alice.testnet; reconnect threshold session via bootstrapEcdsaSession',
    });
    expect(code).toBe('threshold_ecdsa_session_not_ready');
  });

  test('maps threshold signingSession not_found wording to threshold_ecdsa_session_not_ready', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      message:
        '[chains] threshold signingSession is not_found; reconnect threshold session before signing',
    });
    expect(code).toBe('threshold_ecdsa_session_not_ready');
  });

  test('maps near threshold session failures to threshold_ed25519_session_not_ready', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_AND_SEND_TXS',
      message: 'Missing threshold wrapKeySalt for account: alice.testnet',
    });
    expect(code).toBe('threshold_ed25519_session_not_ready');
  });

  test('maps NEAR RPC timeouts to rpc_request_failed', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_AND_SEND_TXS',
      message: 'RPC request failed: 408 Request Timeout',
    });
    expect(code).toBe('rpc_request_failed');
  });

  test('maps session kind mismatch wording to threshold_session_kind_mismatch', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      message: '[multichain] threshold-ecdsa session kind mismatch; reconnect threshold session',
    });
    expect(code).toBe('threshold_session_kind_mismatch');
  });

  test('maps user-rejected signing wording to cancelled', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      message: 'User rejected signing request',
    });
    expect(code).toBe('cancelled');
  });

  test('maps EIP-1193 user-rejection raw code to cancelled', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      rawCode: 4001,
      message: 'The user rejected the request.',
    });
    expect(code).toBe('cancelled');
  });

  test('normalizes signer boundary threshold_ecdsa_session_not_ready message', async () => {
    const message = resolveWalletBoundaryErrorMessage({
      requestType: 'PM_SIGN_TEMPO',
      code: 'threshold_ecdsa_session_not_ready',
      message: 'relayer threshold session expired',
    });
    expect(message).toContain('Threshold ECDSA signing session is not ready');
    expect(message).toContain('Refresh the signing session');
  });

  test('normalizes signer boundary commit_queue_overflow message', async () => {
    const message = resolveWalletBoundaryErrorMessage({
      requestType: 'PM_SIGN_TEMPO',
      code: 'commit_queue_overflow',
      message: 'internal queue overflow details',
    });
    expect(message).toContain('commit queue is full');
  });

  test('normalizes signer boundary deployment_failed message', async () => {
    const message = resolveWalletBoundaryErrorMessage({
      requestType: 'PM_SIGN_TEMPO',
      code: 'deployment_failed',
      message: 'internal deployment failure details',
    });
    expect(message).toContain('deployment failed');
  });

  test('normalizes signer boundary nonce_conflict_retryable message', async () => {
    const message = resolveWalletBoundaryErrorMessage({
      requestType: 'PM_SIGN_TEMPO',
      code: 'nonce_conflict_retryable',
      message: 'nonce too low',
    });
    expect(message).toContain('Nonce conflict detected');
    expect(message).toContain('retry');
  });

  test('normalizes signer boundary nonce_lane_blocked message', async () => {
    const message = resolveWalletBoundaryErrorMessage({
      requestType: 'PM_SIGN_TEMPO',
      code: 'nonce_lane_blocked',
      message: 'nonce lane blocked',
    });
    expect(message).toContain('Nonce lane is blocked');
    expect(message).toContain('Reconcile');
  });

  test('normalizes signer boundary cancelled message', async () => {
    const message = resolveWalletBoundaryErrorMessage({
      requestType: 'PM_SIGN_TEMPO',
      code: 'cancelled',
      message: 'User rejected signing request',
    });
    expect(message).toContain('Request cancelled');
  });

  test('distinguishes fresh Email OTP, passkey step-up, and policy-blocked errors', async () => {
    expect(
      resolveWalletBoundaryErrorCode({
        requestType: 'PM_SIGN_TEMPO',
        message:
          '[SigningEngine] evm signing requires fresh Email OTP verification with per_operation policy',
      }),
    ).toBe('fresh_email_otp_required');
    expect(
      resolveWalletBoundaryErrorMessage({
        requestType: 'PM_SIGN_TEMPO',
        code: 'fresh_email_otp_required',
      }),
    ).toContain('Fresh Email OTP verification is required');

    expect(
      resolveWalletBoundaryErrorCode({
        requestType: 'PM_SIGN_TEMPO',
        rawCode: 'threshold_ecdsa_session_not_ready',
        message: 'Fresh Email OTP verification required',
      }),
    ).toBe('fresh_email_otp_required');
    expect(
      resolveWalletBoundaryErrorCode({
        requestType: 'PM_SIGN_TXS_WITH_ACTIONS',
        rawCode: 'threshold_ed25519_session_not_ready',
        message: 'Fresh Email OTP verification required',
      }),
    ).toBe('fresh_email_otp_required');
    expect(
      resolveWalletBoundaryErrorCode({
        requestType: 'PM_SIGN_TEMPO',
        rawCode: 'threshold_ecdsa_session_not_ready',
        message: 'Email OTP /session/refresh HTTP 401 unauthorized',
      }),
    ).toBe('fresh_email_otp_required');
    expect(
      resolveWalletBoundaryErrorCode({
        requestType: 'PM_SIGN_TXS_WITH_ACTIONS',
        rawCode: 'threshold_ed25519_session_not_ready',
        message: 'Email OTP /session/refresh HTTP 403 forbidden',
      }),
    ).toBe('fresh_email_otp_required');

    expect(
      resolveWalletBoundaryErrorCode({
        requestType: 'PM_SIGN_TEMPO',
        message:
          '[SigningEngine] threshold-ecdsa key export requires fresh passkey authentication after Email OTP login',
      }),
    ).toBe('passkey_step_up_required');
    expect(
      resolveWalletBoundaryErrorMessage({
        requestType: 'PM_SIGN_TEMPO',
        code: 'stronger_auth_required',
      }),
    ).toContain('Passkey authentication is required');

    expect(
      resolveWalletBoundaryErrorCode({
        requestType: 'PM_SIGN_TEMPO',
        rawCode: 'operation_blocked_by_policy',
        message: 'operation blocked by policy',
      }),
    ).toBe('operation_blocked_by_policy');
    expect(
      resolveWalletBoundaryErrorMessage({
        requestType: 'PM_SIGN_TEMPO',
        code: 'operation_blocked_by_policy',
      }),
    ).toContain('blocked by wallet policy');
  });

  test('does not masquerade unknown signer-boundary errors as session-not-ready', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      rawCode: 'SOME_INTERNAL_RUNTIME_ERROR',
      message: 'unexpected runtime path',
    });
    expect(code).toBe('SOME_INTERNAL_RUNTIME_ERROR');
  });

  test('preserves unknown signer-boundary messages for debugging', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TXS_WITH_ACTIONS',
      message: '[SigningEngine][near] Ed25519 transaction has ambiguous runtime lanes',
      defaultCode: 'HOST_ERROR',
    });
    const message = resolveWalletBoundaryErrorMessage({
      requestType: 'PM_SIGN_TXS_WITH_ACTIONS',
      code,
      message: '[SigningEngine][near] Ed25519 transaction has ambiguous runtime lanes',
    });
    expect(code).toBe('HOST_ERROR');
    expect(message).toContain('ambiguous runtime lanes');
  });

  test('does not collapse NEAR Email OTP wiring and material errors into session-not-ready', async () => {
    const messages = [
      '[SigningEngine] Email OTP step-up runtime is unavailable',
      '[SigningEngine] Email OTP signing did not return a threshold session id',
      'Missing PRF.first output for signing',
      '[SigningEngine][near] Ed25519 transaction has ambiguous runtime lanes',
      '[SigningEngine][near] Ed25519 transaction signing requires an exact selected lane',
      '[SigningEngine][near] available Ed25519 lane identity does not match runtime session record for alice.testnet',
    ];
    for (const message of messages) {
      const code = resolveWalletBoundaryErrorCode({
        requestType: 'PM_SIGN_TXS_WITH_ACTIONS',
        message,
        defaultCode: 'HOST_ERROR',
      });
      expect(code, message).toBe('HOST_ERROR');
      expect(
        resolveWalletBoundaryErrorMessage({
          requestType: 'PM_SIGN_TXS_WITH_ACTIONS',
          code,
          message,
        }),
        message,
      ).toBe(message);
    }
  });

  test('still maps true NEAR threshold session failures to threshold_ed25519_session_not_ready', async () => {
    const messages = [
      '[chains] threshold signingSession auth is unavailable; reconnect threshold session before signing',
      '[SigningEngine][near] signing session is not ready: missing_session',
      '[SigningEngine][near] signing session is not ready: exhausted',
      'Missing threshold wrapKeySalt for account: alice.testnet',
    ];
    for (const message of messages) {
      expect(
        resolveWalletBoundaryErrorCode({
          requestType: 'PM_SIGN_TXS_WITH_ACTIONS',
          message,
        }),
        message,
      ).toBe('threshold_ed25519_session_not_ready');
    }
  });
});
