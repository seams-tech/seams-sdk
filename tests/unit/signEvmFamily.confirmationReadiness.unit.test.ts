import { expect, test } from '@playwright/test';
import {
  PENDING_CHALLENGE_B64U,
  PENDING_INTENT_DIGEST,
  consumeIntentDigestPreparation,
} from '@/core/signingEngine/stepUpConfirmation/intentDigestPreparation';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '@/core/signingEngine/session/operationState/types';
import {
  signEvmFamilyWithUiConfirm,
  type EvmFamilyUiConfirmFlowConfig,
  type SignEvmFamilyWithUiConfirmArgs,
} from '@/core/signingEngine/flows/signEvmFamily/signingFlow';
import type { ActiveWalletAuthorityEcdsaSigningAuthPlan } from '@/core/signingEngine/session/material/activeWalletAuthorityEcdsaRuntime';
import { parseWalletSessionId } from '@shared/authorization/capabilityKinds';
import { parseWalletAuthMethodId, parseWalletAuthorityId } from '@shared/utils/domainIds';
import type { SigningIntent } from '@/core/signingEngine/interfaces/signing';
import type { TxDisplayModel } from '@/core/signingEngine/interfaces/display';
import type { UiConfirmContext } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';

type TestRequest = {
  senderSignatureAlgorithm: 'secp256k1';
  payload: string;
};

type TestResult = {
  kind: 'signed';
};

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolvePromise: (value: T) => void = () => undefined;
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });
  return { promise, resolve: resolvePromise };
}

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function activeWalletAuthorityPlan(): ActiveWalletAuthorityEcdsaSigningAuthPlan {
  return {
    kind: 'active_wallet_authority',
    method: 'passkey',
    accountId: 'linked-wallet',
    intent: 'transaction_sign',
    curve: 'ecdsa',
    walletSessionId: required(parseWalletSessionId('wallet-session:linked-wallet')),
    authorityId: required(parseWalletAuthorityId('authority:linked-wallet')),
    authMethodId: required(parseWalletAuthMethodId('auth-method:linked-wallet')),
    expiresAtMs: Date.now() + 60_000,
  };
}

function testDisplayModel(): TxDisplayModel {
  return {
    chain: 'evm',
    title: 'Test transaction',
    operations: [
      {
        id: 'test.operation',
        kind: 'raw.fallback',
        label: 'Test operation',
        raw: 'test',
      },
    ],
  };
}

function testIntent(
  workerCtx: WorkerOperationContext,
  request: TestRequest,
  intentGate: Promise<void>,
): Promise<SigningIntent<unknown, TestResult>> {
  void workerCtx;
  void request;
  return intentGate.then(() => ({
    chain: 'evm' as const,
    uiModel: {},
    signRequests: [
      {
        kind: 'digest' as const,
        algorithm: 'secp256k1' as const,
        digest32: new Uint8Array(32).fill(7),
      },
    ],
    finalize: async () => ({ kind: 'signed' as const }),
  }));
}

test('active Wallet Authority EVM confirmation is requested before intent preparation completes', async () => {
  const intentGate = deferred<void>();
  const intentBuildStarted = deferred<void>();
  const confirmationStarted = deferred<Record<string, unknown>>();
  let exactIntentResolved = false;
  let confirmationDisplayed = false;

  const config: EvmFamilyUiConfirmFlowConfig<TestRequest, TestResult> = {
    targetKind: 'evm',
    flowName: 'evm',
    explicitAuthErrorLabel: 'EVM',
    nonceErrorLabel: 'EVM',
    title: 'Test transaction',
    body: '',
    buildIntent: async ({ workerCtx, request }) => {
      intentBuildStarted.resolve(undefined);
      return await testIntent(workerCtx, request, intentGate.promise);
    },
    buildDisplayModel: () => testDisplayModel(),
    requiredSignatureUsesForRequest: () => 1,
    webauthn: { kind: 'not_supported' },
  };

  const touchConfirm = {
    openTransactionPreparationModal: async () => undefined,
    closeTransactionPreparationModal: () => undefined,
    requestUserConfirmation: async () => ({
      requestId: 'unused',
      confirmed: true,
    }),
    orchestrateSigningConfirmation: async (request: Record<string, unknown>) => {
      confirmationStarted.resolve(request);
      expect(request.kind).toBe('intentDigest');
      expect(request.intentDigest).toBe(PENDING_INTENT_DIGEST);
      expect(request.challengeB64u).toBe(PENDING_CHALLENGE_B64U);
      expect(request.signingAuthPlan).toMatchObject({
        kind: 'active_wallet_authority',
        walletSessionId: 'wallet-session:linked-wallet',
        authorityId: 'authority:linked-wallet',
        authMethodId: 'auth-method:linked-wallet',
      });
      expect(request.signingAuthPlan).not.toHaveProperty('session');
      expect(request.signingAuthPlan).not.toHaveProperty('operationCredential');
      expect(request.signingAuthPlan).not.toHaveProperty('runtime');
      expect(request.signingAuthPlan).not.toHaveProperty('thresholdSessionId');
      expect(request.signingAuthPlan).not.toHaveProperty('remainingUses');
      const preparation = consumeIntentDigestPreparation(String(request.sessionId));
      expect(preparation).toBeDefined();
      const prepared = await preparation!;
      exactIntentResolved = true;
      return {
        sessionId: String(request.sessionId),
        intentDigest: prepared.intentDigest,
      };
    },
  } as unknown as SignEvmFamilyWithUiConfirmArgs<TestRequest>['touchConfirm'];

  const input: SignEvmFamilyWithUiConfirmArgs<TestRequest> = {
    ctx: {} as UiConfirmContext,
    touchConfirm,
    walletId: 'linked-wallet',
    request: {
      senderSignatureAlgorithm: 'secp256k1',
      payload: 'test',
    },
    engines: {},
    workerCtx: {} as WorkerOperationContext,
    signingOperation: {
      operationId: SigningSessionIds.signingOperation('linked-operation'),
      operationFingerprint: SigningSessionIds.signingOperationFingerprint(
        'sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      ),
      intent: SigningOperationIntent.TransactionSign,
    },
    thresholdEcdsaStepUp: { kind: 'not_required' },
    authorization: {
      kind: 'active_wallet_authority',
      confirmationAuthPlan: activeWalletAuthorityPlan(),
      sign: async () => new Uint8Array(65).fill(8),
    },
    onConfirmationDisplayed: () => {
      confirmationDisplayed = true;
    },
  };

  const signing = signEvmFamilyWithUiConfirm({ config, input });
  await intentBuildStarted.promise;
  const pendingRequest = await confirmationStarted.promise;

  expect(confirmationDisplayed).toBe(true);
  expect(exactIntentResolved).toBe(false);
  expect(pendingRequest.intentDigest).toBe(PENDING_INTENT_DIGEST);

  intentGate.resolve(undefined);
  await expect(signing).resolves.toEqual({ kind: 'signed' });
  expect(exactIntentResolved).toBe(true);
});
