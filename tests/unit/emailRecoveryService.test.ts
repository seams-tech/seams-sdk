import { test, expect } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const IMPORT_PATHS = {
  server: '/sdk/esm/server/email-recovery/index.js',
} as const;

const REPO_ROOT = process.env.W3A_REPO_ROOT || process.cwd();

const GMAIL_RESET_EMAIL_BLOB = readFileSync(
  path.join(REPO_ROOT, 'tests/unit/emails/gmail_reset_full.eml'),
  'utf8',
);
const RECOVERY_PAYLOAD = {
  version: 'recovery_email_payload_v1' as const,
  nearAccountId: 'kerp30.w3a-v1.testnet',
  recoverySessionId: '123abc',
  newNearPublicKey: 'ed25519:86mqiBdv45gM4c5uLmvT3TU4g7DAg6KLpuabBSFweigm',
  newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
  deadlineEpochSeconds: 1_893_456_000,
};

test.describe('EmailRecoveryService.verifyEncryptedEmailAndRecover', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await injectImportMap(page);
  });

  test('returns a friendly error when the target account does not exist', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths, emailBlob, recoveryPayload }) => {
        try {
          const { EmailRecoveryService } = await import(paths.server);

          const createMockDeps = () => {
            const nearClient = {
              async view(_params: any): Promise<any> {
                const bytes = new Uint8Array(32);
                for (let i = 0; i < 32; i++) bytes[i] = i + 1;
                let bin = '';
                for (const b of bytes) bin += String.fromCharCode(b);
                return btoa(bin);
              },
              async sendTransaction(_signedTx: any): Promise<any> {
                throw {
                  kind: 'AccountDoesNotExist',
                  short: 'ActionError: AccountDoesNotExist',
                  message: 'Send Transaction failed at action 0 (ActionError: AccountDoesNotExist)',
                };
              },
            };

            return {
              relayerAccount: 'w3a-relayer.testnet',
              relayerPrivateKey: 'ed25519:dummy',
              networkId: 'testnet',
              emailDkimVerifierContract: 'email-dkim-verifier-v1.testnet',
              nearClient,
              ensureSignerAndRelayerAccount: async () => {},
              queueTransaction: async <T>(fn: () => Promise<T>, _label: string): Promise<T> => fn(),
              fetchTxContext: async () => ({ nextNonce: '1', blockHash: 'block-hash' }),
              signWithPrivateKey: async (input: any) => {
                return {
                  transaction: { dummy: true },
                  signature: {},
                  borsh_bytes: [],
                  actions: input.actions,
                };
              },
              getRelayerPublicKey: () => 'relayer-public-key',
            };
          };

          const deps = createMockDeps();
          const service = new EmailRecoveryService(deps);

          const result = await service.verifyEncryptedEmailAndRecover({
            accountId: 'kerp30.w3a-v1.testnet',
            emailBlob,
            recoveryPayload: recoveryPayload,
          });

          return { success: true, result };
        } catch (error: any) {
          return {
            success: false,
            error: error?.message || String(error),
          };
        }
      },
      { paths: IMPORT_PATHS, emailBlob: GMAIL_RESET_EMAIL_BLOB, recoveryPayload: RECOVERY_PAYLOAD },
    );

    if (!res.success) {
      console.error('EmailRecoveryService AccountDoesNotExist test error:', res.error);
      expect(res.success).toBe(true);
      return;
    }

    const { result } = res as { result: any };
    expect(result.success).toBe(false);
    expect(result.error).toBe('Account "kerp30.w3a-v1.testnet" does not exist');
    expect(result.message).toBe('Account "kerp30.w3a-v1.testnet" does not exist');
  });

  test('successfully builds and sends encrypted email verification tx', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths, emailBlob, recoveryPayload }) => {
        try {
          const { EmailRecoveryService } = await import(paths.server);

          const createMockDeps = (calls: any[], signedArgsRef: { current: any }) => {
            const nearClient = {
              async view(params: any): Promise<any> {
                calls.push({ type: 'view', params });
                const bytes = new Uint8Array(32);
                for (let i = 0; i < 32; i++) bytes[i] = i + 1;
                let bin = '';
                for (const b of bytes) bin += String.fromCharCode(b);
                return btoa(bin);
              },
              async sendTransaction(signedTx: any): Promise<any> {
                calls.push({ type: 'send', signedTx });
                // Parse contract args for inspection
                const firstAction = signedTx.actions?.[0];
                const parsedArgs = firstAction?.args ? JSON.parse(firstAction.args) : null;
                calls.push({ type: 'parsedArgs', parsedArgs });
                return {
                  transaction: { hash: 'test-tx-hash' },
                  status: { SuccessValue: '' },
                  receipts_outcome: [],
                };
              },
            };

            return {
              relayerAccount: 'w3a-relayer.testnet',
              relayerPrivateKey: 'ed25519:dummy',
              networkId: 'testnet',
              emailDkimVerifierContract: 'email-dkim-verifier-v1.testnet',
              nearClient,
              ensureSignerAndRelayerAccount: async () => {},
              queueTransaction: async <T>(fn: () => Promise<T>, _label: string): Promise<T> => fn(),
              fetchTxContext: async () => ({ nextNonce: '1', blockHash: 'block-hash' }),
              signWithPrivateKey: async (input: any) => {
                signedArgsRef.current = input;
                return {
                  transaction: { dummy: true },
                  signature: {},
                  borsh_bytes: [],
                  actions: input.actions,
                };
              },
              getRelayerPublicKey: () => 'relayer-public-key',
            };
          };

          const calls: any[] = [];
          const signedArgsRef = { current: null };
          const deps = createMockDeps(calls, signedArgsRef);

          const service = new EmailRecoveryService(deps);

          const result = await service.verifyEncryptedEmailAndRecover({
            accountId: 'kerp30.w3a-v1.testnet',
            emailBlob,
            recoveryPayload,
          });

          return {
            success: true,
            result,
            calls,
            signedArgs: signedArgsRef.current,
          };
        } catch (error: any) {
          return {
            success: false,
            error: error?.message || String(error),
          };
        }
      },
      { paths: IMPORT_PATHS, emailBlob: GMAIL_RESET_EMAIL_BLOB, recoveryPayload: RECOVERY_PAYLOAD },
    );

    if (!res.success) {
      console.error('EmailRecoveryService test error:', res.error);
      expect(res.success).toBe(true);
      return;
    }

    const { result, calls, signedArgs } = res as {
      result: any;
      calls: any[];
      signedArgs: any;
    };

    expect(result.success).toBe(true);
    expect(result.transactionHash).toBe('test-tx-hash');

    const viewCall = calls.find((c: any) => c.type === 'view');
    expect(viewCall).toBeTruthy();
    expect(viewCall.params.account).toBe('email-dkim-verifier-v1.testnet');
    expect(viewCall.params.method).toBe('get_outlayer_encryption_public_key');

    expect(signedArgs).toBeTruthy();
    expect(signedArgs.signerAccountId).toBe('w3a-relayer.testnet');
    // Encrypted path now calls the per-account EmailRecoverer contract.
    expect(signedArgs.receiverId).toBe('kerp30.w3a-v1.testnet');
    expect(Array.isArray(signedArgs.actions)).toBe(true);
    expect(signedArgs.actions.length).toBe(1);

    const action = signedArgs.actions[0];
    expect(action.action_type).toBe('FunctionCall');
    expect(action.method_name).toBe('verify_encrypted_email_and_recover');

    const parsedArgs = JSON.parse(action.args);
    expect(parsedArgs.encrypted_email_blob).toBeTruthy();
    expect(parsedArgs.encrypted_email_blob.version).toBe(1);
    expect(typeof parsedArgs.encrypted_email_blob.ephemeral_pub).toBe('string');
    expect(typeof parsedArgs.encrypted_email_blob.nonce).toBe('string');
    expect(typeof parsedArgs.encrypted_email_blob.ciphertext).toBe('string');
    // AEAD context should be forwarded to EmailRecoverer and then to EmailDKIMVerifier
    // and must include account_id, network_id, payer_account_id.
    expect(parsedArgs.aead_context).toBeTruthy();
    expect(parsedArgs.aead_context.account_id).toBe('kerp30.w3a-v1.testnet');
    expect(parsedArgs.aead_context.network_id).toBe('testnet');
    expect(parsedArgs.aead_context.payer_account_id).toBe('w3a-relayer.testnet');

    // New contract args: expected hashed email + expected new public key
    expect(Array.isArray(parsedArgs.expected_hashed_email)).toBe(true);
    expect(parsedArgs.expected_hashed_email.length).toBe(32);
    expect(typeof parsedArgs.expected_new_public_key).toBe('string');
    expect(parsedArgs.expected_new_public_key.length).toBeGreaterThan(0);
    expect(parsedArgs.request_id).toBe('123abc');
  });
});

test.describe('EmailRecoveryService.requestEmailRecovery', () => {
  test('routes to verify_encrypted_email_and_recover via EmailRecoverer', async ({ page }) => {
    await page.goto('/');
    await injectImportMap(page);
    const res = await page.evaluate(
      async ({ paths, emailBlob, recoveryPayload }) => {
        try {
          const { EmailRecoveryService } = await import(paths.server);

          const createMockDeps = (calls: any[], signedArgsRef: { current: any }) => {
            const nearClient = {
              async view(params: any): Promise<any> {
                calls.push({ type: 'view', params });
                const bytes = new Uint8Array(32);
                for (let i = 0; i < 32; i++) bytes[i] = i + 1;
                let bin = '';
                for (const b of bytes) bin += String.fromCharCode(b);
                return btoa(bin);
              },
              async sendTransaction(signedTx: any): Promise<any> {
                calls.push({ type: 'send', signedTx });
                return {
                  transaction: { hash: 'request-email-recovery-tx-hash' },
                  status: { SuccessValue: '' },
                  receipts_outcome: [],
                };
              },
            };

            return {
              relayerAccount: 'w3a-relayer.testnet',
              relayerPrivateKey: 'ed25519:dummy',
              networkId: 'testnet',
              emailDkimVerifierContract: 'email-dkim-verifier-v1.testnet',
              nearClient,
              ensureSignerAndRelayerAccount: async () => {},
              queueTransaction: async <T>(fn: () => Promise<T>, _label: string): Promise<T> => fn(),
              fetchTxContext: async () => ({ nextNonce: '1', blockHash: 'block-hash' }),
              signWithPrivateKey: async (input: any) => {
                signedArgsRef.current = input;
                return {
                  transaction: { dummy: true },
                  signature: {},
                  borsh_bytes: [],
                  actions: input.actions,
                };
              },
              getRelayerPublicKey: () => 'relayer-public-key',
            };
          };

          const calls: any[] = [];
          const signedArgsRef = { current: null };
          const deps = createMockDeps(calls, signedArgsRef);

          const service = new EmailRecoveryService(deps);

          const result = await service.requestEmailRecovery({
            accountId: 'kerp30.w3a-v1.testnet',
            emailBlob,
            recoveryPayload,
          });

          return {
            success: true,
            result,
            calls,
            signedArgs: signedArgsRef.current,
          };
        } catch (error: any) {
          return {
            success: false,
            error: error?.message || String(error),
          };
        }
      },
      { paths: IMPORT_PATHS, emailBlob: GMAIL_RESET_EMAIL_BLOB, recoveryPayload: RECOVERY_PAYLOAD },
    );

    if (!res.success) {
      console.error('EmailRecoveryService requestEmailRecovery test error:', res.error);
      expect(res.success).toBe(true);
      return;
    }

    const { result, signedArgs } = res as {
      result: any;
      calls: any[];
      signedArgs: any;
    };

    expect(result.success).toBe(true);
    expect(result.transactionHash).toBe('request-email-recovery-tx-hash');

    expect(signedArgs).toBeTruthy();
    expect(signedArgs.signerAccountId).toBe('w3a-relayer.testnet');
    expect(signedArgs.receiverId).toBe('kerp30.w3a-v1.testnet');
    expect(Array.isArray(signedArgs.actions)).toBe(true);
    expect(signedArgs.actions.length).toBe(1);

    const action = signedArgs.actions[0];
    expect(action.action_type).toBe('FunctionCall');
    expect(action.method_name).toBe('verify_encrypted_email_and_recover');

    const parsedArgs = JSON.parse(action.args);
    expect(parsedArgs.encrypted_email_blob).toBeTruthy();
    expect(parsedArgs.encrypted_email_blob.version).toBe(1);
    expect(typeof parsedArgs.encrypted_email_blob.ephemeral_pub).toBe('string');
    expect(typeof parsedArgs.encrypted_email_blob.nonce).toBe('string');
    expect(typeof parsedArgs.encrypted_email_blob.ciphertext).toBe('string');

    expect(Array.isArray(parsedArgs.expected_hashed_email)).toBe(true);
    expect(parsedArgs.expected_hashed_email.length).toBe(32);
    expect(typeof parsedArgs.expected_new_public_key).toBe('string');
    expect(parsedArgs.expected_new_public_key.length).toBeGreaterThan(0);
    expect(parsedArgs.request_id).toBe('123abc');
  });
});
