import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDB: '/sdk/esm/core/indexedDB/passkeyClientDB/manager.js',
  deployment: '/sdk/esm/core/signingEngine/flows/signEvmFamily/smartAccountDeploymentState.js',
} as const;

test.describe('smart-account deployment gate helper', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('observe mode stamps deployment check timestamp for undeployed account', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { ensureSmartAccountDeployed } = await import(paths.deployment);
        const now = Date.now();
        const dbm = new PasskeyClientDBManager();
        dbm.setDbName(
          `PasskeyClientDB-smartacct-observe-${now}-${Math.random().toString(16).slice(2)}`,
        );

        await dbm.upsertProfile({
          profileId: 'profile-smartacct-observe',
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-observe', rawId: 'raw-observe' },
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-observe',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-observe',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: '0xabc111',
          accountModel: 'erc4337',
          isPrimary: true,
          deployed: false,
        });

        const gate = await ensureSmartAccountDeployed({
          clientDB: dbm,
          nearAccountId: 'alice.testnet',
          chainTargetCandidates: [
            { kind: 'evm', namespace: 'eip155', chainId: 11155111, networkSlug: 'sepolia' },
          ],
          accountModelCandidates: ['erc4337'],
          enforce: false,
        });
        const rows = await dbm.listChainAccountsByProfileAndChain(
          'profile-smartacct-observe',
          'evm:eip155:11155111',
        );
        const account = rows.find((row: any) => row.accountAddress === '0xabc111') || null;

        return {
          status: gate.status,
          checkedAt: gate.checkedAt,
          deployed: typeof account?.deployed === 'boolean' ? account.deployed : null,
          lastDeploymentCheckAt:
            typeof account?.lastDeploymentCheckAt === 'number'
              ? account.lastDeploymentCheckAt
              : null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.status).toBe('needs_deploy');
    expect(result.checkedAt).toBeGreaterThan(0);
    expect(result.deployed).toBe(false);
    expect(result.lastDeploymentCheckAt).toBeGreaterThan(0);
  });

  test('successful deploy callback marks account deployed and stores tx hash', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { ensureSmartAccountDeployed } = await import(paths.deployment);
        const now = Date.now();
        const dbm = new PasskeyClientDBManager();
        dbm.setDbName(
          `PasskeyClientDB-smartacct-deploy-${now}-${Math.random().toString(16).slice(2)}`,
        );

        await dbm.upsertProfile({
          profileId: 'profile-smartacct-deploy',
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-deploy', rawId: 'raw-deploy' },
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-deploy',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-deploy',
          chainIdKey: 'tempo:42431',
          accountAddress: '0xabc222',
          accountModel: 'tempo-native',
          isPrimary: true,
          deployed: false,
        });

        const gate = await ensureSmartAccountDeployed({
          clientDB: dbm,
          nearAccountId: 'alice.testnet',
          chainTargetCandidates: [
            { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
          ],
          accountModelCandidates: ['tempo-native'],
          enforce: true,
          deploy: async () => ({
            ok: true,
            deploymentTxHash: '0xdeploytxhash',
          }),
        });

        const rows = await dbm.listChainAccountsByProfileAndChain(
          'profile-smartacct-deploy',
          'tempo:42431',
        );
        const account = rows.find((row: any) => row.accountAddress === '0xabc222') || null;

        return {
          status: gate.status,
          deploymentTxHash: gate.deploymentTxHash || null,
          deployed: typeof account?.deployed === 'boolean' ? account.deployed : null,
          accountDeploymentTxHash: account?.deploymentTxHash || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.status).toBe('deployed');
    expect(result.deploymentTxHash).toBe('0xdeploytxhash');
    expect(result.deployed).toBe(true);
    expect(result.accountDeploymentTxHash).toBe('0xdeploytxhash');
  });

  test('successful deploy reports canonical deployment observation when reporter is configured', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { ensureSmartAccountDeployed } = await import(paths.deployment);
        const now = Date.now();
        const dbm = new PasskeyClientDBManager();
        dbm.setDbName(
          `PasskeyClientDB-smartacct-report-${now}-${Math.random().toString(16).slice(2)}`,
        );

        await dbm.upsertProfile({
          profileId: 'profile-smartacct-report',
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-report', rawId: 'raw-report' },
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-report',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-report',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: '0xabc333',
          accountModel: 'erc4337',
          isPrimary: true,
          deployed: false,
        });

        let reported: Record<string, unknown> | null = null;
        const gate = await ensureSmartAccountDeployed({
          clientDB: dbm,
          nearAccountId: 'alice.testnet',
          chainTargetCandidates: [
            { kind: 'evm', namespace: 'eip155', chainId: 11155111, networkSlug: 'sepolia' },
          ],
          accountModelCandidates: ['erc4337'],
          enforce: true,
          deploy: async () => ({
            ok: true,
            deploymentTxHash: '0xreporttxhash',
          }),
          reportDeployed: async (input: Record<string, unknown>) => {
            reported = input;
          },
        });

        return {
          status: gate.status,
          deploymentTxHash: gate.deploymentTxHash || null,
          reported,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.status).toBe('deployed');
    expect(result.deploymentTxHash).toBe('0xreporttxhash');
    expect(result.reported).toBeTruthy();
    expect(result.reported?.['chainTarget']).toEqual({
      kind: 'evm',
      namespace: 'eip155',
      chainId: 11155111,
      networkSlug: 'sepolia',
    });
    expect(result.reported?.['deploymentTxHash']).toBe('0xreporttxhash');
  });

  test('deployment promotes pending undeployed signers into active canonical state', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { ensureSmartAccountDeployed } = await import(paths.deployment);
        const now = Date.now();
        const dbm = new PasskeyClientDBManager();
        dbm.setDbName(
          `PasskeyClientDB-smartacct-promote-${now}-${Math.random().toString(16).slice(2)}`,
        );

        await dbm.upsertProfile({
          profileId: 'profile-smartacct-promote',
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-promote', rawId: 'raw-promote' },
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-promote',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-promote',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: `0x${'44'.repeat(20)}`,
          accountModel: 'erc4337',
          isPrimary: true,
          deployed: false,
        });
        await dbm.upsertAccountSigner({
          profileId: 'profile-smartacct-promote',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: `0x${'44'.repeat(20)}`,
          signerId: `0x${'dd'.repeat(20)}`,
          signerSlot: 2,
          signerType: 'threshold',
          signerKind: 'threshold-ecdsa',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          status: 'pending',
        });

        const before = await dbm.listSignerOperations({
          statuses: ['queued', 'submitted', 'failed', 'confirmed', 'dead-letter'],
          dueBefore: Number.MAX_SAFE_INTEGER,
        });

        const gate = await ensureSmartAccountDeployed({
          clientDB: dbm,
          nearAccountId: 'alice.testnet',
          chainTargetCandidates: [
            { kind: 'evm', namespace: 'eip155', chainId: 11155111, networkSlug: 'sepolia' },
          ],
          accountModelCandidates: ['erc4337'],
          enforce: true,
          deploy: async () => ({
            ok: true,
            deploymentTxHash: `0x${'ef'.repeat(32)}`,
          }),
        });

        const signer = await dbm.getAccountSigner({
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: `0x${'44'.repeat(20)}`,
          signerId: `0x${'dd'.repeat(20)}`,
        });
        const after = await dbm.listSignerOperations({
          statuses: ['queued', 'submitted', 'failed', 'confirmed', 'dead-letter'],
          dueBefore: Number.MAX_SAFE_INTEGER,
        });

        return {
          status: gate.status,
          before,
          signer,
          after,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.status).toBe('deployed');
    expect(result.before).toHaveLength(1);
    expect(result.before[0]?.status).toBe('queued');
    expect(result.signer?.status).toBe('active');
    expect(result.after).toHaveLength(1);
    expect(result.after[0]?.status).toBe('confirmed');
    expect(result.after[0]?.txHash).toBe(`0x${'ef'.repeat(32)}`);
    expect(result.after[0]?.lastError ?? null).toBeNull();
  });

  test('already deployed account skips deploy callback and returns already_deployed', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { ensureSmartAccountDeployed } = await import(paths.deployment);
        const now = Date.now();
        const dbm = new PasskeyClientDBManager();
        dbm.setDbName(
          `PasskeyClientDB-smartacct-already-${now}-${Math.random().toString(16).slice(2)}`,
        );

        await dbm.upsertProfile({
          profileId: 'profile-smartacct-already',
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-already', rawId: 'raw-already' },
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-already',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-already',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: '0xabc333',
          accountModel: 'erc4337',
          isPrimary: true,
          deployed: true,
          deploymentTxHash: '0xexistinghash',
        });

        let deployCalls = 0;
        const gate = await ensureSmartAccountDeployed({
          clientDB: dbm,
          nearAccountId: 'alice.testnet',
          chainTargetCandidates: [
            { kind: 'evm', namespace: 'eip155', chainId: 11155111, networkSlug: 'sepolia' },
          ],
          accountModelCandidates: ['erc4337'],
          enforce: true,
          deploy: async () => {
            deployCalls += 1;
            return { ok: true, deploymentTxHash: '0xshould-not-run' };
          },
        });

        return {
          status: gate.status,
          deploymentTxHash: gate.deploymentTxHash || null,
          attempts: gate.attempts,
          deployCalls,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.status).toBe('already_deployed');
    expect(result.deploymentTxHash).toBe('0xexistinghash');
    expect(result.attempts).toBe(0);
    expect(result.deployCalls).toBe(0);
  });

  test('transient deploy failure retries and succeeds in enforce mode', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { ensureSmartAccountDeployed } = await import(paths.deployment);
        const now = Date.now();
        const dbm = new PasskeyClientDBManager();
        dbm.setDbName(
          `PasskeyClientDB-smartacct-retry-${now}-${Math.random().toString(16).slice(2)}`,
        );

        await dbm.upsertProfile({
          profileId: 'profile-smartacct-retry',
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-retry', rawId: 'raw-retry' },
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-retry',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-retry',
          chainIdKey: 'tempo:42431',
          accountAddress: '0xabc444',
          accountModel: 'tempo-native',
          isPrimary: true,
          deployed: false,
        });

        let attempts = 0;
        const gate = await ensureSmartAccountDeployed({
          clientDB: dbm,
          nearAccountId: 'alice.testnet',
          chainTargetCandidates: [
            { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
          ],
          accountModelCandidates: ['tempo-native'],
          enforce: true,
          maxDeployAttempts: 2,
          deploy: async () => {
            attempts += 1;
            if (attempts === 1) {
              return { ok: false, code: 'timeout', message: 'gateway timeout' };
            }
            return { ok: true, deploymentTxHash: '0xretryhash' };
          },
        });

        return {
          status: gate.status,
          deploymentTxHash: gate.deploymentTxHash || null,
          attempts: gate.attempts,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.status).toBe('deployed');
    expect(result.deploymentTxHash).toBe('0xretryhash');
    expect(result.attempts).toBe(2);
  });

  test('enforce mode surfaces clear failure message after max deploy attempts', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { ensureSmartAccountDeployed } = await import(paths.deployment);
        const now = Date.now();
        const dbm = new PasskeyClientDBManager();
        dbm.setDbName(
          `PasskeyClientDB-smartacct-fail-${now}-${Math.random().toString(16).slice(2)}`,
        );

        await dbm.upsertProfile({
          profileId: 'profile-smartacct-fail',
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-fail', rawId: 'raw-fail' },
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-fail',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-fail',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: '0xabc555',
          accountModel: 'erc4337',
          isPrimary: true,
          deployed: false,
        });

        try {
          await ensureSmartAccountDeployed({
            clientDB: dbm,
            nearAccountId: 'alice.testnet',
            chainTargetCandidates: [
              { kind: 'evm', namespace: 'eip155', chainId: 11155111, networkSlug: 'sepolia' },
            ],
            accountModelCandidates: ['erc4337'],
            enforce: true,
            maxDeployAttempts: 3,
            deploy: async () => ({
              ok: false,
              code: 'request_failed',
              message: 'temporary network issue',
            }),
          });
          return { threw: false, message: '' };
        } catch (error: any) {
          return { threw: true, message: String(error?.message || error || '') };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.threw).toBe(true);
    expect(result.message).toContain('after 3/3 attempts');
    expect(result.message).toContain('request_failed');
  });

  test('concurrent same deployment identity dedupes to one deploy attempt', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { ensureSmartAccountDeployed } = await import(paths.deployment);
        const now = Date.now();
        const dbm = new PasskeyClientDBManager();
        dbm.setDbName(
          `PasskeyClientDB-smartacct-dedupe-${now}-${Math.random().toString(16).slice(2)}`,
        );

        await dbm.upsertProfile({
          profileId: 'profile-smartacct-dedupe',
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-dedupe', rawId: 'raw-dedupe' },
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-dedupe',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-dedupe',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: '0xdedupe111',
          accountModel: 'erc4337',
          isPrimary: true,
          deployed: false,
        });

        let deployCalls = 0;
        let releaseFirstDeploy: (() => void) | null = null;
        let firstDeployStartedResolve: (() => void) | null = null;
        const firstDeployStarted = new Promise<void>((resolve) => {
          firstDeployStartedResolve = resolve;
        });
        const firstDeployGate = new Promise<void>((resolve) => {
          releaseFirstDeploy = resolve;
        });

        const deploy = async () => {
          deployCalls += 1;
          if (deployCalls === 1) {
            firstDeployStartedResolve?.();
            await firstDeployGate;
          }
          return { ok: true, deploymentTxHash: '0xdedupehash' };
        };

        const p1 = ensureSmartAccountDeployed({
          clientDB: dbm,
          nearAccountId: 'alice.testnet',
          chainTargetCandidates: [
            { kind: 'evm', namespace: 'eip155', chainId: 11155111, networkSlug: 'sepolia' },
          ],
          accountModelCandidates: ['erc4337'],
          enforce: true,
          deploy,
        });
        await firstDeployStarted;
        const p2 = ensureSmartAccountDeployed({
          clientDB: dbm,
          nearAccountId: 'alice.testnet',
          chainTargetCandidates: [
            { kind: 'evm', namespace: 'eip155', chainId: 11155111, networkSlug: 'sepolia' },
          ],
          accountModelCandidates: ['erc4337'],
          enforce: true,
          deploy,
        });
        const releaseFirstDeployFn = releaseFirstDeploy as unknown as (() => void) | null;
        if (releaseFirstDeployFn) releaseFirstDeployFn();

        const [r1, r2] = await Promise.all([p1, p2]);
        const rows = await dbm.listChainAccountsByProfileAndChain(
          'profile-smartacct-dedupe',
          'evm:eip155:11155111',
        );
        const account = rows.find((row: any) => row.accountAddress === '0xdedupe111') || null;

        return {
          deployCalls,
          firstStatus: r1.status,
          secondStatus: r2.status,
          firstAttempts: r1.attempts,
          secondAttempts: r2.attempts,
          accountDeployed: !!account?.deployed,
          accountDeploymentTxHash: account?.deploymentTxHash || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.deployCalls).toBe(1);
    expect(result.firstStatus).toBe('deployed');
    expect(result.firstAttempts).toBe(1);
    expect(result.secondStatus).toBe('already_deployed');
    expect(result.secondAttempts).toBe(0);
    expect(result.accountDeployed).toBe(true);
    expect(result.accountDeploymentTxHash).toBe('0xdedupehash');
  });

  test('concurrent different deployment identities are not blocked by dedupe lock', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { ensureSmartAccountDeployed } = await import(paths.deployment);
        const now = Date.now();
        const dbm = new PasskeyClientDBManager();
        dbm.setDbName(
          `PasskeyClientDB-smartacct-dedupe-keys-${now}-${Math.random().toString(16).slice(2)}`,
        );

        await dbm.upsertProfile({
          profileId: 'profile-smartacct-dedupe-keys',
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-dedupe-keys', rawId: 'raw-dedupe-keys' },
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-dedupe-keys',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-dedupe-keys',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: '0xaaa111',
          accountModel: 'erc4337',
          isPrimary: true,
          deployed: false,
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-dedupe-keys',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: '0xbbb222',
          accountModel: 'erc4337',
          isPrimary: false,
          deployed: false,
        });

        let deployCalls = 0;
        const deployAddresses: string[] = [];
        let releaseFirstDeploy: (() => void) | null = null;
        let firstDeployStartedResolve: (() => void) | null = null;
        let secondDeployStartedResolve: (() => void) | null = null;
        const firstDeployStarted = new Promise<void>((resolve) => {
          firstDeployStartedResolve = resolve;
        });
        const secondDeployStarted = new Promise<void>((resolve) => {
          secondDeployStartedResolve = resolve;
        });
        const firstDeployGate = new Promise<void>((resolve) => {
          releaseFirstDeploy = resolve;
        });

        const deploy = async (input: any) => {
          deployCalls += 1;
          const accountAddress = String(input?.account?.accountAddress || '');
          deployAddresses.push(accountAddress);
          if (accountAddress === '0xaaa111') {
            firstDeployStartedResolve?.();
            await firstDeployGate;
            return { ok: true, deploymentTxHash: '0xhash-aaa' };
          }
          if (accountAddress === '0xbbb222') {
            secondDeployStartedResolve?.();
            return { ok: true, deploymentTxHash: '0xhash-bbb' };
          }
          return { ok: true, deploymentTxHash: '0xhash-unknown' };
        };

        const p1 = ensureSmartAccountDeployed({
          clientDB: dbm,
          nearAccountId: 'alice.testnet',
          chainTargetCandidates: [
            { kind: 'evm', namespace: 'eip155', chainId: 11155111, networkSlug: 'sepolia' },
          ],
          accountModelCandidates: ['erc4337'],
          enforce: true,
          deploy,
        });
        await firstDeployStarted;

        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-dedupe-keys',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: '0xaaa111',
          accountModel: 'erc4337',
          isPrimary: false,
          deployed: false,
        });
        await dbm.upsertChainAccount({
          profileId: 'profile-smartacct-dedupe-keys',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: '0xbbb222',
          accountModel: 'erc4337',
          isPrimary: true,
          deployed: false,
        });

        const p2 = ensureSmartAccountDeployed({
          clientDB: dbm,
          nearAccountId: 'alice.testnet',
          chainTargetCandidates: [
            { kind: 'evm', namespace: 'eip155', chainId: 11155111, networkSlug: 'sepolia' },
          ],
          accountModelCandidates: ['erc4337'],
          enforce: true,
          deploy,
        });

        const secondStartedBeforeRelease = await Promise.race<boolean>([
          secondDeployStarted.then(() => true),
          new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 1200)),
        ]);

        const releaseFirstDeployFn = releaseFirstDeploy as unknown as (() => void) | null;
        if (releaseFirstDeployFn) releaseFirstDeployFn();
        const [r1, r2] = await Promise.all([p1, p2]);

        return {
          deployCalls,
          deployAddresses,
          secondStartedBeforeRelease,
          firstStatus: r1.status,
          secondStatus: r2.status,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.secondStartedBeforeRelease).toBe(true);
    expect(result.deployCalls).toBe(2);
    expect(result.deployAddresses).toContain('0xaaa111');
    expect(result.deployAddresses).toContain('0xbbb222');
    expect(result.firstStatus).toBe('deployed');
    expect(result.secondStatus).toBe('deployed');
  });
});
