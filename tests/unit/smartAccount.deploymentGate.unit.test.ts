import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDB: '/sdk/esm/core/indexedDB/passkeyClientDB/manager.js',
  deployment: '/sdk/esm/core/signingEngine/orchestration/ensureSmartAccountDeployed.js',
} as const;

test.describe('smart-account deployment gate helper', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('observe mode stamps deployment check timestamp for undeployed account', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDB);
      const { ensureSmartAccountDeployed } = await import(paths.deployment);
      const now = Date.now();
      const dbm = new PasskeyClientDBManager();
      dbm.setDbName(`PasskeyClientDB-smartacct-observe-${now}-${Math.random().toString(16).slice(2)}`);

      await dbm.upsertProfile({
        profileId: 'profile-smartacct-observe',
        defaultDeviceNumber: 1,
        passkeyCredential: { id: 'cred-observe', rawId: 'raw-observe' },
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-observe',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-observe',
        chainId: 'eip155:11155111',
        accountAddress: '0xabc111',
        accountModel: 'erc4337',
        isPrimary: true,
        deployed: false,
      });

      const gate = await ensureSmartAccountDeployed({
        clientDB: dbm,
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        chainIdCandidates: ['eip155:11155111', 'eip155:unknown'],
        accountModelCandidates: ['erc4337'],
        enforce: false,
      });
      const rows = await dbm.listChainAccountsByProfileAndChain(
        'profile-smartacct-observe',
        'eip155:11155111',
      );
      const account = rows.find((row: any) => row.accountAddress === '0xabc111') || null;

      return {
        status: gate.status,
        checkedAt: gate.checkedAt,
        deployed: typeof account?.deployed === 'boolean' ? account.deployed : null,
        lastDeploymentCheckAt:
          typeof account?.lastDeploymentCheckAt === 'number' ? account.lastDeploymentCheckAt : null,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.status).toBe('needs_deploy');
    expect(result.checkedAt).toBeGreaterThan(0);
    expect(result.deployed).toBe(false);
    expect(result.lastDeploymentCheckAt).toBeGreaterThan(0);
  });

  test('successful deploy callback marks account deployed and stores tx hash', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDB);
      const { ensureSmartAccountDeployed } = await import(paths.deployment);
      const now = Date.now();
      const dbm = new PasskeyClientDBManager();
      dbm.setDbName(`PasskeyClientDB-smartacct-deploy-${now}-${Math.random().toString(16).slice(2)}`);

      await dbm.upsertProfile({
        profileId: 'profile-smartacct-deploy',
        defaultDeviceNumber: 1,
        passkeyCredential: { id: 'cred-deploy', rawId: 'raw-deploy' },
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-deploy',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-deploy',
        chainId: 'tempo:42431',
        accountAddress: '0xabc222',
        accountModel: 'tempo-native',
        isPrimary: true,
        deployed: false,
      });

      const gate = await ensureSmartAccountDeployed({
        clientDB: dbm,
        nearAccountId: 'alice.testnet',
        chain: 'tempo',
        chainIdCandidates: ['tempo:42431', 'tempo:unknown'],
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
    }, { paths: IMPORT_PATHS });

    expect(result.status).toBe('deployed');
    expect(result.deploymentTxHash).toBe('0xdeploytxhash');
    expect(result.deployed).toBe(true);
    expect(result.accountDeploymentTxHash).toBe('0xdeploytxhash');
  });

  test('already deployed account skips deploy callback and returns already_deployed', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDB);
      const { ensureSmartAccountDeployed } = await import(paths.deployment);
      const now = Date.now();
      const dbm = new PasskeyClientDBManager();
      dbm.setDbName(
        `PasskeyClientDB-smartacct-already-${now}-${Math.random().toString(16).slice(2)}`,
      );

      await dbm.upsertProfile({
        profileId: 'profile-smartacct-already',
        defaultDeviceNumber: 1,
        passkeyCredential: { id: 'cred-already', rawId: 'raw-already' },
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-already',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-already',
        chainId: 'eip155:11155111',
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
        chain: 'evm',
        chainIdCandidates: ['eip155:11155111'],
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
    }, { paths: IMPORT_PATHS });

    expect(result.status).toBe('already_deployed');
    expect(result.deploymentTxHash).toBe('0xexistinghash');
    expect(result.attempts).toBe(0);
    expect(result.deployCalls).toBe(0);
  });

  test('enforce mode auto-heals missing evm row from tempo bootstrap metadata', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDB);
      const { ensureSmartAccountDeployed } = await import(paths.deployment);
      const now = Date.now();
      const dbm = new PasskeyClientDBManager();
      dbm.setDbName(`PasskeyClientDB-smartacct-autofill-${now}-${Math.random().toString(16).slice(2)}`);

      await dbm.upsertProfile({
        profileId: 'profile-smartacct-autofill',
        defaultDeviceNumber: 1,
        passkeyCredential: { id: 'cred-autofill', rawId: 'raw-autofill' },
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-autofill',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-autofill',
        chainId: 'tempo:42431',
        accountAddress: '0xabc666',
        accountModel: 'tempo-native',
        isPrimary: true,
        counterfactualAddress: '0xabc666',
        factory: '0xfac7ory',
        entryPoint: '0xentry',
        salt: '0xsalt',
        deployed: false,
      });

      let deployInput: any = null;
      const gate = await ensureSmartAccountDeployed({
        clientDB: dbm,
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        chainIdCandidates: ['eip155:11155111', 'eip155:unknown'],
        accountModelCandidates: ['erc4337'],
        enforce: true,
        deploy: async (input: any) => {
          deployInput = {
            chain: input.chain,
            chainId: input.chainId,
            accountModel: input.account.accountModel,
            accountAddress: input.account.accountAddress,
          };
          return { ok: true, deploymentTxHash: '0xautofilltx' };
        },
      });

      const rows = await dbm.listChainAccountsByProfileAndChain(
        'profile-smartacct-autofill',
        'eip155:unknown',
      );
      const account = rows.find((row: any) => row.accountAddress === '0xabc666') || null;

      return {
        status: gate.status,
        deploymentTxHash: gate.deploymentTxHash || null,
        deployInput,
        accountExists: !!account,
        accountModel: account?.accountModel || null,
        accountDeployed: typeof account?.deployed === 'boolean' ? account.deployed : null,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.status).toBe('deployed');
    expect(result.deploymentTxHash).toBe('0xautofilltx');
    expect(result.deployInput?.chain).toBe('evm');
    expect(result.deployInput?.chainId).toBe('eip155:unknown');
    expect(result.deployInput?.accountModel).toBe('erc4337');
    expect(result.accountExists).toBe(true);
    expect(result.accountModel).toBe('erc4337');
    expect(result.accountDeployed).toBe(true);
  });

  test('transient deploy failure retries and succeeds in enforce mode', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDB);
      const { ensureSmartAccountDeployed } = await import(paths.deployment);
      const now = Date.now();
      const dbm = new PasskeyClientDBManager();
      dbm.setDbName(`PasskeyClientDB-smartacct-retry-${now}-${Math.random().toString(16).slice(2)}`);

      await dbm.upsertProfile({
        profileId: 'profile-smartacct-retry',
        defaultDeviceNumber: 1,
        passkeyCredential: { id: 'cred-retry', rawId: 'raw-retry' },
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-retry',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-retry',
        chainId: 'tempo:42431',
        accountAddress: '0xabc444',
        accountModel: 'tempo-native',
        isPrimary: true,
        deployed: false,
      });

      let attempts = 0;
      const gate = await ensureSmartAccountDeployed({
        clientDB: dbm,
        nearAccountId: 'alice.testnet',
        chain: 'tempo',
        chainIdCandidates: ['tempo:42431'],
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
    }, { paths: IMPORT_PATHS });

    expect(result.status).toBe('deployed');
    expect(result.deploymentTxHash).toBe('0xretryhash');
    expect(result.attempts).toBe(2);
  });

  test('enforce mode surfaces clear failure message after max deploy attempts', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDB);
      const { ensureSmartAccountDeployed } = await import(paths.deployment);
      const now = Date.now();
      const dbm = new PasskeyClientDBManager();
      dbm.setDbName(
        `PasskeyClientDB-smartacct-fail-${now}-${Math.random().toString(16).slice(2)}`,
      );

      await dbm.upsertProfile({
        profileId: 'profile-smartacct-fail',
        defaultDeviceNumber: 1,
        passkeyCredential: { id: 'cred-fail', rawId: 'raw-fail' },
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-fail',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-fail',
        chainId: 'eip155:11155111',
        accountAddress: '0xabc555',
        accountModel: 'erc4337',
        isPrimary: true,
        deployed: false,
      });

      try {
        await ensureSmartAccountDeployed({
          clientDB: dbm,
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          chainIdCandidates: ['eip155:11155111'],
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
    }, { paths: IMPORT_PATHS });

    expect(result.threw).toBe(true);
    expect(result.message).toContain('after 3/3 attempts');
    expect(result.message).toContain('request_failed');
  });

  test('concurrent same deployment identity dedupes to one deploy attempt', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDB);
      const { ensureSmartAccountDeployed } = await import(paths.deployment);
      const now = Date.now();
      const dbm = new PasskeyClientDBManager();
      dbm.setDbName(`PasskeyClientDB-smartacct-dedupe-${now}-${Math.random().toString(16).slice(2)}`);

      await dbm.upsertProfile({
        profileId: 'profile-smartacct-dedupe',
        defaultDeviceNumber: 1,
        passkeyCredential: { id: 'cred-dedupe', rawId: 'raw-dedupe' },
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-dedupe',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-dedupe',
        chainId: 'eip155:11155111',
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
        chain: 'evm',
        chainIdCandidates: ['eip155:11155111'],
        accountModelCandidates: ['erc4337'],
        enforce: true,
        deploy,
      });
      await firstDeployStarted;
      const p2 = ensureSmartAccountDeployed({
        clientDB: dbm,
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        chainIdCandidates: ['eip155:11155111'],
        accountModelCandidates: ['erc4337'],
        enforce: true,
        deploy,
      });
      const releaseFirstDeployFn = releaseFirstDeploy as unknown as (() => void) | null;
      if (releaseFirstDeployFn) releaseFirstDeployFn();

      const [r1, r2] = await Promise.all([p1, p2]);
      const rows = await dbm.listChainAccountsByProfileAndChain(
        'profile-smartacct-dedupe',
        'eip155:11155111',
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
    }, { paths: IMPORT_PATHS });

    expect(result.deployCalls).toBe(1);
    expect(result.firstStatus).toBe('deployed');
    expect(result.firstAttempts).toBe(1);
    expect(result.secondStatus).toBe('already_deployed');
    expect(result.secondAttempts).toBe(0);
    expect(result.accountDeployed).toBe(true);
    expect(result.accountDeploymentTxHash).toBe('0xdedupehash');
  });

  test('concurrent different deployment identities are not blocked by dedupe lock', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDB);
      const { ensureSmartAccountDeployed } = await import(paths.deployment);
      const now = Date.now();
      const dbm = new PasskeyClientDBManager();
      dbm.setDbName(`PasskeyClientDB-smartacct-dedupe-keys-${now}-${Math.random().toString(16).slice(2)}`);

      await dbm.upsertProfile({
        profileId: 'profile-smartacct-dedupe-keys',
        defaultDeviceNumber: 1,
        passkeyCredential: { id: 'cred-dedupe-keys', rawId: 'raw-dedupe-keys' },
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-dedupe-keys',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-dedupe-keys',
        chainId: 'eip155:11155111',
        accountAddress: '0xaaa111',
        accountModel: 'erc4337',
        isPrimary: true,
        deployed: false,
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-dedupe-keys',
        chainId: 'eip155:11155111',
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
        chain: 'evm',
        chainIdCandidates: ['eip155:11155111'],
        accountModelCandidates: ['erc4337'],
        enforce: true,
        deploy,
      });
      await firstDeployStarted;

      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-dedupe-keys',
        chainId: 'eip155:11155111',
        accountAddress: '0xaaa111',
        accountModel: 'erc4337',
        isPrimary: false,
        deployed: false,
      });
      await dbm.upsertChainAccount({
        profileId: 'profile-smartacct-dedupe-keys',
        chainId: 'eip155:11155111',
        accountAddress: '0xbbb222',
        accountModel: 'erc4337',
        isPrimary: true,
        deployed: false,
      });

      const p2 = ensureSmartAccountDeployed({
        clientDB: dbm,
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        chainIdCandidates: ['eip155:11155111'],
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
    }, { paths: IMPORT_PATHS });

    expect(result.secondStartedBeforeRelease).toBe(true);
    expect(result.deployCalls).toBe(2);
    expect(result.deployAddresses).toContain('0xaaa111');
    expect(result.deployAddresses).toContain('0xbbb222');
    expect(result.firstStatus).toBe('deployed');
    expect(result.secondStatus).toBe('deployed');
  });
});
