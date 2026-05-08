import { expect, test } from '@playwright/test';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const pnpmCommand = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm';

function runCommand(
  args: string[],
  cwd: string,
  env?: NodeJS.ProcessEnv,
): Promise<{
  code: number | null;
  stdout: string;
  stderr: string;
}> {
  return new Promise((resolve, reject) => {
    const child = spawn(pnpmCommand, args, {
      cwd,
      env: {
        ...process.env,
        ...env,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += String(chunk || '');
    });
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk || '');
    });
    child.on('error', reject);
    child.on('exit', (code) => resolve({ code, stdout, stderr }));
  });
}

function extractTaggedJson(output: string, tag: string): unknown {
  const line = output
    .split(/\r?\n/)
    .map((entry) => entry.trim())
    .find((entry) => entry.startsWith(`${tag}:`));
  if (!line) {
    throw new Error(`Missing ${tag} output in:\n${output}`);
  }
  return JSON.parse(line.slice(tag.length + 1));
}

test.describe('source-backed EVM smart-account verification', () => {
  test('canonical deployment plan preserves manifest owner ordering in initData', async () => {
    const deploymentManifestPath = pathToFileURL(
      path.join(repoRoot, 'server/src/core/smartAccountDeploymentManifest.ts'),
    ).href;
    const deploymentPlanPath = pathToFileURL(
      path.join(repoRoot, 'server/src/core/evmSmartAccountDeploymentPlan.ts'),
    ).href;

    const script = `
      const { buildCanonicalSmartAccountDeploymentManifest } = await import(${JSON.stringify(
        deploymentManifestPath,
      )});
      const { buildCanonicalEvmSmartAccountDeploymentPlan } = await import(${JSON.stringify(
        deploymentPlanPath,
      )});

      const manifest = buildCanonicalSmartAccountDeploymentManifest({
        recoverySubject: {
          version: 'smart_account_recovery_subject_v1',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'evm:11155111',
          accountAddress: ${JSON.stringify(`0x${'11'.repeat(20)}`)},
          createdAtMs: 1,
          updatedAtMs: 1,
          metadata: {
            chain: 'evm',
            chainId: 11155111,
            chainTarget: {
              kind: 'evm',
              namespace: 'eip155',
              chainId: 11155111,
              networkSlug: 'ethereum-sepolia',
            },
            accountModel: 'erc4337',
            deployed: false,
            factory: ${JSON.stringify(`0x${'22'.repeat(20)}`)},
            entryPoint: ${JSON.stringify(`0x${'33'.repeat(20)}`)},
            recoveryAuthority: ${JSON.stringify(`0x${'44'.repeat(20)}`)},
            salt: '0x1234',
          },
        },
        signers: [
          {
            version: 'account_signer_v1',
            userId: 'alice.testnet',
            chainIdKey: 'evm:11155111',
            accountAddress: ${JSON.stringify(`0x${'11'.repeat(20)}`)},
            signerType: 'threshold',
            signerId: ${JSON.stringify(`0x${'dd'.repeat(20)}`)},
            status: 'pending',
            createdAtMs: 40,
            updatedAtMs: 40,
            metadata: {
              signerSlot: 4,
            },
          },
          {
            version: 'account_signer_v1',
            userId: 'alice.testnet',
            chainIdKey: 'evm:11155111',
            accountAddress: ${JSON.stringify(`0x${'11'.repeat(20)}`)},
            signerType: 'threshold',
            signerId: ${JSON.stringify(`0x${'cc'.repeat(20)}`)},
            status: 'active',
            createdAtMs: 20,
            updatedAtMs: 20,
            metadata: {
              signerSlot: 2,
            },
          },
          {
            version: 'account_signer_v1',
            userId: 'alice.testnet',
            chainIdKey: 'evm:11155111',
            accountAddress: ${JSON.stringify(`0x${'11'.repeat(20)}`)},
            signerType: 'threshold',
            signerId: ${JSON.stringify(`0x${'bb'.repeat(20)}`)},
            status: 'active',
            createdAtMs: 10,
            updatedAtMs: 10,
            metadata: {
              signerSlot: 1,
            },
          },
          {
            version: 'account_signer_v1',
            userId: 'alice.testnet',
            chainIdKey: 'evm:11155111',
            accountAddress: ${JSON.stringify(`0x${'11'.repeat(20)}`)},
            signerType: 'threshold',
            signerId: ${JSON.stringify(`0x${'aa'.repeat(20)}`)},
            status: 'pending',
            createdAtMs: 30,
            updatedAtMs: 30,
          },
          {
            version: 'account_signer_v1',
            userId: 'alice.testnet',
            chainIdKey: 'evm:11155111',
            accountAddress: ${JSON.stringify(`0x${'11'.repeat(20)}`)},
            signerType: 'threshold',
            signerId: ${JSON.stringify(`0x${'ee'.repeat(20)}`)},
            status: 'revoked',
            createdAtMs: 5,
            updatedAtMs: 5,
          },
        ],
        materializedAtMs: 1234,
      });

      const plan = manifest ? buildCanonicalEvmSmartAccountDeploymentPlan(manifest) : null;
      const ownerWords = [];
      if (plan) {
        const hex = String(plan.initData || '').slice(2);
        const ownersLengthOffset = 128 * 2;
        const ownersLength = Number.parseInt(hex.slice(ownersLengthOffset, ownersLengthOffset + 64), 16);
        for (let index = 0; index < ownersLength; index += 1) {
          const start = ownersLengthOffset + 64 + index * 64;
          ownerWords.push(\`0x\${hex.slice(start + 24, start + 64)}\`);
        }
      }

      console.log(
        'RESULT:' +
          JSON.stringify({
            ownerAddresses: manifest?.ownerAddresses || null,
            owners: manifest?.owners?.map((owner) => ({
              signerId: owner.signerId,
              status: owner.status,
              signerSlot: owner.signerSlot ?? null,
            })) || null,
            initOwners: ownerWords,
          }),
      );
    `;

    const result = await runCommand(
      ['exec', 'node', '--import', 'tsx', '--eval', script],
      repoRoot,
      {
        TSX_TSCONFIG_PATH: path.join(repoRoot, 'sdk/tsconfig.json'),
      },
    );

    expect(result.code, `${result.stdout}\n${result.stderr}`).toBe(0);
    const parsed = extractTaggedJson(`${result.stdout}\n${result.stderr}`, 'RESULT') as {
      ownerAddresses: string[] | null;
      owners: Array<{
        signerId: string;
        status: string;
        signerSlot: number | null;
      }> | null;
      initOwners: string[];
    };

    expect(parsed.ownerAddresses).toEqual([
      `0x${'bb'.repeat(20)}`,
      `0x${'cc'.repeat(20)}`,
      `0x${'dd'.repeat(20)}`,
      `0x${'aa'.repeat(20)}`,
    ]);
    expect(parsed.owners).toEqual([
      {
        signerId: `0x${'bb'.repeat(20)}`,
        status: 'active',
        signerSlot: 1,
      },
      {
        signerId: `0x${'cc'.repeat(20)}`,
        status: 'active',
        signerSlot: 2,
      },
      {
        signerId: `0x${'dd'.repeat(20)}`,
        status: 'pending',
        signerSlot: 4,
      },
      {
        signerId: `0x${'aa'.repeat(20)}`,
        status: 'pending',
        signerSlot: null,
      },
    ]);
    expect(parsed.initOwners).toEqual(parsed.ownerAddresses);
  });

  test('deployed addOwner and removeOwner runtime uses canonical spec selectors', async () => {
    const linkDeviceOwnerManagementPath = pathToFileURL(
      path.join(repoRoot, 'client/src/core/SeamsPasskey/near/linkDeviceOwnerManagement.ts'),
    ).href;

    const script = `
      const { createLocalDeployedSignerMutationRuntime } = await import(${JSON.stringify(
        linkDeviceOwnerManagementPath,
      )});

      const accountAddress = ${JSON.stringify(`0x${'22'.repeat(20)}`)};
      const ownerAddress = ${JSON.stringify(`0x${'11'.repeat(20)}`)};
      const txHash = ${JSON.stringify(`0x${'ab'.repeat(32)}`)};
      const signCalls = [];
      const rpcMethods = [];
      const reportCounts = {
        accepted: 0,
        rejected: 0,
        finalized: 0,
        dropped: 0,
        reconciled: 0,
      };
      let txLookupIndex = 0;

      globalThis.fetch = async (_input, init) => {
        const body = JSON.parse(String(init?.body || '{}'));
        const method = String(body?.method || '');
        rpcMethods.push(method);
        const id = body?.id ?? 1;
        if (method === 'eth_getBlockByNumber') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: {
                number: '0x10',
                baseFeePerGas: '0x3b9aca00',
              },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_sendRawTransaction') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: txHash,
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionReceipt') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: {
                transactionHash: txHash,
                status: '0x1',
                blockNumber: '0x11',
                gasUsed: '0x5208',
                effectiveGasPrice: '0x3b9aca00',
                to: accountAddress,
                from: ${JSON.stringify(`0x${'33'.repeat(20)}`)},
              },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionByHash') {
          const current = signCalls[txLookupIndex] || signCalls[signCalls.length - 1];
          txLookupIndex += 1;
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: {
                hash: txHash,
                to: accountAddress,
                input: String(current?.data || '0x'),
              },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            error: { code: -32601, message: 'unsupported method' },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      };

      const runtime = createLocalDeployedSignerMutationRuntime({
        context: {
          configs: {
            network: {
              chains: [
                {
                  network: 'ethereum-sepolia',
                  chainId: 11155111,
                  rpcUrl: 'https://rpc.evm.example.test',
                },
              ],
            },
          },
          signingEngine: {
            signTempo: async (args) => {
              signCalls.push({
                data: args.request.tx.data,
                abiName: Array.isArray(args.request.tx.abi) ? args.request.tx.abi[0]?.name : null,
              });
              return {
                chain: 'evm',
                kind: 'eip1559',
                txHashHex: txHash,
                rawTxHex: ${JSON.stringify(`0x02${'34'.repeat(64)}`)},
                managedNonce: {
                  sender: ${JSON.stringify(`0x${'44'.repeat(20)}`)},
                  nonce: String(signCalls.length),
                },
              };
            },
            reportTempoBroadcastAccepted: async () => {
              reportCounts.accepted += 1;
            },
            reportTempoBroadcastRejected: async () => {
              reportCounts.rejected += 1;
            },
            reportTempoFinalized: async () => {
              reportCounts.finalized += 1;
            },
            reportTempoDroppedOrReplaced: async () => {
              reportCounts.dropped += 1;
            },
            reconcileTempoNonceLane: async () => {
              reportCounts.reconciled += 1;
              return {
                chainNextNonce: String(signCalls.length + 1),
                unresolvedInFlightNonces: [],
                blocked: false,
              };
            },
          },
        },
      });

      const baseInput = {
        ownerAccountId: 'alice.testnet',
        op: { id: 'op1' },
        signer: {
          signerId: ownerAddress,
        },
        chainAccount: {
          chainIdKey: 'evm:11155111',
          accountAddress,
        },
        now: Date.now(),
      };

      const addResult = await runtime.executeDeployedAddSigner(baseInput);
      const removeResult = await runtime.executeDeployedRemoveSigner({
        ...baseInput,
        op: { id: 'op2' },
      });

      console.log(
        'RESULT:' +
          JSON.stringify({
            addTxHash: addResult.txHash || null,
            removeTxHash: removeResult.txHash || null,
            selectors: signCalls.map((entry) => String(entry.data || '').slice(0, 10)),
            abiNames: signCalls.map((entry) => entry.abiName || null),
            reportCounts,
            rpcMethods,
          }),
      );
    `;

    const result = await runCommand(
      ['exec', 'node', '--import', 'tsx', '--eval', script],
      repoRoot,
      {
        TSX_TSCONFIG_PATH: path.join(repoRoot, 'sdk/tsconfig.json'),
      },
    );

    expect(result.code, `${result.stdout}\n${result.stderr}`).toBe(0);
    const parsed = extractTaggedJson(`${result.stdout}\n${result.stderr}`, 'RESULT') as {
      addTxHash: string | null;
      removeTxHash: string | null;
      selectors: string[];
      abiNames: Array<string | null>;
      reportCounts: Record<string, number>;
      rpcMethods: string[];
    };

    expect(parsed.addTxHash).toBe(`0x${'ab'.repeat(32)}`);
    expect(parsed.removeTxHash).toBe(`0x${'ab'.repeat(32)}`);
    expect(parsed.selectors).toEqual(['0x7065cb48', '0x173825d9']);
    expect(parsed.abiNames).toEqual(['addOwner', 'removeOwner']);
    expect(parsed.reportCounts).toEqual({
      accepted: 2,
      rejected: 0,
      finalized: 2,
      dropped: 0,
      reconciled: 0,
    });
    expect(parsed.rpcMethods).toEqual([
      'eth_getBlockByNumber',
      'eth_sendRawTransaction',
      'eth_getTransactionReceipt',
      'eth_getTransactionByHash',
      'eth_getBlockByNumber',
      'eth_sendRawTransaction',
      'eth_getTransactionReceipt',
      'eth_getTransactionByHash',
    ]);
  });

  test('shared replay store rejects reused recovery authorization in the spec package', async () => {
    const result = await runCommand(
      ['exec', 'forge', 'test', '--match-test', 'testVerifyAndRecoverIsPublicAndSharesReplayStore'],
      path.join(repoRoot, 'contracts/evm-smart-account'),
    );

    expect(result.code, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(`${result.stdout}\n${result.stderr}`).toContain(
      'testVerifyAndRecoverIsPublicAndSharesReplayStore',
    );
    expect(`${result.stdout}\n${result.stderr}`).toContain('passed');
  });
});
