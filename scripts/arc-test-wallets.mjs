import { mkdir, open, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import process from 'node:process';

import {
  createPublicClient,
  createWalletClient,
  formatUnits,
  getAddress,
  http,
  isAddress,
  parseAbi,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { arcTestnet } from 'viem/chains';

const DEFAULT_WALLET_FILE = '.runtime/arc-test-wallets.json';
const DEFAULT_RPC_URL = 'https://rpc.testnet.arc.network';
const DEFAULT_WALLET_COUNT = 20;
const MAX_WALLET_COUNT = 100;
const ARC_TESTNET_CHAIN_ID = 5_042_002;
const ARC_TESTNET_USDC = '0x3600000000000000000000000000000000000000';
const USDC_DECIMALS = 6;
const WALLET_BUNDLE_VERSION = 'arc_test_wallet_bundle_v1';
const ERC20_ABI = parseAbi([
  'function balanceOf(address owner) view returns (uint256)',
  'function transfer(address to, uint256 amount) returns (bool)',
]);

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const [command, ...tokens] = argv;
  const options = new Map();
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token === '--') continue;
    if (!token.startsWith('--')) fail(`Unexpected argument: ${token}`);
    if (token === '--confirm') {
      options.set('confirm', true);
      continue;
    }
    const value = tokens[index + 1];
    if (!value || value.startsWith('--')) fail(`Missing value for ${token}`);
    options.set(token.slice(2), value);
    index += 1;
  }
  return { command, options };
}

function parseWalletCount(value) {
  const count = Number(value ?? DEFAULT_WALLET_COUNT);
  if (!Number.isSafeInteger(count) || count < 1 || count > MAX_WALLET_COUNT) {
    fail(`Wallet count must be an integer from 1 to ${MAX_WALLET_COUNT}`);
  }
  return count;
}

function createWalletRecord(index) {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  return {
    index,
    address: account.address,
    publicKey: account.publicKey,
    privateKey,
  };
}

function createWalletBundle(count) {
  const wallets = [];
  for (let index = 0; index < count; index += 1) {
    wallets.push(createWalletRecord(index + 1));
  }
  return {
    version: WALLET_BUNDLE_VERSION,
    network: {
      name: 'Arc Testnet',
      chainId: ARC_TESTNET_CHAIN_ID,
      rpcUrl: DEFAULT_RPC_URL,
      usdcAddress: ARC_TESTNET_USDC,
    },
    createdAt: new Date().toISOString(),
    wallets,
  };
}

async function writePrivateWalletBundle(filePath, bundle) {
  const absolutePath = resolve(filePath);
  await mkdir(dirname(absolutePath), { recursive: true, mode: 0o700 });
  const file = await open(absolutePath, 'wx', 0o600);
  try {
    await file.writeFile(`${JSON.stringify(bundle, null, 2)}\n`, { encoding: 'utf8' });
    await file.chmod(0o600);
  } finally {
    await file.close();
  }
  return absolutePath;
}

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseWalletRecord(value, expectedIndex) {
  if (!isObject(value)) fail(`Wallet ${expectedIndex} is invalid`);
  if (value.index !== expectedIndex) fail(`Wallet ${expectedIndex} has an invalid index`);
  if (typeof value.privateKey !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value.privateKey)) {
    fail(`Wallet ${expectedIndex} has an invalid private key`);
  }
  const account = privateKeyToAccount(value.privateKey);
  if (typeof value.address !== 'string' || getAddress(value.address) !== account.address) {
    fail(`Wallet ${expectedIndex} address does not match its private key`);
  }
  if (typeof value.publicKey !== 'string' || value.publicKey.toLowerCase() !== account.publicKey) {
    fail(`Wallet ${expectedIndex} public key does not match its private key`);
  }
  return {
    index: expectedIndex,
    address: account.address,
    publicKey: account.publicKey,
    privateKey: value.privateKey,
  };
}

function parseWalletBundle(value) {
  if (!isObject(value) || value.version !== WALLET_BUNDLE_VERSION) {
    fail(`Wallet file must use ${WALLET_BUNDLE_VERSION}`);
  }
  if (!isObject(value.network) || value.network.chainId !== ARC_TESTNET_CHAIN_ID) {
    fail('Wallet file is not for Arc Testnet');
  }
  if (!Array.isArray(value.wallets) || value.wallets.length === 0) {
    fail('Wallet file contains no wallets');
  }
  const wallets = [];
  for (let index = 0; index < value.wallets.length; index += 1) {
    wallets.push(parseWalletRecord(value.wallets[index], index + 1));
  }
  return {
    version: WALLET_BUNDLE_VERSION,
    network: {
      name: 'Arc Testnet',
      chainId: ARC_TESTNET_CHAIN_ID,
      rpcUrl: DEFAULT_RPC_URL,
      usdcAddress: ARC_TESTNET_USDC,
    },
    createdAt: String(value.createdAt || ''),
    wallets,
  };
}

async function readWalletBundle(filePath) {
  const absolutePath = resolve(filePath);
  const raw = await readFile(absolutePath, 'utf8');
  return { absolutePath, bundle: parseWalletBundle(JSON.parse(raw)) };
}

function printPublicWallets(bundle) {
  const publicWallets = [];
  for (const { index, address, publicKey } of bundle.wallets) {
    publicWallets.push({ index, address, publicKey });
  }
  console.log(JSON.stringify(publicWallets, null, 2));
}

async function generateWallets(options) {
  const count = parseWalletCount(options.get('count'));
  const output = options.get('output') ?? DEFAULT_WALLET_FILE;
  const bundle = createWalletBundle(count);
  const absolutePath = await writePrivateWalletBundle(output, bundle);
  console.log(`Generated ${count} Arc testnet wallets.`);
  console.log(`Private wallet file: ${absolutePath}`);
  console.log('The private keys were saved with mode 0600 and were not printed.');
  printPublicWallets(bundle);
}

async function printAddresses(options) {
  const filePath = options.get('file') ?? DEFAULT_WALLET_FILE;
  const { bundle } = await readWalletBundle(filePath);
  printPublicWallets(bundle);
}

function parseDestination(value) {
  if (!value || !isAddress(value)) fail('sweep requires --to <Arc testnet address>');
  return getAddress(value);
}

function createArcPublicClient(rpcUrl) {
  return createPublicClient({ chain: arcTestnet, transport: http(rpcUrl) });
}

async function readUsdcBalance(publicClient, address) {
  return publicClient.readContract({
    address: ARC_TESTNET_USDC,
    abi: ERC20_ABI,
    functionName: 'balanceOf',
    args: [address],
  });
}

async function inspectSweepBalances(publicClient, wallets) {
  const balances = [];
  for (const wallet of wallets) {
    const balance = await readUsdcBalance(publicClient, wallet.address);
    balances.push({ wallet, balance });
  }
  return balances;
}

function printSweepPlan(destination, balances) {
  const funded = [];
  let total = 0n;
  for (const entry of balances) {
    if (entry.balance > 0n) {
      funded.push(entry);
      total += entry.balance;
    }
  }
  console.log(`Destination: ${destination}`);
  console.log(`Funded source wallets: ${funded.length}/${balances.length}`);
  console.log(`USDC to sweep: ${formatUnits(total, USDC_DECIMALS)}`);
  for (const { wallet, balance } of funded) {
    console.log(
      `  ${wallet.index.toString().padStart(2, '0')} ${wallet.address} ${formatUnits(balance, USDC_DECIMALS)} USDC`,
    );
  }
  return funded;
}

async function transferWalletUsdc({ publicClient, rpcUrl, destination, wallet, balance }) {
  const account = privateKeyToAccount(wallet.privateKey);
  const walletClient = createWalletClient({ account, chain: arcTestnet, transport: http(rpcUrl) });
  const { request } = await publicClient.simulateContract({
    account,
    address: ARC_TESTNET_USDC,
    abi: ERC20_ABI,
    functionName: 'transfer',
    args: [destination, balance],
  });
  const hash = await walletClient.writeContract(request);
  console.log(`Wallet ${wallet.index}: submitted ${hash}`);
  const receipt = await publicClient.waitForTransactionReceipt({ hash, confirmations: 1 });
  if (receipt.status !== 'success') fail(`Wallet ${wallet.index}: transaction reverted (${hash})`);
  console.log(`Wallet ${wallet.index}: swept ${formatUnits(balance, USDC_DECIMALS)} USDC`);
}

async function executeSweep(publicClient, rpcUrl, destination, balances) {
  const failures = [];
  for (const entry of balances) {
    try {
      await transferWalletUsdc({ publicClient, rpcUrl, destination, ...entry });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      failures.push({ index: entry.wallet.index, address: entry.wallet.address, message });
      console.error(`Wallet ${entry.wallet.index}: ${message}`);
    }
  }
  if (failures.length > 0) {
    fail(
      `${failures.length} wallet sweep(s) failed; rerun the command to retry remaining balances`,
    );
  }
}

async function sweepWallets(options) {
  const destination = parseDestination(options.get('to'));
  const filePath = options.get('file') ?? DEFAULT_WALLET_FILE;
  const rpcUrl = options.get('rpc-url') ?? DEFAULT_RPC_URL;
  const { bundle } = await readWalletBundle(filePath);
  for (const wallet of bundle.wallets) {
    if (wallet.address === destination) {
      fail('Sweep destination must not be one of the generated source wallets');
    }
  }

  const publicClient = createArcPublicClient(rpcUrl);
  const chainId = await publicClient.getChainId();
  if (chainId !== ARC_TESTNET_CHAIN_ID) {
    fail(`RPC chain ID ${chainId} does not match Arc Testnet ${ARC_TESTNET_CHAIN_ID}`);
  }

  const balances = await inspectSweepBalances(publicClient, bundle.wallets);
  const funded = printSweepPlan(destination, balances);
  if (funded.length === 0) return;
  if (options.get('confirm') !== true) {
    console.log('Dry run only. Add --confirm to sign and broadcast these transfers.');
    return;
  }
  await executeSweep(publicClient, rpcUrl, destination, funded);
}

function printUsage() {
  console.log(`Usage:
  pnpm arc-wallets:generate -- [--count 20] [--output ${DEFAULT_WALLET_FILE}]
  pnpm arc-wallets:addresses -- [--file ${DEFAULT_WALLET_FILE}]
  pnpm arc-wallets:sweep -- --to <address> [--file ${DEFAULT_WALLET_FILE}] [--rpc-url <url>] [--confirm]

The sweep command is a dry run until --confirm is supplied.`);
}

async function main() {
  const { command, options } = parseArgs(process.argv.slice(2));
  switch (command) {
    case 'generate':
      await generateWallets(options);
      return;
    case 'addresses':
      await printAddresses(options);
      return;
    case 'sweep':
      await sweepWallets(options);
      return;
    case undefined:
    case 'help':
    case '--help':
      printUsage();
      return;
    default:
      fail(`Unknown command: ${command}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
