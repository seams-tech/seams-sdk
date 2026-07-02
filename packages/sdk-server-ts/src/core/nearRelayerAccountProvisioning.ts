import { ActionType, type ActionArgsWasm, validateActionArgsWasm } from '@shared/near/actions';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { errorMessage } from '@shared/utils/errors';
import {
  deriveImplicitNearAccountIdFromEd25519PublicKey,
  parseImplicitNearAccountId,
  parseNamedNearAccountId,
} from '@shared/utils/near';
import type { FinalExecutionOutcome, TxExecutionStatus } from '@near-js/types';
import {
  threshold_ed25519_build_near_tx_unsigned_borsh,
  threshold_ed25519_finalize_near_tx_from_signature,
} from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import { decodeNearSecretKey, toPublicKeyStringFromSecretKey } from './nearKeys';
import { ensureNearSignerWasm } from './nearSignerWasmRuntime';
import {
  MinimalNearClient,
  SignedTransaction,
  type NearClient,
} from './rpcClients/near/NearClient';
import type {
  AccountCreationRequest,
  AccountCreationResult,
  FundImplicitNearAccountRequest,
  FundImplicitNearAccountResult,
} from './types';

const NEAR_IMPLICIT_ACCOUNT_FUND_WAIT_UNTIL: TxExecutionStatus = 'FINAL';
const ED25519_PKCS8_SEED_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

type NearRelayerRuntimeInput = {
  readonly relayerAccount: string;
  readonly relayerPrivateKey: string;
  readonly relayerPublicKey?: string;
  readonly nearRpcUrl: string;
  readonly nearClient?: NearClient;
  readonly ensureSignerWasm?: () => Promise<void>;
};

type ValidatedNearRelayerRuntimeInput = {
  readonly relayerAccount: string;
  readonly relayerPrivateKey: string;
  readonly relayerPublicKey: string;
  readonly nearRpcUrl: string;
  readonly nearClient?: NearClient;
  readonly ensureSignerWasm?: () => Promise<void>;
};

type NearImplicitFundingInput = FundImplicitNearAccountRequest &
  NearRelayerRuntimeInput & {
    readonly fundedAmountYocto: string;
  };

type NearNamedAccountCreationInput = AccountCreationRequest &
  NearRelayerRuntimeInput & {
    readonly initialBalanceYocto: string;
  };

type NearTxUnsignedBorshOutput = {
  readonly unsignedTransactionBorshB64u: string;
  readonly signingDigestB64u: string;
};

type FinalizeNearTxFromSignatureOutput = {
  readonly signedTransactionBorshB64u: string;
  readonly transactionHash: string;
};

type ValidatedFundingInput = FundImplicitNearAccountRequest &
  ValidatedNearRelayerRuntimeInput & {
    readonly fundedAmountYocto: string;
  };

type ValidatedNamedAccountCreationInput = AccountCreationRequest &
  ValidatedNearRelayerRuntimeInput & {
    readonly accountId: string;
    readonly publicKey: string;
    readonly initialBalanceYocto: string;
  };

function requireNonEmptyString(value: unknown, label: string): string {
  const text = String(value || '').trim();
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object') {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireSingleUnsignedNearTxBorshOutput(value: unknown): NearTxUnsignedBorshOutput {
  if (!Array.isArray(value) || value.length !== 1) {
    throw new Error('Expected exactly one unsigned NEAR transaction from signer WASM');
  }
  const record = requireRecord(value[0], 'unsigned NEAR transaction output');
  return {
    unsignedTransactionBorshB64u: requireNonEmptyString(
      record.unsignedTransactionBorshB64u,
      'unsignedTransactionBorshB64u',
    ),
    signingDigestB64u: requireNonEmptyString(record.signingDigestB64u, 'signingDigestB64u'),
  };
}

function requireFinalizeNearTxFromSignatureOutput(
  value: unknown,
): FinalizeNearTxFromSignatureOutput {
  const record = requireRecord(value, 'finalized NEAR transaction output');
  return {
    signedTransactionBorshB64u: requireNonEmptyString(
      record.signedTransactionBorshB64u,
      'signedTransactionBorshB64u',
    ),
    transactionHash: requireNonEmptyString(record.transactionHash, 'transactionHash'),
  };
}

function createEd25519Pkcs8FromSeed(seed32: Uint8Array): Uint8Array {
  if (seed32.length !== 32) {
    throw new Error(`Ed25519 seed must be 32 bytes, got ${seed32.length}`);
  }
  const pkcs8 = new Uint8Array(ED25519_PKCS8_SEED_PREFIX.length + seed32.length);
  pkcs8.set(ED25519_PKCS8_SEED_PREFIX, 0);
  pkcs8.set(seed32, ED25519_PKCS8_SEED_PREFIX.length);
  return pkcs8;
}

function copyToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.length);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function signEd25519MessageWithNodeCrypto(
  pkcs8: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array | null> {
  try {
    const nodeCrypto = await import('node:crypto');
    const { Buffer } = await import('node:buffer');
    const key = nodeCrypto.createPrivateKey({
      key: Buffer.from(pkcs8),
      format: 'der',
      type: 'pkcs8',
    });
    return new Uint8Array(nodeCrypto.sign(null, message, key));
  } catch {
    return null;
  }
}

async function signEd25519MessageWithWebCrypto(
  pkcs8: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array | null> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return null;
  try {
    const key = await subtle.importKey('pkcs8', copyToArrayBuffer(pkcs8), 'Ed25519', false, [
      'sign',
    ]);
    return new Uint8Array(await subtle.sign('Ed25519', key, copyToArrayBuffer(message)));
  } catch {
    return null;
  }
}

async function signEd25519MessageWithPkcs8(
  pkcs8: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> {
  const nodeSignature = await signEd25519MessageWithNodeCrypto(pkcs8, message);
  if (nodeSignature) return nodeSignature;
  const webCryptoSignature = await signEd25519MessageWithWebCrypto(pkcs8, message);
  if (webCryptoSignature) return webCryptoSignature;
  throw new Error('Ed25519 private-key signing is unavailable in this runtime');
}

async function signNearDigestWithSecretKey(args: {
  readonly nearPrivateKey: string;
  readonly signingDigestB64u: string;
  readonly expectedSignerPublicKey: string;
}): Promise<string> {
  const actualPublicKey = toPublicKeyStringFromSecretKey(args.nearPrivateKey);
  if (actualPublicKey !== args.expectedSignerPublicKey) {
    throw new Error('NEAR private key does not match expected signer public key');
  }
  const digest = base64UrlDecode(args.signingDigestB64u);
  if (digest.length !== 32) {
    throw new Error(`NEAR signing digest must be 32 bytes, got ${digest.length}`);
  }

  const secretKeyBytes = decodeNearSecretKey(args.nearPrivateKey);
  const seed32 = new Uint8Array(secretKeyBytes.subarray(0, 32));
  const pkcs8 = createEd25519Pkcs8FromSeed(seed32);
  try {
    const signature = await signEd25519MessageWithPkcs8(pkcs8, digest);
    if (signature.length !== 64) {
      throw new Error(`Ed25519 signature must be 64 bytes, got ${signature.length}`);
    }
    return base64UrlEncode(signature);
  } finally {
    secretKeyBytes.fill(0);
    seed32.fill(0);
    pkcs8.fill(0);
  }
}

function parsePositiveYocto(value: unknown, label: string): string {
  const text = requireNonEmptyString(value, label);
  const amount = BigInt(text);
  if (amount <= 0n) throw new Error(`${label} must be positive`);
  return amount.toString();
}

function requireEd25519PublicKey(value: unknown, label: string): string {
  const text = requireNonEmptyString(value, label);
  if (!text.startsWith('ed25519:')) throw new Error(`${label} must be an ed25519 public key`);
  return text;
}

function validateNearRelayerRuntimeInput(
  input: NearRelayerRuntimeInput,
): ValidatedNearRelayerRuntimeInput {
  const relayerAccount = requireNonEmptyString(input.relayerAccount, 'relayerAccount');
  const relayerPrivateKey = requireNonEmptyString(input.relayerPrivateKey, 'relayerPrivateKey');
  const derivedRelayerPublicKey = toPublicKeyStringFromSecretKey(relayerPrivateKey);
  const configuredRelayerPublicKey = String(input.relayerPublicKey || '').trim();
  if (configuredRelayerPublicKey && configuredRelayerPublicKey !== derivedRelayerPublicKey) {
    throw new Error('relayerPublicKey does not match relayerPrivateKey');
  }
  return {
    relayerAccount,
    relayerPrivateKey,
    relayerPublicKey: derivedRelayerPublicKey,
    nearRpcUrl: requireNonEmptyString(input.nearRpcUrl, 'nearRpcUrl'),
    nearClient: input.nearClient,
    ensureSignerWasm: input.ensureSignerWasm,
  };
}

function validateFundingInput(input: NearImplicitFundingInput): ValidatedFundingInput {
  const walletId = requireNonEmptyString(input.walletId, 'walletId');
  const nearPublicKeyStr = requireNonEmptyString(input.nearPublicKeyStr, 'nearPublicKeyStr');
  const parsedNearAccountId = parseImplicitNearAccountId(input.nearAccountId);
  if (!parsedNearAccountId.ok) throw new Error(parsedNearAccountId.message);
  const derivedNearAccountId = deriveImplicitNearAccountIdFromEd25519PublicKey(nearPublicKeyStr);
  if (derivedNearAccountId !== parsedNearAccountId.value) {
    throw new Error('nearAccountId does not match nearPublicKeyStr implicit account ID');
  }
  const runtime = validateNearRelayerRuntimeInput(input);
  return {
    walletId,
    nearAccountId: parsedNearAccountId.value,
    nearPublicKeyStr,
    relayerAccount: runtime.relayerAccount,
    relayerPrivateKey: runtime.relayerPrivateKey,
    relayerPublicKey: runtime.relayerPublicKey,
    nearRpcUrl: runtime.nearRpcUrl,
    nearClient: runtime.nearClient,
    ensureSignerWasm: runtime.ensureSignerWasm,
    fundedAmountYocto: parsePositiveYocto(input.fundedAmountYocto, 'fundedAmountYocto'),
  };
}

function validateNamedAccountCreationInput(
  input: NearNamedAccountCreationInput,
): ValidatedNamedAccountCreationInput {
  const accountId = requireNonEmptyString(input.accountId, 'accountId');
  const parsedAccountId = parseNamedNearAccountId(accountId);
  if (!parsedAccountId.ok) throw new Error(parsedAccountId.message);
  const runtime = validateNearRelayerRuntimeInput(input);
  return {
    accountId: parsedAccountId.value,
    publicKey: requireEd25519PublicKey(input.publicKey, 'publicKey'),
    recoveryPublicKey: input.recoveryPublicKey,
    relayerAccount: runtime.relayerAccount,
    relayerPrivateKey: runtime.relayerPrivateKey,
    relayerPublicKey: runtime.relayerPublicKey,
    nearRpcUrl: runtime.nearRpcUrl,
    nearClient: runtime.nearClient,
    ensureSignerWasm: runtime.ensureSignerWasm,
    initialBalanceYocto: parsePositiveYocto(input.initialBalanceYocto, 'initialBalanceYocto'),
  };
}

async function fetchRelayerTxContext(input: {
  readonly nearClient: NearClient;
  readonly relayerAccount: string;
  readonly relayerPublicKey: string;
}): Promise<{ readonly nextNonce: string; readonly blockHash: string }> {
  let nonce = 0n;
  try {
    const accessKey = await input.nearClient.viewAccessKey(
      input.relayerAccount,
      input.relayerPublicKey,
    );
    nonce = BigInt(accessKey?.nonce ?? 0);
  } catch {
    nonce = 0n;
  }
  const block = await input.nearClient.viewBlock({ finality: 'final' });
  return {
    nextNonce: (nonce + 1n).toString(),
    blockHash: block.header.hash,
  };
}

function buildFullAccessAddKeyAction(publicKey: string): ActionArgsWasm {
  return {
    action_type: ActionType.AddKey,
    public_key: publicKey,
    access_key: JSON.stringify({
      nonce: 0,
      permission: { FullAccess: {} },
    }),
  };
}

async function buildSignedRelayerActionTransaction(input: {
  readonly relayerAccount: string;
  readonly relayerPrivateKey: string;
  readonly relayerPublicKey: string;
  readonly receiverId: string;
  readonly nextNonce: string;
  readonly blockHash: string;
  readonly actions: readonly ActionArgsWasm[];
}): Promise<{ readonly signedTransaction: SignedTransaction; readonly transactionHash: string }> {
  for (const action of input.actions) validateActionArgsWasm(action);
  const unsignedTx = requireSingleUnsignedNearTxBorshOutput(
    threshold_ed25519_build_near_tx_unsigned_borsh({
      txSigningRequests: [
        {
          nearAccountId: input.relayerAccount,
          receiverId: input.receiverId,
          actions: [...input.actions],
        },
      ],
      transactionContext: {
        nearPublicKeyStr: input.relayerPublicKey,
        nextNonce: input.nextNonce,
        txBlockHash: input.blockHash,
      },
    }),
  );
  const signatureB64u = await signNearDigestWithSecretKey({
    nearPrivateKey: input.relayerPrivateKey,
    signingDigestB64u: unsignedTx.signingDigestB64u,
    expectedSignerPublicKey: input.relayerPublicKey,
  });
  const finalized = requireFinalizeNearTxFromSignatureOutput(
    threshold_ed25519_finalize_near_tx_from_signature({
      unsignedTransactionBorshB64u: unsignedTx.unsignedTransactionBorshB64u,
      signingDigestB64u: unsignedTx.signingDigestB64u,
      signatureB64u,
      expectedNearAccountId: input.relayerAccount,
      expectedSignerPublicKey: input.relayerPublicKey,
    }),
  );
  return {
    transactionHash: finalized.transactionHash,
    signedTransaction: SignedTransaction.fromPlain({
      transaction: null,
      signature: null,
      borsh_bytes: Array.from(base64UrlDecode(finalized.signedTransactionBorshB64u)),
    }),
  };
}

async function buildSignedRelayerTransfer(input: {
  readonly relayerAccount: string;
  readonly relayerPrivateKey: string;
  readonly relayerPublicKey: string;
  readonly receiverId: string;
  readonly nextNonce: string;
  readonly blockHash: string;
  readonly fundedAmountYocto: string;
}): Promise<{ readonly signedTransaction: SignedTransaction; readonly transactionHash: string }> {
  return await buildSignedRelayerActionTransaction({
    ...input,
    actions: [{ action_type: ActionType.Transfer, deposit: input.fundedAmountYocto }],
  });
}

async function buildSignedRelayerCreateAccount(input: {
  readonly relayerAccount: string;
  readonly relayerPrivateKey: string;
  readonly relayerPublicKey: string;
  readonly accountId: string;
  readonly nextNonce: string;
  readonly blockHash: string;
  readonly initialBalanceYocto: string;
  readonly publicKey: string;
}): Promise<{ readonly signedTransaction: SignedTransaction; readonly transactionHash: string }> {
  return await buildSignedRelayerActionTransaction({
    relayerAccount: input.relayerAccount,
    relayerPrivateKey: input.relayerPrivateKey,
    relayerPublicKey: input.relayerPublicKey,
    receiverId: input.accountId,
    nextNonce: input.nextNonce,
    blockHash: input.blockHash,
    actions: [
      { action_type: ActionType.CreateAccount },
      { action_type: ActionType.Transfer, deposit: input.initialBalanceYocto },
      buildFullAccessAddKeyAction(input.publicKey),
    ],
  });
}

function transactionHashFromOutcome(
  outcome: FinalExecutionOutcome,
  fallback: string,
): string | undefined {
  const record = outcome as unknown as {
    transaction?: { hash?: unknown };
    transaction_outcome?: { id?: unknown };
  };
  return (
    String(record.transaction?.hash || record.transaction_outcome?.id || fallback || '').trim() ||
    undefined
  );
}

async function ensureSignerWasm(input: {
  readonly ensureSignerWasm?: () => Promise<void>;
}): Promise<void> {
  if (input.ensureSignerWasm) {
    await input.ensureSignerWasm();
    return;
  }
  await ensureNearSignerWasm();
}

export async function fundImplicitNearAccountWithRelayer(
  input: NearImplicitFundingInput,
): Promise<FundImplicitNearAccountResult> {
  try {
    const validated = validateFundingInput(input);
    const nearClient = validated.nearClient || new MinimalNearClient(validated.nearRpcUrl);
    await ensureSignerWasm(validated);
    const txContext = await fetchRelayerTxContext({
      nearClient,
      relayerAccount: validated.relayerAccount,
      relayerPublicKey: validated.relayerPublicKey,
    });
    const transfer = await buildSignedRelayerTransfer({
      relayerAccount: validated.relayerAccount,
      relayerPrivateKey: validated.relayerPrivateKey,
      relayerPublicKey: validated.relayerPublicKey,
      receiverId: validated.nearAccountId,
      nextNonce: txContext.nextNonce,
      blockHash: txContext.blockHash,
      fundedAmountYocto: validated.fundedAmountYocto,
    });
    const outcome = await nearClient.sendTransaction(
      transfer.signedTransaction,
      NEAR_IMPLICIT_ACCOUNT_FUND_WAIT_UNTIL,
    );
    return {
      ok: true,
      walletId: validated.walletId,
      nearAccountId: validated.nearAccountId,
      fundedAmountYocto: validated.fundedAmountYocto,
      transactionHash: transactionHashFromOutcome(outcome, transfer.transactionHash),
      message: 'Implicit NEAR account funding transaction submitted',
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'funding_failed',
      message: errorMessage(error) || 'Failed to fund implicit NEAR account',
    };
  }
}

export async function createNamedNearAccountWithRelayer(
  input: NearNamedAccountCreationInput,
): Promise<AccountCreationResult> {
  try {
    const validated = validateNamedAccountCreationInput(input);
    const nearClient = validated.nearClient || new MinimalNearClient(validated.nearRpcUrl);
    await ensureSignerWasm(validated);
    const txContext = await fetchRelayerTxContext({
      nearClient,
      relayerAccount: validated.relayerAccount,
      relayerPublicKey: validated.relayerPublicKey,
    });
    const created = await buildSignedRelayerCreateAccount({
      relayerAccount: validated.relayerAccount,
      relayerPrivateKey: validated.relayerPrivateKey,
      relayerPublicKey: validated.relayerPublicKey,
      accountId: validated.accountId,
      nextNonce: txContext.nextNonce,
      blockHash: txContext.blockHash,
      initialBalanceYocto: validated.initialBalanceYocto,
      publicKey: validated.publicKey,
    });
    const outcome = await nearClient.sendTransaction(
      created.signedTransaction,
      NEAR_IMPLICIT_ACCOUNT_FUND_WAIT_UNTIL,
    );
    return {
      success: true,
      accountId: validated.accountId,
      transactionHash: transactionHashFromOutcome(outcome, created.transactionHash),
      message: `Account ${validated.accountId} created`,
    };
  } catch (error: unknown) {
    const message = errorMessage(error) || 'Failed to create NEAR account';
    return {
      success: false,
      error: message,
      message,
    };
  }
}
