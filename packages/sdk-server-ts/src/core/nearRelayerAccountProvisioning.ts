import { ActionType, type ActionArgsWasm, validateActionArgsWasm } from '@shared/near/actions';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { base58Encode } from '@shared/utils/base58';
import { sha256Bytes } from '@shared/utils/digests';
import { errorMessage } from '@shared/utils/errors';
import {
  deriveImplicitNearAccountIdFromEd25519PublicKey,
  parseImplicitNearAccountId,
  parseNamedNearAccountId,
} from '@shared/utils/near';
import type { AccessKeyView, FinalExecutionOutcome, TxExecutionStatus } from '@near-js/types';
import {
  threshold_ed25519_build_near_tx_unsigned_borsh,
  threshold_ed25519_decode_signed_near_tx_borsh,
  threshold_ed25519_finalize_near_tx_from_signature,
} from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import { decodeNearSecretKey, toPublicKeyStringFromSecretKey } from './nearKeys';
import { ensureNearSignerWasm } from './nearSignerWasmRuntime';
import {
  MinimalNearClient,
  NearRpcError,
  SignedTransaction,
  type NearClient,
} from './rpcClients/near/NearClient';
import type {
  AccountCreationRequest,
  AccountCreationResult,
  FundImplicitNearAccountRequest,
  FundImplicitNearAccountResult,
} from './types';

/**
 * A plain funding transfer only has to be executed before the client can read
 * the account's access key, and the client polls until it is queryable — so
 * optimistic execution is enough, matching DEFAULT_WAIT_STATUS everywhere else
 * ("finality will converge shortly after"). Waiting for full finality here used
 * to add several seconds directly in front of the signing step-up prompt, since
 * an operation step-up cannot be prepared until funding lands.
 */
const NEAR_IMPLICIT_ACCOUNT_FUND_WAIT_UNTIL: TxExecutionStatus = 'EXECUTED_OPTIMISTIC';
/**
 * The sponsored account-creation broadcast keeps full finality: its caller
 * persists the prepared bytes and reconciles ambiguous outcomes by rebroadcast,
 * so a reorged optimistic result would feed that reconciliation a false
 * terminal state.
 */
const NEAR_SPONSORED_ACCOUNT_CREATION_WAIT_UNTIL: TxExecutionStatus = 'FINAL';
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

type DecodedSponsoredNearAccountCreation = {
  readonly transactionHash: string;
  readonly signerId: string;
  readonly signerPublicKey: string;
  readonly nonce: string;
  readonly receiverId: string;
  readonly blockHash: string;
  readonly actions: readonly [
    'createAccount',
    { readonly transfer: { readonly deposit: string } },
    {
      readonly addKey: {
        readonly publicKey: string;
        readonly accessKey: { readonly nonce: string; readonly permission: 'FullAccess' };
      };
    },
  ];
  readonly signedTransactionBorshB64u: string;
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

function requireByteArray(value: unknown, label: string, expectedLength?: number): number[] {
  if (
    !Array.isArray(value) ||
    value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255) ||
    (expectedLength !== undefined && value.length !== expectedLength)
  ) {
    throw new Error(`${label} must be a${expectedLength ? ` ${expectedLength}-byte` : ''} array`);
  }
  return value;
}

function requireUnsignedIntegerString(value: unknown, label: string): string {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a safe unsigned integer`);
  }
  return String(value);
}

function requireDecodedEd25519PublicKey(value: unknown, label: string): string {
  const record = requireRecord(value, label);
  if (record.keyType !== 0) throw new Error(`${label} must be Ed25519`);
  return `ed25519:${base58Encode(Uint8Array.from(requireByteArray(record.keyData, `${label}.keyData`, 32)))}`;
}

function requireDecodedSponsoredNearAccountCreation(
  value: unknown,
  signedTransactionBorshB64u: string,
): DecodedSponsoredNearAccountCreation {
  const output = requireRecord(value, 'decoded signed NEAR transaction');
  const transactionHash = requireNonEmptyString(output.transactionHash, 'transactionHash');
  const signed = requireRecord(output.signedTransaction, 'signedTransaction');
  const transaction = requireRecord(signed.transaction, 'signedTransaction.transaction');
  const decodedBytes = requireByteArray(signed.borshBytes, 'signedTransaction.borshBytes');
  if (base64UrlEncode(Uint8Array.from(decodedBytes)) !== signedTransactionBorshB64u) {
    throw new Error('Decoded NEAR transaction bytes do not match the persisted signed bytes');
  }
  const actions =
    signed.transaction && Array.isArray(transaction.actions) ? transaction.actions : [];
  if (actions.length !== 3 || actions[0] !== 'createAccount') {
    throw new Error(
      'Persisted NEAR transaction must contain create-account, transfer, and add-key',
    );
  }
  const transfer = requireRecord(actions[1], 'signedTransaction.transaction.actions[1]');
  const transferBody = requireRecord(transfer.transfer, 'transfer action');
  const addKey = requireRecord(actions[2], 'signedTransaction.transaction.actions[2]');
  const addKeyBody = requireRecord(addKey.addKey, 'add-key action');
  const accessKey = requireRecord(addKeyBody.access_key, 'add-key access key');
  if (accessKey.permission !== 'FullAccess') {
    throw new Error('Persisted NEAR transaction add-key action must grant full access');
  }
  return {
    transactionHash,
    signerId: requireNonEmptyString(transaction.signerId, 'signedTransaction.transaction.signerId'),
    signerPublicKey: requireDecodedEd25519PublicKey(
      transaction.publicKey,
      'signedTransaction.transaction.publicKey',
    ),
    nonce: requireUnsignedIntegerString(transaction.nonce, 'signedTransaction.transaction.nonce'),
    receiverId: requireNonEmptyString(
      transaction.receiverId,
      'signedTransaction.transaction.receiverId',
    ),
    blockHash: base58Encode(
      Uint8Array.from(
        requireByteArray(transaction.blockHash, 'signedTransaction.transaction.blockHash', 32),
      ),
    ),
    actions: [
      'createAccount',
      { transfer: { deposit: requireNonEmptyString(transferBody.deposit, 'transfer.deposit') } },
      {
        addKey: {
          publicKey: requireDecodedEd25519PublicKey(addKeyBody.public_key, 'add-key public key'),
          accessKey: {
            nonce: requireUnsignedIntegerString(accessKey.nonce, 'add-key access-key nonce'),
            permission: 'FullAccess',
          },
        },
      },
    ],
    signedTransactionBorshB64u,
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
  } catch (error: unknown) {
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

/**
 * A sponsored account-creation transaction that is fully built, signed, and
 * hashed but not yet broadcast. It is JSON-serializable so a caller can persist
 * it before the broadcast and reconcile an ambiguous outcome afterwards by
 * rebroadcasting these exact bytes. Rebuilding instead of replaying would pick
 * up a fresh nonce and block hash, producing a second distinct transaction.
 */
export type PreparedSponsoredNearAccountCreationV1 = {
  readonly kind: 'prepared_sponsored_near_account_creation_v1';
  readonly accountId: string;
  readonly publicKey: string;
  readonly relayerAccountId: string;
  readonly relayerPublicKey: string;
  readonly initialBalanceYocto: string;
  readonly transactionHash: string;
  readonly nextNonce: string;
  readonly blockHash: string;
  readonly signedTransactionBorshB64u: string;
};

export type PrepareSponsoredNearAccountCreationResultV1 =
  | { readonly ok: true; readonly prepared: PreparedSponsoredNearAccountCreationV1 }
  | { readonly ok: false; readonly error: string; readonly message: string };

/**
 * Builds and signs the sponsored account-creation transaction without
 * broadcasting it. Persist the result before calling
 * [`broadcastPreparedSponsoredNearAccountCreation`].
 */
export async function prepareSponsoredNearAccountCreationWithRelayer(
  input: NearNamedAccountCreationInput,
): Promise<PrepareSponsoredNearAccountCreationResultV1> {
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
    return {
      ok: true,
      prepared: {
        kind: 'prepared_sponsored_near_account_creation_v1',
        accountId: validated.accountId,
        publicKey: validated.publicKey,
        relayerAccountId: validated.relayerAccount,
        relayerPublicKey: validated.relayerPublicKey,
        initialBalanceYocto: validated.initialBalanceYocto,
        transactionHash: created.transactionHash,
        nextNonce: txContext.nextNonce,
        blockHash: txContext.blockHash,
        signedTransactionBorshB64u: base64UrlEncode(
          Uint8Array.from(created.signedTransaction.borsh_bytes),
        ),
      },
    };
  } catch (error: unknown) {
    const message = errorMessage(error) || 'Failed to prepare NEAR account creation';
    return { ok: false, error: message, message };
  }
}

/**
 * A broadcast either lands, is definitively rejected, or leaves the caller
 * unable to tell. Collapsing the third case into a rejection would record a
 * transaction that may already be on chain as a terminal failure, so it stays
 * distinct and must never be persisted as a completed outcome.
 */
export type BroadcastPreparedSponsoredNearAccountResultV1 =
  | { readonly kind: 'created'; readonly result: AccountCreationResult }
  | { readonly kind: 'rejected'; readonly result: AccountCreationResult }
  | { readonly kind: 'uncertain'; readonly message: string };

type SponsoredNearAccountTransactionProbeV1 =
  | { readonly kind: 'created'; readonly result: AccountCreationResult }
  | { readonly kind: 'rejected'; readonly message: string }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'pending'; readonly message: string }
  | { readonly kind: 'infrastructure_failure'; readonly message: string };

type SponsoredNearAccountReadbackV1 =
  | { readonly kind: 'created'; readonly result: AccountCreationResult }
  | { readonly kind: 'account_not_found' }
  | { readonly kind: 'rejected'; readonly message: string }
  | { readonly kind: 'infrastructure_failure'; readonly message: string };

type SponsoredNearAccountReconciliationV1 =
  | { readonly kind: 'terminal'; readonly result: BroadcastPreparedSponsoredNearAccountResultV1 }
  | { readonly kind: 'replay_exact_transaction' };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function outcomeStatus(
  outcome: FinalExecutionOutcome,
): Extract<
  SponsoredNearAccountTransactionProbeV1,
  { readonly kind: 'created' | 'rejected' | 'pending' }
> {
  const status = outcome.status;
  if (status === 'Failure') {
    return { kind: 'rejected', message: 'NEAR transaction failed' };
  }
  if (isRecord(status) && ('SuccessValue' in status || 'SuccessReceiptId' in status)) {
    return { kind: 'created', result: { success: true, message: 'NEAR transaction completed' } };
  }
  if (isRecord(status) && 'Failure' in status) {
    return {
      kind: 'rejected',
      message: `NEAR transaction failed: ${JSON.stringify(status.Failure)}`,
    };
  }
  return { kind: 'pending', message: 'NEAR transaction status is not terminal' };
}

async function probeSponsoredNearAccountCreation(input: {
  readonly prepared: PreparedSponsoredNearAccountCreationV1;
  readonly nearClient: NearClient;
  readonly relayerAccountId: string;
}): Promise<SponsoredNearAccountTransactionProbeV1> {
  try {
    const outcome = await input.nearClient.txStatus(
      input.prepared.transactionHash,
      input.relayerAccountId,
    );
    const status = outcomeStatus(outcome);
    if (status.kind === 'created') {
      return {
        kind: 'created',
        result: {
          success: true,
          accountId: input.prepared.accountId,
          transactionHash: transactionHashFromOutcome(outcome, input.prepared.transactionHash),
          message: `Account ${input.prepared.accountId} created`,
        },
      };
    }
    return status;
  } catch (error: unknown) {
    if (error instanceof NearRpcError) {
      if (error.failureKind === 'transaction_not_found') return { kind: 'not_found' };
      if (isDefinitiveNearRejection(error)) {
        return { kind: 'rejected', message: error.message };
      }
    }
    return {
      kind: 'infrastructure_failure',
      message: 'Unable to query NEAR transaction status',
    };
  }
}

async function readBackSponsoredNearAccount(input: {
  readonly prepared: PreparedSponsoredNearAccountCreationV1;
  readonly nearClient: NearClient;
}): Promise<SponsoredNearAccountReadbackV1> {
  try {
    await input.nearClient.viewAccount(input.prepared.accountId);
  } catch (error: unknown) {
    if (error instanceof NearRpcError && error.failureKind === 'account_not_found') {
      return { kind: 'account_not_found' };
    }
    return {
      kind: 'infrastructure_failure',
      message: errorMessage(error) || 'NEAR account readback failed',
    };
  }

  let accessKey: AccessKeyView;
  try {
    accessKey = await input.nearClient.viewAccessKey(
      input.prepared.accountId,
      input.prepared.publicKey,
    );
  } catch (error: unknown) {
    if (error instanceof NearRpcError && error.failureKind === 'access_key_not_found') {
      return {
        kind: 'rejected',
        message: 'NEAR account exists without the expected access key',
      };
    }
    return {
      kind: 'infrastructure_failure',
      message: errorMessage(error) || 'NEAR access-key readback failed',
    };
  }
  if (accessKey.permission !== 'FullAccess') {
    return {
      kind: 'rejected',
      message: 'NEAR account exists without the expected full-access key',
    };
  }
  return {
    kind: 'created',
    result: {
      success: true,
      accountId: input.prepared.accountId,
      transactionHash: input.prepared.transactionHash,
      message: `Account ${input.prepared.accountId} created`,
    },
  };
}

function rejectedBroadcast(message: string): BroadcastPreparedSponsoredNearAccountResultV1 {
  return {
    kind: 'rejected',
    result: { success: false, error: message, message },
  };
}

async function reconcileSponsoredNearAccountCreation(input: {
  readonly prepared: PreparedSponsoredNearAccountCreationV1;
  readonly nearClient: NearClient;
  readonly relayerAccountId: string;
}): Promise<SponsoredNearAccountReconciliationV1> {
  const transaction = await probeSponsoredNearAccountCreation(input);
  switch (transaction.kind) {
    case 'created':
      return { kind: 'terminal', result: transaction };
    case 'rejected':
      return { kind: 'terminal', result: rejectedBroadcast(transaction.message) };
    case 'not_found':
    case 'pending':
    case 'infrastructure_failure':
      break;
  }

  const readback = await readBackSponsoredNearAccount({
    prepared: input.prepared,
    nearClient: input.nearClient,
  });
  switch (readback.kind) {
    case 'created':
      return { kind: 'terminal', result: readback };
    case 'rejected':
      return { kind: 'terminal', result: rejectedBroadcast(readback.message) };
    case 'infrastructure_failure':
      return {
        kind: 'terminal',
        result: { kind: 'uncertain', message: readback.message },
      };
    case 'account_not_found':
      return transaction.kind === 'not_found'
        ? { kind: 'replay_exact_transaction' }
        : {
            kind: 'terminal',
            result: { kind: 'uncertain', message: transaction.message },
          };
  }
}

async function validatePreparedSponsoredNearAccountCreation(
  prepared: PreparedSponsoredNearAccountCreationV1,
): Promise<DecodedSponsoredNearAccountCreation> {
  await ensureNearSignerWasm();
  const decoded = requireDecodedSponsoredNearAccountCreation(
    threshold_ed25519_decode_signed_near_tx_borsh({
      signedTransactionBorshB64u: prepared.signedTransactionBorshB64u,
    }),
    prepared.signedTransactionBorshB64u,
  );
  if (decoded.transactionHash !== prepared.transactionHash) {
    throw new Error('Persisted NEAR transaction hash does not match its signed bytes');
  }
  if (
    decoded.signerId !== prepared.relayerAccountId ||
    decoded.signerPublicKey !== prepared.relayerPublicKey
  ) {
    throw new Error('Persisted NEAR transaction signer does not match its relayer metadata');
  }
  if (decoded.receiverId !== prepared.accountId) {
    throw new Error('Persisted NEAR transaction receiver does not match its account metadata');
  }
  if (decoded.nonce !== prepared.nextNonce || decoded.blockHash !== prepared.blockHash) {
    throw new Error('Persisted NEAR transaction context does not match its nonce or block hash');
  }
  const [, transfer, addKey] = decoded.actions;
  if (
    transfer.transfer.deposit !== prepared.initialBalanceYocto ||
    addKey.addKey.publicKey !== prepared.publicKey ||
    addKey.addKey.accessKey.nonce !== '0'
  ) {
    throw new Error('Persisted NEAR transaction actions do not match account-creation metadata');
  }
  return decoded;
}

export async function preparedSponsoredNearAccountCreationArtifactFingerprint(
  prepared: PreparedSponsoredNearAccountCreationV1,
): Promise<string> {
  await validatePreparedSponsoredNearAccountCreation(prepared);
  const signedBytes = base64UrlDecode(prepared.signedTransactionBorshB64u);
  return `sponsored-near-account-creation-v1:${base64UrlEncode(await sha256Bytes(signedBytes))}`;
}

export async function broadcastPreparedSponsoredNearAccountCreation(input: {
  readonly prepared: PreparedSponsoredNearAccountCreationV1;
  readonly nearRpcUrl: string;
  readonly relayerAccountId: string;
  readonly nearClient?: NearClient;
  /** Set when replaying a persisted transaction whose outcome is unknown. */
  readonly reconcileFirst?: boolean;
}): Promise<BroadcastPreparedSponsoredNearAccountResultV1> {
  const nearClient = input.nearClient || new MinimalNearClient(input.nearRpcUrl);
  if (input.prepared.relayerAccountId !== input.relayerAccountId) {
    const message = 'Persisted NEAR transaction relayer does not match the configured relayer';
    return { kind: 'rejected', result: { success: false, error: message, message } };
  }
  try {
    await validatePreparedSponsoredNearAccountCreation(input.prepared);
  } catch (error: unknown) {
    return {
      kind: 'rejected',
      result: { success: false, error: errorMessage(error), message: errorMessage(error) },
    };
  }
  if (input.reconcileFirst) {
    const reconciliation = await reconcileSponsoredNearAccountCreation({
      prepared: input.prepared,
      nearClient,
      relayerAccountId: input.relayerAccountId,
    });
    if (reconciliation.kind === 'terminal') return reconciliation.result;
  }
  try {
    const outcome = await nearClient.sendTransaction(
      SignedTransaction.fromPlain({
        transaction: null,
        signature: null,
        borsh_bytes: Array.from(base64UrlDecode(input.prepared.signedTransactionBorshB64u)),
      }),
      NEAR_SPONSORED_ACCOUNT_CREATION_WAIT_UNTIL,
    );
    const status = outcomeStatus(outcome);
    if (status.kind === 'created') {
      return {
        kind: 'created',
        result: {
          success: true,
          accountId: input.prepared.accountId,
          transactionHash: transactionHashFromOutcome(outcome, input.prepared.transactionHash),
          message: `Account ${input.prepared.accountId} created`,
        },
      };
    }
    if (status.kind === 'rejected') return rejectedBroadcast(status.message);
    const readback = await readBackSponsoredNearAccount({ prepared: input.prepared, nearClient });
    if (readback.kind === 'created') return readback;
    if (readback.kind === 'infrastructure_failure') {
      return { kind: 'uncertain', message: `${status.message}; ${readback.message}` };
    }
    if (readback.kind === 'rejected') return rejectedBroadcast(readback.message);
    return { kind: 'uncertain', message: status.message };
  } catch (error: unknown) {
    const message = errorMessage(error) || 'Failed to create NEAR account';
    const readback = await readBackSponsoredNearAccount({ prepared: input.prepared, nearClient });
    if (readback.kind === 'created') return readback;
    if (readback.kind === 'infrastructure_failure')
      return { kind: 'uncertain', message: `${message}; ${readback.message}` };
    if (readback.kind === 'rejected') return rejectedBroadcast(readback.message);
    if (isDefinitiveNearRejection(error)) {
      return rejectedBroadcast(message);
    }
    return { kind: 'uncertain', message };
  }
}

/**
 * Only failures that prove the transaction cannot have taken effect are
 * definitive. Transport and timeout failures say nothing about whether the
 * transaction reached the network, so they are treated as uncertain.
 */
function isDefinitiveNearRejection(error: unknown): boolean {
  if (!(error instanceof NearRpcError)) return false;
  switch (error.failureKind) {
    case 'invalid_transaction':
    case 'action_error':
    case 'execution_failure':
      return true;
    case 'transaction_not_found':
    case 'account_not_found':
    case 'access_key_not_found':
    case 'invalid_nonce':
    case 'expired':
    case 'infrastructure_failure':
    case 'unknown':
      return false;
  }
}

export async function createNamedNearAccountWithRelayer(
  input: NearNamedAccountCreationInput,
): Promise<AccountCreationResult> {
  try {
    const validated = validateNamedAccountCreationInput(input);
    const prepared = await prepareSponsoredNearAccountCreationWithRelayer(input);
    if (!prepared.ok) {
      return { success: false, error: prepared.error, message: prepared.message };
    }
    const broadcast = await broadcastPreparedSponsoredNearAccountCreation({
      prepared: prepared.prepared,
      nearRpcUrl: validated.nearRpcUrl,
      relayerAccountId: validated.relayerAccount,
      ...(validated.nearClient ? { nearClient: validated.nearClient } : {}),
    });
    if (broadcast.kind === 'uncertain') {
      // This entry point has no durable claim to reconcile against, so surface
      // the ambiguity to its caller rather than reporting a definitive failure.
      throw new Error(broadcast.message);
    }
    return broadcast.result;
  } catch (error: unknown) {
    const message = errorMessage(error) || 'Failed to create NEAR account';
    return {
      success: false,
      error: message,
      message,
    };
  }
}
