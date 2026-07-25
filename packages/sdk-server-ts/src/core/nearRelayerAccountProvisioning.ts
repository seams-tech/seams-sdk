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
import type { FinalExecutionOutcome, TxExecutionStatus } from '@near-js/types';
import {
  threshold_ed25519_build_near_tx_unsigned_borsh,
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
  readonly transactionHash: string;
  readonly nextNonce: string;
  readonly blockHash: string;
  readonly signedTransaction: {
    readonly transaction: unknown;
    readonly signature: unknown;
    readonly borsh_bytes: number[];
  };
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
        transactionHash: created.transactionHash,
        nextNonce: txContext.nextNonce,
        blockHash: txContext.blockHash,
        signedTransaction: {
          transaction: created.signedTransaction.transaction,
          signature: created.signedTransaction.signature,
          borsh_bytes: [...created.signedTransaction.borsh_bytes],
        },
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

type SponsoredNearAccountProbeV1 =
  | { readonly kind: 'created'; readonly result: AccountCreationResult }
  | { readonly kind: 'rejected'; readonly message: string }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'uncertain'; readonly message: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function outcomeStatus(outcome: FinalExecutionOutcome): SponsoredNearAccountProbeV1 {
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
  return { kind: 'uncertain', message: 'NEAR transaction status is not terminal' };
}

function isTransactionNotFound(error: unknown): boolean {
  if (!(error instanceof NearRpcError)) return false;
  const text = `${error.kind || ''} ${error.message}`.toLowerCase();
  return (
    error.type === 'RpcError' &&
    (text.includes('unknown transaction') ||
      text.includes('transaction_not_found') ||
      text.includes('does not exist'))
  );
}

async function probeSponsoredNearAccountCreation(input: {
  readonly prepared: PreparedSponsoredNearAccountCreationV1;
  readonly nearClient: NearClient;
  readonly relayerAccountId: string;
}): Promise<SponsoredNearAccountProbeV1> {
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
    if (!isTransactionNotFound(error)) {
      return { kind: 'uncertain', message: 'Unable to query NEAR transaction status' };
    }
    return { kind: 'not_found' };
  }
}

async function readBackSponsoredNearAccount(input: {
  readonly prepared: PreparedSponsoredNearAccountCreationV1;
  readonly nearClient: NearClient;
}): Promise<SponsoredNearAccountProbeV1> {
  try {
    await input.nearClient.viewAccount(input.prepared.accountId);
    const accessKey = await input.nearClient.viewAccessKey(
      input.prepared.accountId,
      input.prepared.publicKey,
    );
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
  } catch (error: unknown) {
    if (error instanceof NearRpcError && isTransactionNotFound(error)) {
      return { kind: 'not_found' };
    }
    return { kind: 'uncertain', message: errorMessage(error) || 'NEAR account readback failed' };
  }
}

async function validatePreparedSponsoredNearAccountCreation(
  prepared: PreparedSponsoredNearAccountCreationV1,
): Promise<void> {
  const bytes = Uint8Array.from(prepared.signedTransaction.borsh_bytes);
  const expectedHash = base58Encode(await sha256Bytes(bytes));
  if (expectedHash !== prepared.transactionHash) {
    throw new Error('Persisted NEAR transaction hash does not match its signed bytes');
  }
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
    return { kind: 'rejected', result: { success: false, error: errorMessage(error), message: errorMessage(error) } };
  }
  if (input.reconcileFirst) {
    const probe = await probeSponsoredNearAccountCreation({
      prepared: input.prepared,
      nearClient,
      relayerAccountId: input.relayerAccountId,
    });
    if (probe.kind === 'created') return probe;
    if (probe.kind === 'rejected') return { kind: 'rejected', result: { success: false, error: probe.message, message: probe.message } };
    if (probe.kind === 'uncertain') return { kind: 'uncertain', message: probe.message };
    const readback = await readBackSponsoredNearAccount({ prepared: input.prepared, nearClient });
    if (readback.kind === 'created') return readback;
    if (readback.kind === 'uncertain') return { kind: 'uncertain', message: readback.message };
    if (readback.kind === 'rejected') return { kind: 'rejected', result: { success: false, error: readback.message, message: readback.message } };
  }
  try {
    const outcome = await nearClient.sendTransaction(
      SignedTransaction.fromPlain({
        transaction: input.prepared.signedTransaction.transaction,
        signature: input.prepared.signedTransaction.signature,
        borsh_bytes: [...input.prepared.signedTransaction.borsh_bytes],
      }),
      NEAR_IMPLICIT_ACCOUNT_FUND_WAIT_UNTIL,
    );
    return {
      kind: 'created',
      result: {
        success: true,
        accountId: input.prepared.accountId,
        transactionHash: transactionHashFromOutcome(outcome, input.prepared.transactionHash),
        message: `Account ${input.prepared.accountId} created`,
      },
    };
  } catch (error: unknown) {
    const message = errorMessage(error) || 'Failed to create NEAR account';
    const readback = await readBackSponsoredNearAccount({ prepared: input.prepared, nearClient });
    if (readback.kind === 'created') return readback;
    if (readback.kind === 'uncertain') return { kind: 'uncertain', message: `${message}; ${readback.message}` };
    if (readback.kind === 'not_found' && isDefinitiveNearRejection(error)) {
      return { kind: 'rejected', result: { success: false, error: message, message } };
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
  return (
    error instanceof NearRpcError &&
    (error.type === 'InvalidTxError' || error.type === 'ActionError' || error.type === 'Failure')
  );
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
