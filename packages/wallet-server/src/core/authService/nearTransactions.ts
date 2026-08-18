import type { AccessKeyList, FinalExecutionOutcome } from '@near-js/types';
import { base64UrlDecode } from '@shared/utils/encoders';
import { errorMessage, toError } from '@shared/utils/errors';
import { ensureEd25519Prefix } from '@shared/utils/validation';
import type { ActionArgsWasm } from '@shared/near/actions';
import {
  MinimalNearClient,
  SignedTransaction,
} from '../rpcClients/near/NearClient';
import { toPublicKeyStringFromSecretKey } from '../nearKeys';
import {
  requireFinalizeNearTxFromSignatureOutput,
  requireSingleUnsignedNearTxBorshOutput,
  signNearDigestWithSecretKey,
} from './nearPrivateKeySigning';
import {
  threshold_ed25519_build_near_tx_unsigned_borsh,
  threshold_ed25519_finalize_near_tx_from_signature,
} from '../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import type { NormalizedLogger } from '../logger';

export type NearTxContext = {
  nextNonce: string;
  blockHash: string;
};

export type AccountAccessKeyVisibilityOptions = {
  attempts?: number;
  delayMs?: number;
  finality?: 'optimistic' | 'final';
};

function nearAccountNotFound(message: string): boolean {
  return /does not exist|UNKNOWN_ACCOUNT|unknown\s+account/i.test(message);
}

function retryableNearAccountLookupError(message: string): boolean {
  return /server error|internal|temporar|timeout|too many requests|429|empty response|rpc request failed/i.test(
    message,
  );
}

function errorDetailsBlob(error: Error & { details?: unknown }): string {
  const details = error.details;
  if (!details) return '';
  try {
    return typeof details === 'string' ? details : JSON.stringify(details);
  } catch {
    return '';
  }
}

function accountLookupRetryDelayMs(attemptNumber: number): number {
  return 150 * Math.pow(2, attemptNumber - 1);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizedExpectedEd25519PublicKeys(expectedPublicKeys: readonly string[]): string[] {
  return Array.from(new Set(expectedPublicKeys.map((key) => ensureEd25519Prefix(key)).filter(Boolean)));
}

function accessKeyPublicKeys(accessKeyList: AccessKeyList): string[] {
  return accessKeyList.keys
    .map((key) => ensureEd25519Prefix(String(key?.public_key || '').trim()))
    .filter(Boolean);
}

export async function viewAccessKeyListWithClient(input: {
  readonly nearClient: MinimalNearClient;
  readonly accountId: string;
}): Promise<AccessKeyList> {
  return await input.nearClient.viewAccessKeyList(input.accountId);
}

export async function dispatchNearSignedTransactionBorshWithClient(input: {
  readonly nearClient: MinimalNearClient;
  readonly signedTransactionBorshB64u: string;
}): Promise<{ rpcResult: FinalExecutionOutcome }> {
  const signedTransactionBorsh = base64UrlDecode(input.signedTransactionBorshB64u);
  const signedTransaction = SignedTransaction.fromPlain({
    transaction: {},
    signature: {},
    borsh_bytes: Array.from(signedTransactionBorsh),
  });
  return {
    rpcResult: await input.nearClient.sendTransaction(signedTransaction),
  };
}

export async function fetchNearTxContextWithClient(input: {
  readonly nearClient: MinimalNearClient;
  readonly accountId: string;
  readonly publicKey: string;
}): Promise<NearTxContext> {
  let nonce = 0n;
  try {
    const accessKey = await input.nearClient.viewAccessKey(input.accountId, input.publicKey);
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

export async function signGasRelayerNearTransactionWithDeps(input: {
  readonly ensureSignerWasm: () => Promise<void>;
  readonly relayerAccount: string;
  readonly relayerPrivateKey: string;
  readonly receiverId: string;
  readonly nonce: string;
  readonly blockHash: string;
  readonly actions: readonly ActionArgsWasm[];
}): Promise<SignedTransaction> {
  await input.ensureSignerWasm();
  const signerPublicKey = toPublicKeyStringFromSecretKey(input.relayerPrivateKey);
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
        nearPublicKeyStr: signerPublicKey,
        nextNonce: input.nonce,
        txBlockHash: input.blockHash,
      },
    }),
  );
  const signatureB64u = await signNearDigestWithSecretKey({
    nearPrivateKey: input.relayerPrivateKey,
    signingDigestB64u: unsignedTx.signingDigestB64u,
    expectedSignerPublicKey: signerPublicKey,
  });
  const finalized = requireFinalizeNearTxFromSignatureOutput(
    threshold_ed25519_finalize_near_tx_from_signature({
      unsignedTransactionBorshB64u: unsignedTx.unsignedTransactionBorshB64u,
      signingDigestB64u: unsignedTx.signingDigestB64u,
      signatureB64u,
      expectedNearAccountId: input.relayerAccount,
      expectedSignerPublicKey: signerPublicKey,
    }),
  );
  return SignedTransaction.fromPlain({
    transaction: null,
    signature: null,
    borsh_bytes: Array.from(base64UrlDecode(finalized.signedTransactionBorshB64u)),
  });
}

export async function checkNearAccountExistsWithClient(input: {
  readonly nearClient: MinimalNearClient;
  readonly logger: NormalizedLogger;
  readonly accountId: string;
}): Promise<boolean> {
  const attempts = 3;
  let lastError: Error | null = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const view = await input.nearClient.viewAccount(input.accountId);
      return Boolean(view);
    } catch (error: unknown) {
      const parsedError = toError(error) as Error & { details?: unknown };
      lastError = parsedError;
      const message = parsedError.message;
      const combined = `${message}\n${errorDetailsBlob(parsedError)}`;
      if (nearAccountNotFound(combined)) return false;
      if (retryableNearAccountLookupError(message) && attempt < attempts) {
        await delay(accountLookupRetryDelayMs(attempt));
        continue;
      }
      if (retryableNearAccountLookupError(message)) {
        input.logger.warn(
          `[AuthService] Assuming account '${input.accountId}' not found after retryable RPC errors:`,
          message,
        );
        return false;
      }
      input.logger.error(`Error checking account existence for ${input.accountId}:`, parsedError);
      throw parsedError;
    }
  }
  throw lastError || new Error('Unknown error');
}

export async function verifyAccountAccessKeysPresentWithClient(input: {
  readonly nearClient: MinimalNearClient;
  readonly accountId: string;
  readonly expectedPublicKeys: readonly string[];
  readonly options?: AccountAccessKeyVisibilityOptions;
}): Promise<boolean> {
  const expectedPublicKeys = normalizedExpectedEd25519PublicKeys(input.expectedPublicKeys);
  if (!expectedPublicKeys.length) return false;

  const attempts = Math.max(1, Math.floor(input.options?.attempts ?? 4));
  const delayMs = Math.max(50, Math.floor(input.options?.delayMs ?? 250));
  const finality = input.options?.finality ?? 'final';

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const accessKeyList = await input.nearClient.viewAccessKeyList(input.accountId, { finality });
      const actualPublicKeys = accessKeyPublicKeys(accessKeyList);
      if (expectedPublicKeys.every((expected) => actualPublicKeys.includes(expected))) {
        return true;
      }
    } catch {
      // tolerate transient RPC lag during finality propagation
    }
    if (attempt < attempts - 1) await delay(delayMs);
  }

  return false;
}
