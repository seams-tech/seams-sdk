import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { type ActionArgsWasm, validateActionArgsWasm } from '@/core/types/actions';
import {
  isExtractCosePublicKeySuccess,
  WorkerRequestType,
  WorkerResponseType,
  type WasmTransactionSignResult,
  type WasmDeriveThresholdEd25519ClientVerifyingShareResult,
  type WasmDeriveThresholdEd25519BootstrapPackageResult,
} from '@/core/types/signer-worker';
import { ensureEd25519Prefix } from '@shared/utils/validation';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';

export async function deriveThresholdEd25519ClientVerifyingShareWasm(args: {
  sessionId: string;
  nearAccountId: string;
  prfFirstB64u: string;
  wrapKeySalt: string;
  workerCtx: WorkerOperationContext;
}): Promise<{ nearAccountId: string; clientVerifyingShareB64u: string }> {
  const sessionId = String(args.sessionId || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  const wrapKeySalt = String(args.wrapKeySalt || '').trim();

  if (!sessionId) throw new Error('Missing sessionId');
  if (!nearAccountId) throw new Error('Missing nearAccountId');
  if (!prfFirstB64u || !wrapKeySalt) {
    throw new Error('Missing PRF.first or wrapKeySalt for share derivation');
  }

  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId,
      type: WorkerRequestType.DeriveThresholdEd25519ClientVerifyingShare,
      payload: {
        nearAccountId,
        prfFirstB64u,
        wrapKeySalt,
      },
    },
  });

  if (response.type !== WorkerResponseType.DeriveThresholdEd25519ClientVerifyingShareSuccess) {
    throw new Error('DeriveThresholdEd25519ClientVerifyingShare failed');
  }

  const wasmResult = response.payload as WasmDeriveThresholdEd25519ClientVerifyingShareResult;
  const clientVerifyingShareB64u = String(wasmResult?.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('Missing clientVerifyingShareB64u in worker response');
  }

  return {
    nearAccountId,
    clientVerifyingShareB64u,
  };
}

export async function deriveThresholdEd25519BootstrapPackageWasm(args: {
  sessionId: string;
  nearAccountId: string;
  rpId?: string;
  keyVersion: string;
  prfFirstB64u: string;
  recoveryServerShareB64u?: string;
  workerCtx: WorkerOperationContext;
}): Promise<{
  nearAccountId: string;
  keyVersion: string;
  recoveryExportCapable: true;
  clientParticipantId: number;
  relayerParticipantId: number;
  publicKey: string;
  recoveryPublicKey: string;
  clientVerifyingShareB64u: string;
  relayerSigningShareB64u: string;
  relayerVerifyingShareB64u: string;
}> {
  const sessionId = String(args.sessionId || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const rpId = String(args.rpId || '').trim();
  const keyVersion = String(args.keyVersion || '').trim();
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  const recoveryServerShareB64u = String(args.recoveryServerShareB64u || '').trim();

  if (!sessionId) throw new Error('Missing sessionId');
  if (!nearAccountId) throw new Error('Missing nearAccountId');
  if (!keyVersion) throw new Error('Missing keyVersion');
  if (!prfFirstB64u) throw new Error('Missing prfFirstB64u');

  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId,
      type: WorkerRequestType.DeriveThresholdEd25519BootstrapPackage,
      payload: {
        nearAccountId,
        ...(rpId ? { rpId } : {}),
        keyVersion,
        prfFirstB64u,
        ...(recoveryServerShareB64u ? { recoveryServerShareB64u } : {}),
      },
    },
  });

  if (response.type !== WorkerResponseType.DeriveThresholdEd25519BootstrapPackageSuccess) {
    throw new Error('DeriveThresholdEd25519BootstrapPackage failed');
  }

  const wasmResult = response.payload as WasmDeriveThresholdEd25519BootstrapPackageResult;
  const normalizedKeyVersion = String(wasmResult?.keyVersion || '').trim();
  const recoveryExportCapable =
    Boolean((wasmResult as { recoveryExportCapable?: unknown })?.recoveryExportCapable) === true;
  const publicKey = ensureEd25519Prefix(String(wasmResult?.publicKey || '').trim());
  const recoveryPublicKey = ensureEd25519Prefix(
    String((wasmResult as { recoveryPublicKey?: unknown })?.recoveryPublicKey || '').trim(),
  );
  const clientVerifyingShareB64u = String(wasmResult?.clientVerifyingShareB64u || '').trim();
  const relayerSigningShareB64u = String(wasmResult?.relayerSigningShareB64u || '').trim();
  const relayerVerifyingShareB64u = String(wasmResult?.relayerVerifyingShareB64u || '').trim();
  if (!normalizedKeyVersion) {
    throw new Error('Missing keyVersion in threshold Ed25519 bootstrap package');
  }
  if (!recoveryExportCapable) {
    throw new Error('Threshold Ed25519 bootstrap package must set recoveryExportCapable=true');
  }
  if (!publicKey || !recoveryPublicKey) {
    throw new Error('Threshold Ed25519 bootstrap package missing public keys');
  }
  if (!clientVerifyingShareB64u || !relayerSigningShareB64u || !relayerVerifyingShareB64u) {
    throw new Error('Threshold Ed25519 bootstrap package missing share material');
  }
  return {
    nearAccountId,
    keyVersion: normalizedKeyVersion,
    recoveryExportCapable: true,
    clientParticipantId: Number(wasmResult?.clientParticipantId),
    relayerParticipantId: Number(wasmResult?.relayerParticipantId),
    publicKey,
    recoveryPublicKey,
    clientVerifyingShareB64u,
    relayerSigningShareB64u,
    relayerVerifyingShareB64u,
  };
}

export async function extractCosePublicKeyWasm(args: {
  attestationObjectBase64url: string;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: WorkerRequestType.ExtractCosePublicKey,
      payload: {
        attestationObjectBase64url: args.attestationObjectBase64url,
      },
    },
  });

  if (!isExtractCosePublicKeySuccess(response)) {
    throw new Error('COSE public key extraction failed in WASM worker');
  }

  return response.payload.cosePublicKeyBytes;
}

export async function signTransactionWithKeyPairWasm(args: {
  nearPrivateKey: string;
  signerAccountId: string;
  receiverId: string;
  nonce: string;
  blockHash: string;
  actions: ActionArgsWasm[];
  workerCtx: WorkerOperationContext;
}): Promise<{ signedTransaction: SignedTransaction; logs?: string[] }> {
  args.actions.forEach((action) => {
    validateActionArgsWasm(action);
  });

  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: WorkerRequestType.SignTransactionWithKeyPair,
      payload: {
        nearPrivateKey: args.nearPrivateKey,
        signerAccountId: args.signerAccountId,
        receiverId: args.receiverId,
        nonce: args.nonce,
        blockHash: args.blockHash,
        actions: args.actions,
      },
    },
  });

  if (response.type !== WorkerResponseType.SignTransactionWithKeyPairSuccess) {
    throw new Error('Transaction signing with private key failed');
  }

  const wasmResult = response.payload as WasmTransactionSignResult;
  if (!wasmResult.success) {
    throw new Error(wasmResult.error || 'Transaction signing failed');
  }

  const signedTransactions = wasmResult.signedTransactions || [];
  if (signedTransactions.length !== 1) {
    throw new Error(`Expected 1 signed transaction but received ${signedTransactions.length}`);
  }
  const signedTx = signedTransactions[0];
  if (!signedTx || !signedTx.transaction || !signedTx.signature) {
    throw new Error('Incomplete signed transaction data received');
  }

  return {
    signedTransaction: new SignedTransaction({
      transaction: signedTx.transaction,
      signature: signedTx.signature,
      borsh_bytes: Array.from(signedTx.borshBytes || []),
    }),
    logs: wasmResult.logs,
  };
}

export async function generateEphemeralNearKeypairWasm(args: {
  workerCtx: WorkerOperationContext;
}): Promise<{ publicKey: string; privateKey: string }> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: WorkerRequestType.GenerateEphemeralNearKeypair,
      payload: {},
    },
  });

  if (response.type !== WorkerResponseType.GenerateEphemeralNearKeypairSuccess) {
    throw new Error('Worker failed to generate ephemeral NEAR keypair');
  }

  const publicKey = ensureEd25519Prefix(
    String((response.payload as { publicKey?: unknown }).publicKey || '').trim(),
  );
  const privateKey = ensureEd25519Prefix(
    String((response.payload as { privateKey?: unknown }).privateKey || '').trim(),
  );
  if (!publicKey || !privateKey) {
    throw new Error('Worker returned invalid ephemeral NEAR keypair');
  }

  return { publicKey, privateKey };
}
