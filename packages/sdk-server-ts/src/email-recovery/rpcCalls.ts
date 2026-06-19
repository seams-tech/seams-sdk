import type { ActionArgsWasm } from '@shared/near/actions';
import { ActionType, validateActionArgsWasm } from '@shared/near/actions';
import { parseContractExecutionError } from '../core/errors';
import { hashRecoveryEmailForAccount, type EmailEncryptionContext } from './emailEncryptor';
import { parseHeaderValue } from './emailParsers';
import type {
  EmailRecoveryResult,
  EmailRecoveryServiceDeps,
  VerifiedEmailRecoveryRequest,
} from './types';
import type { RecoveryEmailPayload } from '@shared/utils/recoveryEmail';
import { toSingleLine } from '@shared/utils/validation';

function formatEmailRecoveryTxError(error: unknown, receiverId: string): string {
  const kind = typeof (error as any)?.kind === 'string' ? String((error as any).kind) : '';
  const short = typeof (error as any)?.short === 'string' ? String((error as any).short) : '';
  const msg = toSingleLine((error as any)?.message || String(error || ''));

  // Non-existent target account (common when the Subject includes a typo / unknown account).
  if (
    kind === 'AccountDoesNotExist' ||
    /AccountDoesNotExist/i.test(short) ||
    /AccountDoesNotExist/i.test(msg) ||
    /account does not exist/i.test(msg)
  ) {
    return `Account "${receiverId}" does not exist`;
  }

  // Invalid / malformed account id.
  if (
    /Invalid(Account|Receiver)Id/i.test(kind) ||
    /Invalid(Account|Receiver)Id/i.test(short) ||
    /Invalid(Account|Receiver)Id/i.test(msg)
  ) {
    return `Invalid NEAR account ID "${receiverId}"`;
  }

  // Prefer concise NearRpcError "short" where available.
  if (short && short !== 'TxExecutionError' && short !== 'RPC error') {
    return `Transaction failed (${short})`;
  }

  return msg || 'Unknown email recovery error';
}

export async function getOutlayerEncryptionPublicKey(
  deps: Pick<EmailRecoveryServiceDeps, 'nearClient' | 'emailDkimVerifierContract'>,
): Promise<Uint8Array> {
  const { nearClient, emailDkimVerifierContract } = deps;

  const result = await nearClient.view<Record<string, never>, unknown>({
    account: emailDkimVerifierContract,
    method: 'get_outlayer_encryption_public_key',
    args: {},
  });

  if (typeof result !== 'string' || !result) {
    throw new Error('Outlayer encryption public key is not configured on EmailDkimVerifier');
  }

  let bytes: Uint8Array;
  try {
    const decoded =
      typeof Buffer !== 'undefined'
        ? Buffer.from(result, 'base64')
        : Uint8Array.from(atob(result), (c) => c.charCodeAt(0));
    bytes = decoded instanceof Uint8Array ? decoded : new Uint8Array(decoded);
  } catch (e) {
    throw new Error(`Failed to decode Outlayer email DKIM public key: ${(e as Error).message}`);
  }

  if (bytes.length !== 32) {
    throw new Error(`Outlayer email DKIM public key must be 32 bytes, got ${bytes.length}`);
  }

  return bytes;
}

export async function buildEncryptedEmailRecoveryActions(
  deps: EmailRecoveryServiceDeps,
  input: {
    accountId: string;
    emailBlob: string;
    recoveryPayload: RecoveryEmailPayload;
    recipientPk: Uint8Array;
    encrypt: (args: {
      emailRaw: string;
      aeadContext: EmailEncryptionContext;
      recipientPk: Uint8Array;
    }) => Promise<{
      envelope: { version: number; ephemeral_pub: string; nonce: string; ciphertext: string };
    }>;
  },
): Promise<{
  actions: ActionArgsWasm[];
  receiverId: string;
  verifiedRecoveryRequest: VerifiedEmailRecoveryRequest;
}> {
  const { relayerAccount, networkId } = deps;
  const { accountId, emailBlob, recoveryPayload, recipientPk, encrypt } = input;

  const aeadContext: EmailEncryptionContext = {
    account_id: accountId,
    network_id: networkId,
    payer_account_id: relayerAccount,
  };

  const { envelope } = await encrypt({
    emailRaw: emailBlob,
    aeadContext,
    recipientPk,
  });

  const verifiedRecoveryRequest = buildVerifiedEmailRecoveryRequest({
    accountId,
    recoveryPayload,
  });

  const fromHeader = parseHeaderValue(emailBlob, 'from');
  if (!fromHeader) {
    throw new Error('Encrypted email recovery requires a From: header');
  }
  const expectedHashedEmail = await hashRecoveryEmailForAccount({
    recoveryEmail: fromHeader,
    accountId,
  });

  const contractArgs = {
    encrypted_email_blob: envelope,
    aead_context: aeadContext,
    expected_hashed_email: expectedHashedEmail,
    expected_new_public_key: verifiedRecoveryRequest.newNearPublicKey,
    request_id: verifiedRecoveryRequest.recoverySessionId,
  };

  const actions: ActionArgsWasm[] = [
    {
      action_type: ActionType.FunctionCall,
      method_name: 'verify_encrypted_email_and_recover',
      args: JSON.stringify(contractArgs),
      gas: '300000000000000',
      deposit: '10000000000000000000000',
    },
  ];
  actions.forEach(validateActionArgsWasm);

  return {
    actions,
    receiverId: accountId,
    verifiedRecoveryRequest,
  };
}

export function buildVerifiedEmailRecoveryRequest(input: {
  accountId: string;
  recoveryPayload: RecoveryEmailPayload;
}): VerifiedEmailRecoveryRequest {
  const accountId = String(input.accountId || '').trim();
  const recoveryPayload = input.recoveryPayload;
  if (!accountId) {
    throw new Error('Encrypted email recovery accountId is required');
  }
  if (!recoveryPayload || recoveryPayload.nearAccountId !== accountId) {
    throw new Error(
      `Encrypted email recovery payload accountId mismatch (expected "${accountId}", got "${String(recoveryPayload?.nearAccountId || '')}")`,
    );
  }

  return {
    version: 'verified_email_recovery_request_v1',
    nearAccountId: accountId,
    recoverySessionId: recoveryPayload.recoverySessionId,
    newNearPublicKey: recoveryPayload.newNearPublicKey,
    newEvmOwnerAddress: recoveryPayload.newEvmOwnerAddress,
    deadlineEpochSeconds: recoveryPayload.deadlineEpochSeconds,
    ...(recoveryPayload.scope ? { scope: recoveryPayload.scope } : {}),
  };
}

export async function sendEmailRecoveryTransaction(
  deps: EmailRecoveryServiceDeps,
  args: {
    receiverId: string;
    actions: ActionArgsWasm[];
    label: string;
  },
): Promise<EmailRecoveryResult> {
  const {
    relayerAccount,
    relayerPrivateKey,
    nearClient,
    queueTransaction,
    fetchTxContext,
    signWithPrivateKey,
    getRelayerPublicKey,
  } = deps;

  const { receiverId, actions, label } = args;

  return queueTransaction(async () => {
    try {
      const relayerPublicKey = getRelayerPublicKey();
      const { nextNonce, blockHash } = await fetchTxContext(relayerAccount, relayerPublicKey);

      const signed = await signWithPrivateKey({
        nearPrivateKey: relayerPrivateKey,
        signerAccountId: relayerAccount,
        receiverId,
        nonce: nextNonce,
        blockHash,
        actions,
      });

      const result = await nearClient.sendTransaction(signed);

      const contractError = parseContractExecutionError(result, receiverId);
      if (contractError) {
        return {
          success: false,
          error: contractError,
          message: contractError,
        };
      }

      return {
        success: true,
        transactionHash: result.transaction.hash,
        message: label,
      };
    } catch (error: any) {
      const msg = formatEmailRecoveryTxError(error, receiverId);
      return {
        success: false,
        error: msg,
        message: msg,
      };
    }
  }, args.label);
}
