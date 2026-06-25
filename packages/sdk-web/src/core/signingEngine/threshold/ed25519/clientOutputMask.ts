import { base64UrlDecode } from '@shared/utils/encoders';
import { type ThresholdEd25519HssCanonicalContext } from '../crypto/hssClientSignerWasm';
import { prepareThresholdEd25519HssClientOutputMaskHandleNearSignerWasm } from '../../chains/near/nearSignerWasm';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';

export type ThresholdEd25519HssClientOutputMaskOperation =
  | 'registration'
  | 'tx_signing'
  | 'link_device'
  | 'email_recovery'
  | 'warm_session_reconstruction'
  | 'explicit_key_export';

export type ThresholdEd25519HssClientOutputMaskContext = ThresholdEd25519HssCanonicalContext & {
  contextBindingB64u: string;
  operation: ThresholdEd25519HssClientOutputMaskOperation;
  relayerKeyId: string;
};

export type ThresholdEd25519HssOutputProjectionPolicy = {
  kind: 'client-masked-projection';
  clientRecoverableSecretB64u: string;
};

const CLIENT_OUTPUT_MASK_BYTES = 32;

function throwUnsupportedPolicy(value: unknown): never {
  const raw = value;
  const kind =
    raw && typeof raw === 'object' && 'kind' in raw
      ? String((raw as { kind?: unknown }).kind || '')
      : 'unknown';
  throw new Error(`Unsupported Ed25519 HSS output projection policy: ${kind}`);
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (bytes instanceof Uint8Array) {
    bytes.fill(0);
  }
}

function requireNonEmptyString(value: string, fieldName: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`Missing ${fieldName} for Ed25519 HSS client output mask derivation`);
  }
  return normalized;
}

function decodeFixed32B64u(value: string, fieldName: string): Uint8Array {
  const normalized = requireNonEmptyString(value, fieldName);
  const decoded = base64UrlDecode(normalized);
  if (decoded.length !== CLIENT_OUTPUT_MASK_BYTES) {
    zeroizeBytes(decoded);
    throw new Error(`${fieldName} must decode to 32 bytes`);
  }
  return decoded;
}

export async function resolveThresholdEd25519HssClientOutputMaskHandle(args: {
  policy: ThresholdEd25519HssOutputProjectionPolicy;
  context: ThresholdEd25519HssClientOutputMaskContext;
  workerCtx: WorkerOperationContext;
}): Promise<string> {
  validateThresholdEd25519HssOutputProjectionPolicy(args.policy);
  switch (args.policy.kind) {
    case 'client-masked-projection': {
      const result = await prepareThresholdEd25519HssClientOutputMaskHandleNearSignerWasm({
        request: {
          applicationBindingDigestB64u: args.context.applicationBindingDigestB64u,
          participantIds: args.context.participantIds,
          contextBindingB64u: args.context.contextBindingB64u,
          operation: args.context.operation,
          relayerKeyId: args.context.relayerKeyId,
          clientRecoverableSecretB64u: args.policy.clientRecoverableSecretB64u,
          expiresAtMs: 0,
        },
        workerCtx: args.workerCtx,
      });
      return result.clientOutputMaskHandle;
    }
    default: {
      return throwUnsupportedPolicy(args.policy);
    }
  }
}

export function validateThresholdEd25519HssOutputProjectionPolicy(
  policy: ThresholdEd25519HssOutputProjectionPolicy,
): void {
  switch (policy.kind) {
    case 'client-masked-projection': {
      const decoded = decodeFixed32B64u(
        policy.clientRecoverableSecretB64u,
        'clientRecoverableSecretB64u',
      );
      zeroizeBytes(decoded);
      return;
    }
    default: {
      throwUnsupportedPolicy(policy);
    }
  }
}
