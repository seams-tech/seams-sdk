import {
  parseWalletSessionAuthorizationBoundary,
  type WalletSessionAuthorizationState,
} from '../identity/clientSessionPersistenceState';
import {
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';
import { exactSigningLaneWalletId } from '../identity/exactSigningLaneIdentity';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import type { WalletSessionAuthorizationExactActiveReadResult } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { WalletAuthMethodId, WalletAuthorityId } from '@shared/utils/domainIds';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

type ResolvedSelectedWalletAuthority = Extract<
  ResolveSelectedWalletAuthorityResultV1,
  { readonly kind: 'resolved' }
>;

export type ClientWalletSessionAuthorizationPersistenceDeps = {
  readonly resolveSelectedWalletAuthority: (
    walletId: string,
  ) => Promise<ResolveSelectedWalletAuthorityResultV1>;
  readonly readExactActiveForWallet: (input: {
    readonly walletId: WalletId;
    readonly authorityId: WalletAuthorityId;
    readonly authMethodId: WalletAuthMethodId;
  }) => Promise<WalletSessionAuthorizationExactActiveReadResult>;
};

export type ReadClientWalletSessionAuthorizationRequest =
  | {
      readonly kind: 'ed25519';
      readonly laneIdentity: ExactEd25519SigningLaneIdentity;
      readonly authorization?: never;
      readonly nowMs: number;
    }
  | {
      readonly kind: 'ecdsa';
      readonly laneIdentity: ExactEcdsaSigningLaneIdentity;
      readonly authorization: ActiveEvmFamilyWalletSessionAuthorization;
      readonly nowMs: number;
    };

async function readEd25519ClientWalletSessionAuthorization(
  deps: ClientWalletSessionAuthorizationPersistenceDeps,
  request: Extract<ReadClientWalletSessionAuthorizationRequest, { kind: 'ed25519' }>,
): Promise<WalletSessionAuthorizationState> {
  const identity = request.laneIdentity;
  const source = { kind: 'ed25519' as const, laneIdentity: identity };
  const walletId = exactSigningLaneWalletId(identity);
  let selected: ResolveSelectedWalletAuthorityResultV1;
  try {
    selected = await deps.resolveSelectedWalletAuthority(String(walletId));
  } catch {
    return parseWalletSessionAuthorizationBoundary({
      observation: { kind: 'unavailable', source, reason: 'persistence_unavailable' },
      nowMs: request.nowMs,
    });
  }
  if (selected.kind !== 'resolved') {
    return parseWalletSessionAuthorizationBoundary({
      observation:
        selected.kind === 'integrity_error'
          ? { kind: 'invalid', source, reason: 'malformed' }
          : { kind: 'missing', source },
      nowMs: request.nowMs,
    });
  }
  if (!selectedAuthorityMatchesEd25519Lane(selected, identity)) {
    return parseWalletSessionAuthorizationBoundary({
      observation: { kind: 'invalid', source, reason: 'scope_mismatch' },
      nowMs: request.nowMs,
    });
  }
  let authorization: WalletSessionAuthorizationExactActiveReadResult;
  try {
    authorization = await deps.readExactActiveForWallet({
      walletId,
      authorityId: selected.authority.authorityId,
      authMethodId: selected.authMethod.walletAuthMethodId,
    });
  } catch {
    return parseWalletSessionAuthorizationBoundary({
      observation: { kind: 'unavailable', source, reason: 'persistence_unavailable' },
      nowMs: request.nowMs,
    });
  }
  switch (authorization.kind) {
    case 'missing':
      return parseWalletSessionAuthorizationBoundary({
        observation: { kind: 'missing', source },
        nowMs: request.nowMs,
      });
    case 'corrupt':
    case 'upgrade_required':
      return parseWalletSessionAuthorizationBoundary({
        observation: { kind: 'invalid', source, reason: 'malformed' },
        nowMs: request.nowMs,
      });
    case 'persistence_unavailable':
      return parseWalletSessionAuthorizationBoundary({
        observation: { kind: 'unavailable', source, reason: 'persistence_unavailable' },
        nowMs: request.nowMs,
      });
    case 'found':
      break;
  }
  if (
    authorization.record.walletId !== walletId ||
    authorization.record.authorityId !== selected.authority.authorityId ||
    authorization.record.authMethodId !== selected.authMethod.walletAuthMethodId ||
    authorization.operationCredential.walletSessionId !== identity.walletSessionId
  ) {
    return parseWalletSessionAuthorizationBoundary({
      observation: { kind: 'invalid', source, reason: 'scope_mismatch' },
      nowMs: request.nowMs,
    });
  }
  if (
    authorization.record.authorityDigestB64u !== selected.authority.authorityDigestB64u ||
    authorization.record.authorityRevocationEpoch !== selected.authority.revocationEpoch
  ) {
    return parseWalletSessionAuthorizationBoundary({
      observation: { kind: 'invalid', source, reason: 'authority_mismatch' },
      nowMs: request.nowMs,
    });
  }
  return parseWalletSessionAuthorizationBoundary({
    observation: {
      kind: 'found',
      source,
      expiresAtMs: authorization.record.expiresAtMs,
    },
    nowMs: request.nowMs,
  });
}

function selectedAuthorityMatchesEd25519Lane(
  selected: ResolvedSelectedWalletAuthority,
  identity: ExactEd25519SigningLaneIdentity,
): boolean {
  const walletId = exactSigningLaneWalletId(identity);
  if (
    selected.selection.lockState !== 'unlocked' ||
    selected.selection.walletId !== walletId ||
    selected.selection.walletAuthMethodId !== selected.authMethod.walletAuthMethodId ||
    selected.authMethod.walletId !== walletId ||
    selected.authMethod.walletAuthorityId !== selected.authority.authorityId ||
    selected.authMethod.status !== 'active' ||
    selected.authority.walletId !== walletId ||
    selected.authority.state !== 'active'
  ) {
    return false;
  }
  switch (identity.auth.kind) {
    case 'passkey':
      return (
        selected.authMethod.kind === 'passkey' &&
        String(selected.authMethod.rpId) === String(identity.auth.rpId) &&
        selected.authMethod.credentialIdB64u === identity.auth.credentialIdB64u
      );
    case 'email_otp':
      return selected.authMethod.kind === 'email_otp';
  }
}

function readEcdsaClientWalletSessionAuthorization(
  request: Extract<ReadClientWalletSessionAuthorizationRequest, { kind: 'ecdsa' }>,
): WalletSessionAuthorizationState {
  return parseWalletSessionAuthorizationBoundary({
    observation: {
      kind: 'found',
      source: {
        kind: 'ecdsa',
        laneIdentity: request.laneIdentity,
        authorization: request.authorization,
      },
      expiresAtMs: request.authorization.status.expiresAtMs,
    },
    nowMs: request.nowMs,
  });
}

export async function readClientWalletSessionAuthorization(
  deps: ClientWalletSessionAuthorizationPersistenceDeps,
  request: ReadClientWalletSessionAuthorizationRequest,
): Promise<WalletSessionAuthorizationState> {
  switch (request.kind) {
    case 'ed25519':
      return await readEd25519ClientWalletSessionAuthorization(deps, request);
    case 'ecdsa':
      return readEcdsaClientWalletSessionAuthorization(request);
  }
}
