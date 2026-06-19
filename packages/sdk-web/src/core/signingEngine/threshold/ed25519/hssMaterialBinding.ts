import { base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';

export type Ed25519HssMaterialHandle = string & {
  readonly __ed25519HssMaterialHandle: unique symbol;
};

export type RouterAbEd25519SigningMaterialBindingInput = {
  thresholdSessionId: string;
  walletSigningSessionId: string;
  signingRootId: string;
  signingRootVersion: string;
  expiresAtMs: number;
  nearAccountId: string;
  relayerKeyId: string;
  participantIds: number[];
  signingWorkerId: string;
  clientVerifyingShareB64u: string;
};

export type RouterAbEd25519SigningMaterialPersistedHandle = {
  materialHandle: Ed25519HssMaterialHandle;
  bindingDigest: string;
  clientVerifyingShareB64u: string;
};

export type RouterAbEd25519SigningMaterialRef = {
  kind: 'router_ab_ed25519_hss_material_ref_v1';
  materialHandle: Ed25519HssMaterialHandle;
  bindingDigest: string;
  clientVerifierB64u: string;
};

export function buildRouterAbEd25519SigningMaterialRef(input: {
  materialHandle: string;
  bindingDigest: string;
  clientVerifyingShareB64u: string;
}): RouterAbEd25519SigningMaterialRef {
  const materialHandle = String(input.materialHandle || '').trim();
  const bindingDigest = String(input.bindingDigest || '').trim();
  const clientVerifierB64u = String(input.clientVerifyingShareB64u || '').trim();
  if (!materialHandle || !bindingDigest || !clientVerifierB64u) {
    throw new Error('Router A/B Ed25519 signing material ref is missing binding input');
  }
  return {
    kind: 'router_ab_ed25519_hss_material_ref_v1',
    materialHandle: materialHandle as Ed25519HssMaterialHandle,
    bindingDigest,
    clientVerifierB64u,
  };
}

export function routerAbEd25519SigningMaterialRefToPersistedHandle(
  ref: RouterAbEd25519SigningMaterialRef,
): RouterAbEd25519SigningMaterialPersistedHandle {
  return {
    materialHandle: ref.materialHandle,
    bindingDigest: ref.bindingDigest,
    clientVerifyingShareB64u: ref.clientVerifierB64u,
  };
}

async function materialBindingDigestB64u(
  input: RouterAbEd25519SigningMaterialBindingInput,
): Promise<string> {
  return base64UrlEncode(
    await sha256BytesUtf8(
      alphabetizeStringify({
        kind: 'router_ab_ed25519_hss_material_binding_v1',
        thresholdSessionId: input.thresholdSessionId,
        walletSigningSessionId: input.walletSigningSessionId,
        signingRootId: input.signingRootId,
        signingRootVersion: input.signingRootVersion,
        expiresAtMs: input.expiresAtMs,
        nearAccountId: input.nearAccountId,
        relayerKeyId: input.relayerKeyId,
        participantIds: input.participantIds,
        signingWorkerId: input.signingWorkerId,
        clientVerifyingShareB64u: input.clientVerifyingShareB64u,
      }),
    ),
  );
}

function materialHandleFromBindingDigest(args: {
  thresholdSessionId: string;
  bindingDigest: string;
}): Ed25519HssMaterialHandle {
  return `ed25519-hss-material:${args.thresholdSessionId}:${args.bindingDigest}` as Ed25519HssMaterialHandle;
}

export async function buildRouterAbEd25519SigningMaterialPersistedHandle(
  input: RouterAbEd25519SigningMaterialBindingInput,
): Promise<RouterAbEd25519SigningMaterialPersistedHandle> {
  const thresholdSessionId = String(input.thresholdSessionId || '').trim();
  const clientVerifyingShareB64u = String(input.clientVerifyingShareB64u || '').trim();
  if (!thresholdSessionId || !clientVerifyingShareB64u) {
    throw new Error('Router A/B Ed25519 signing material handle is missing binding input');
  }
  const bindingDigest = await materialBindingDigestB64u({
    ...input,
    thresholdSessionId,
    clientVerifyingShareB64u,
  });
  const ref = buildRouterAbEd25519SigningMaterialRef({
    materialHandle: materialHandleFromBindingDigest({
      thresholdSessionId,
      bindingDigest,
    }),
    bindingDigest,
    clientVerifyingShareB64u,
  });
  return routerAbEd25519SigningMaterialRefToPersistedHandle(ref);
}
