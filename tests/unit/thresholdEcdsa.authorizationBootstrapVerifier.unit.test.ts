import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  secp256k1PrivateKey32ToPublicKey33,
  signSecp256k1Recoverable,
} from '../../packages/wallet-server/src/core/ThresholdService/evmCryptoWasm';
import { verifyEcdsaClientRootProof } from '../../packages/wallet-server/src/core/ThresholdService/ecdsaClientRootProof';
import type { EcdsaDerivationClientRootProof } from '../../packages/wallet-server/src/core/types';

test('client root proof rejects verification against an ECDSA derivation client-share public key', async () => {
  const digest32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index));
  const clientRootPrivateKey32 = new Uint8Array(32).fill(1);
  const derivationClientSharePrivateKey32 = new Uint8Array(32).fill(2);
  const clientRootPublicKey33 = await secp256k1PrivateKey32ToPublicKey33(clientRootPrivateKey32);
  const derivationClientSharePublicKey33 = await secp256k1PrivateKey32ToPublicKey33(
    derivationClientSharePrivateKey32,
  );
  const signature65 = await signSecp256k1Recoverable(digest32, clientRootPrivateKey32);
  const rootProof: EcdsaDerivationClientRootProof = {
    version: 'ecdsa-derivation:role-local:first-bootstrap-root-proof:v2',
    digest32B64u: base64UrlEncode(digest32),
    signature65B64u: base64UrlEncode(signature65),
    clientRootPublicKey33B64u: base64UrlEncode(
      clientRootPublicKey33,
    ) as EcdsaDerivationClientRootProof['clientRootPublicKey33B64u'],
  };

  await expect(verifyEcdsaClientRootProof(rootProof)).resolves.toMatchObject({ ok: true });
  await expect(
    verifyEcdsaClientRootProof({
      ...rootProof,
      clientRootPublicKey33B64u: base64UrlEncode(
        derivationClientSharePublicKey33,
      ) as EcdsaDerivationClientRootProof['clientRootPublicKey33B64u'],
    }),
  ).resolves.toMatchObject({
    ok: false,
    code: 'unauthorized',
    message: 'Invalid client root proof',
  });
});
