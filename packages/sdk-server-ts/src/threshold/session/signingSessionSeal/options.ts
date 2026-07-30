import { createSigningSessionSealShamir3PassCipherAdapter } from './crypto/cipher';
import { createSigningSessionSealRoutesOptions } from './routesOptions';
import {
  formatSigningSessionSealShamirPrimeB64uForWire,
  formatSigningSessionSealKeyVersionForWire,
  parseSigningSessionSealShamirPrimeB64u,
  parseSigningSessionSealKeyVersion,
  type SigningSessionSealKeyVersion,
  type SigningSessionSealShamirPrimeB64u,
} from '../../../core/keyMaterialBrands';

export type CreateSigningSessionSealOptionsInput = {
  keyVersion?: unknown;
  shamirPrimeB64u: string;
  serverEncryptExponentB64u: string;
  serverDecryptExponentB64u: string;
};

function createShamir3PassCipher(input: {
  signingSessionSealKeyVersion: SigningSessionSealKeyVersion;
  shamirPrimeB64u: SigningSessionSealShamirPrimeB64u;
  serverEncryptExponentB64u: string;
  serverDecryptExponentB64u: string;
}) {
  const keyVersion = formatSigningSessionSealKeyVersionForWire(input.signingSessionSealKeyVersion);
  const shamirPrimeB64u = formatSigningSessionSealShamirPrimeB64uForWire(input.shamirPrimeB64u);
  return createSigningSessionSealShamir3PassCipherAdapter({
    currentKeyVersion: keyVersion,
    keys: [
      {
        keyVersion,
        shamirPrimeB64u,
        serverEncryptExponentB64u: input.serverEncryptExponentB64u,
        serverDecryptExponentB64u: input.serverDecryptExponentB64u,
      },
    ],
  });
}

export function createSigningSessionSealOptions(input: CreateSigningSessionSealOptionsInput) {
  const signingSessionSealKeyVersion = parseSigningSessionSealKeyVersion(input.keyVersion);
  const keyVersion = formatSigningSessionSealKeyVersionForWire(signingSessionSealKeyVersion);
  const signingSessionSealShamirPrimeB64u = parseSigningSessionSealShamirPrimeB64u(
    input.shamirPrimeB64u,
  );
  const shamirPrimeB64u = formatSigningSessionSealShamirPrimeB64uForWire(
    signingSessionSealShamirPrimeB64u,
  );

  return createSigningSessionSealRoutesOptions({
    cipher: createShamir3PassCipher({
      signingSessionSealKeyVersion,
      shamirPrimeB64u: signingSessionSealShamirPrimeB64u,
      serverEncryptExponentB64u: input.serverEncryptExponentB64u,
      serverDecryptExponentB64u: input.serverDecryptExponentB64u,
    }),
    capabilities: {
      mode: 'sealed_refresh_v1',
      keyVersion,
      shamirPrimeB64u,
    },
    logger: console,
  });
}
