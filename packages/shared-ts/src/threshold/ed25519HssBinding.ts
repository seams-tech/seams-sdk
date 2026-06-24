import { sha256Bytes } from '../utils/digests';
import { base64UrlEncode } from '../utils/encoders';
import type { Ed25519KeyScopeId } from '../utils/registrationIntent';
import type { SigningRootId, SigningRootVersion } from './ecdsaHssRoleLocalBootstrap';

const SDK_ED25519_HSS_APPLICATION_BINDING_DOMAIN_V1 =
  'seams-sdk:ed25519-hss:application-binding:v1';

export type Ed25519HssApplicationBindingDigestB64u = string & {
  readonly __brand: 'Ed25519HssApplicationBindingDigestB64u';
};

export type SdkEd25519HssBindingFacts = {
  ed25519KeyScopeId: Ed25519KeyScopeId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
};

function requireSdkEd25519HssBindingFactString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function pushU32(out: number[], value: number): void {
  out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function pushLengthDelimitedField(out: number[], label: string, value: unknown): void {
  const labelBytes = new TextEncoder().encode(label);
  const valueBytes = new TextEncoder().encode(
    requireSdkEd25519HssBindingFactString(value, label),
  );
  pushU32(out, labelBytes.length);
  out.push(...labelBytes);
  pushU32(out, valueBytes.length);
  out.push(...valueBytes);
}

export function encodeSdkEd25519HssBindingFactsV1(input: SdkEd25519HssBindingFacts): Uint8Array {
  const out: number[] = [];
  const domainBytes = new TextEncoder().encode(SDK_ED25519_HSS_APPLICATION_BINDING_DOMAIN_V1);
  pushU32(out, domainBytes.length);
  out.push(...domainBytes);
  pushLengthDelimitedField(out, 'ed25519KeyScopeId', input.ed25519KeyScopeId);
  pushLengthDelimitedField(out, 'signingRootId', input.signingRootId);
  pushLengthDelimitedField(out, 'signingRootVersion', input.signingRootVersion);
  return new Uint8Array(out);
}

export async function computeSdkEd25519HssApplicationBindingDigest32(
  input: SdkEd25519HssBindingFacts,
): Promise<Uint8Array> {
  return await sha256Bytes(encodeSdkEd25519HssBindingFactsV1(input));
}

export async function computeSdkEd25519HssApplicationBindingDigestB64u(
  input: SdkEd25519HssBindingFacts,
): Promise<Ed25519HssApplicationBindingDigestB64u> {
  return base64UrlEncode(
    await computeSdkEd25519HssApplicationBindingDigest32(input),
  ) as Ed25519HssApplicationBindingDigestB64u;
}
