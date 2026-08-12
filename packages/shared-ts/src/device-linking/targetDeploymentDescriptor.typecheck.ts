import type { LinkedDeviceTargetDeploymentDescriptorUnsignedV1 } from './targetDeploymentDescriptor';
import type { EcdsaTargetCapabilityBindingV1 } from '../signing-lanes/rotation';
import type { Ed25519YaoSuiteId } from '../signing-lanes/ids';
import type { DigestB64u } from '../utils/canonicalPrimitives';

declare const ed25519Descriptor: Extract<
  LinkedDeviceTargetDeploymentDescriptorUnsignedV1,
  { readonly keyFamily: 'ed25519' }
>;
declare const ecdsaDescriptor: Extract<
  LinkedDeviceTargetDeploymentDescriptorUnsignedV1,
  { readonly keyFamily: 'ecdsa_secp256k1' }
>;
declare const ecdsaCapability: EcdsaTargetCapabilityBindingV1;
declare const yaoSuiteId: Ed25519YaoSuiteId;
declare const circuitDigestB64u: DigestB64u;

const validEd25519Descriptor: LinkedDeviceTargetDeploymentDescriptorUnsignedV1 = ed25519Descriptor;
const validEcdsaDescriptor: LinkedDeviceTargetDeploymentDescriptorUnsignedV1 = ecdsaDescriptor;
void validEd25519Descriptor;
void validEcdsaDescriptor;

const invalidEd25519Capability: Extract<
  LinkedDeviceTargetDeploymentDescriptorUnsignedV1,
  { readonly keyFamily: 'ed25519' }
> = {
  ...ed25519Descriptor,
  // @ts-expect-error Ed25519 descriptors cannot carry ECDSA target capability.
  targetCapability: ecdsaCapability,
};

const invalidEcdsaYaoFacts: Extract<
  LinkedDeviceTargetDeploymentDescriptorUnsignedV1,
  { readonly keyFamily: 'ecdsa_secp256k1' }
> = {
  ...ecdsaDescriptor,
  // @ts-expect-error ECDSA descriptors cannot carry Ed25519 Yao suite.
  yaoSuiteId,
  // @ts-expect-error ECDSA descriptors cannot carry Ed25519 circuit digest.
  circuitDigestB64u,
};

const invalidEcdsaReshareBinding: Extract<
  LinkedDeviceTargetDeploymentDescriptorUnsignedV1,
  { readonly keyFamily: 'ecdsa_secp256k1' }
> = {
  ...ecdsaDescriptor,
  // @ts-expect-error ECDSA descriptors require an authenticated reshare binding.
  reshareChannelBindingDigestB64u: undefined,
};

void invalidEd25519Capability;
void invalidEcdsaYaoFacts;
void invalidEcdsaReshareBinding;
