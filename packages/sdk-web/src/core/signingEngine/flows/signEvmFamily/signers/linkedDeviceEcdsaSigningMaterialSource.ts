import type {
  DeviceLinkingHolderSigningMaterialHandleV1,
  DeviceLinkingHolderSigningMaterialPortV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
import type { WorkerOperationContext } from '../../../workerManager/executeWorkerOperation';
import type { RouterAbEcdsaDerivationClientSigningMaterialSource } from '../../../routerAb/ecdsaDerivation/presignaturePool';
import {
  thresholdEcdsaLinkedHolderPresignSessionInitWasm,
  thresholdEcdsaRoleLocalAdmitPresignatureWasm,
  thresholdEcdsaRoleLocalCommitPresignatureWasm,
  thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm,
  thresholdEcdsaRoleLocalDestroyPresignatureWasm,
  thresholdEcdsaRoleLocalListAvailablePresignaturesWasm,
  thresholdEcdsaRoleLocalPresignSessionAbortWasm,
  thresholdEcdsaRoleLocalPresignSessionStepWasm,
  thresholdEcdsaRoleLocalReservePresignatureWasm,
  thresholdEcdsaRoleLocalRetirePresignaturePoolWasm,
} from '../../../threshold/crypto/ecdsaDerivationClientWasm';

type LinkedDeviceEcdsaHolderHandleV1 = Extract<
  DeviceLinkingHolderSigningMaterialHandleV1,
  { readonly keyFamily: 'ecdsa_secp256k1' }
>;

export class LinkedDeviceEcdsaSigningMaterialSourceV1 implements RouterAbEcdsaDerivationClientSigningMaterialSource {
  readonly kind = 'router_ab_ecdsa_derivation_client_signing_material_source_v1' as const;
  private readonly handle: LinkedDeviceEcdsaHolderHandleV1;
  private readonly holderMaterial: DeviceLinkingHolderSigningMaterialPortV1;

  constructor(input: {
    readonly handle: LinkedDeviceEcdsaHolderHandleV1;
    readonly holderMaterial: DeviceLinkingHolderSigningMaterialPortV1;
  }) {
    this.handle = input.handle;
    this.holderMaterial = input.holderMaterial;
  }

  async initClientPresignSession(
    input: Parameters<
      RouterAbEcdsaDerivationClientSigningMaterialSource['initClientPresignSession']
    >[0],
  ): ReturnType<RouterAbEcdsaDerivationClientSigningMaterialSource['initClientPresignSession']> {
    return await thresholdEcdsaLinkedHolderPresignSessionInitWasm({
      holderHandleId: this.handle.handleId,
      ...input,
    });
  }

  async stepClientPresignSession(
    input: Parameters<
      RouterAbEcdsaDerivationClientSigningMaterialSource['stepClientPresignSession']
    >[0],
  ): ReturnType<RouterAbEcdsaDerivationClientSigningMaterialSource['stepClientPresignSession']> {
    return await thresholdEcdsaRoleLocalPresignSessionStepWasm(input);
  }

  async abortClientPresignSession(
    input: Parameters<
      RouterAbEcdsaDerivationClientSigningMaterialSource['abortClientPresignSession']
    >[0],
  ): ReturnType<RouterAbEcdsaDerivationClientSigningMaterialSource['abortClientPresignSession']> {
    await thresholdEcdsaRoleLocalPresignSessionAbortWasm(input);
  }

  async admitClientPresignature(
    input: Parameters<
      RouterAbEcdsaDerivationClientSigningMaterialSource['admitClientPresignature']
    >[0],
  ): ReturnType<RouterAbEcdsaDerivationClientSigningMaterialSource['admitClientPresignature']> {
    await thresholdEcdsaRoleLocalAdmitPresignatureWasm(input);
  }

  async destroyClientPresignature(
    input: Parameters<
      RouterAbEcdsaDerivationClientSigningMaterialSource['destroyClientPresignature']
    >[0],
  ): ReturnType<RouterAbEcdsaDerivationClientSigningMaterialSource['destroyClientPresignature']> {
    await thresholdEcdsaRoleLocalDestroyPresignatureWasm(input);
  }

  async reserveClientPresignature(
    input: Parameters<
      RouterAbEcdsaDerivationClientSigningMaterialSource['reserveClientPresignature']
    >[0],
  ): ReturnType<RouterAbEcdsaDerivationClientSigningMaterialSource['reserveClientPresignature']> {
    await thresholdEcdsaRoleLocalReservePresignatureWasm(input);
  }

  async commitClientPresignature(
    input: Parameters<
      RouterAbEcdsaDerivationClientSigningMaterialSource['commitClientPresignature']
    >[0],
  ): ReturnType<RouterAbEcdsaDerivationClientSigningMaterialSource['commitClientPresignature']> {
    await thresholdEcdsaRoleLocalCommitPresignatureWasm(input);
  }

  async listAvailableClientPresignatures(
    input: Parameters<
      RouterAbEcdsaDerivationClientSigningMaterialSource['listAvailableClientPresignatures']
    >[0],
  ): ReturnType<
    RouterAbEcdsaDerivationClientSigningMaterialSource['listAvailableClientPresignatures']
  > {
    return await thresholdEcdsaRoleLocalListAvailablePresignaturesWasm(input);
  }

  async retireClientPresignaturePool(
    input: Parameters<
      RouterAbEcdsaDerivationClientSigningMaterialSource['retireClientPresignaturePool']
    >[0],
  ): ReturnType<
    RouterAbEcdsaDerivationClientSigningMaterialSource['retireClientPresignaturePool']
  > {
    return await thresholdEcdsaRoleLocalRetirePresignaturePoolWasm(input);
  }

  async computeSignatureShareFromPresignatureHandle(
    input: Parameters<
      RouterAbEcdsaDerivationClientSigningMaterialSource['computeSignatureShareFromPresignatureHandle']
    >[0],
  ): ReturnType<
    RouterAbEcdsaDerivationClientSigningMaterialSource['computeSignatureShareFromPresignatureHandle']
  > {
    return await thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm(input);
  }

  async cleanupAfterSign(): Promise<void> {
    await this.holderMaterial.discardHolderSigningMaterialV1({ handle: this.handle });
  }
}
