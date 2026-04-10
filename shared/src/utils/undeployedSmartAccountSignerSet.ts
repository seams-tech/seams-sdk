export type UndeployedSmartAccountSignerStatus = 'active' | 'pending';

export type UndeployedSmartAccountSigner = {
  signerId: string;
  signerType: string;
  status: UndeployedSmartAccountSignerStatus;
  deviceNumber?: number;
  relayerKeyId?: string;
  thresholdEcdsaPublicKeyB64u?: string;
  participantIds?: number[];
  credentialIdB64u?: string;
  rpId?: string;
};

export type UndeployedSmartAccountSignerSet = {
  version: 'undeployed_smart_account_signer_set_v1';
  ownerAddresses: string[];
  activeOwnerAddresses: string[];
  pendingOwnerAddresses: string[];
  owners: UndeployedSmartAccountSigner[];
};
