export type RecoverySubjectBinding = {
  nearAccountId: string;
  recoverySessionId: string;
  deadlineEpochSeconds: number;
  scope?: string;
};

export type RecoveryTargetKeySet = {
  newNearPublicKey: string;
  newEvmOwnerAddress: string;
};

export type MultichainRecoveryPayloadFields = RecoverySubjectBinding & RecoveryTargetKeySet;
