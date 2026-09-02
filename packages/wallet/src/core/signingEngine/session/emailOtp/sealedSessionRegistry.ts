import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ExactWalletSessionAuthorization } from '../persistence/walletSessionAuthorizationProjection';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  buildCurrentSealedSessionRecord,
  type BuildCurrentSealedSessionRecordInput,
  type readExactSealedSession,
  type writeExactSealedSession,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  persistEmailOtpEcdsaSigningSessionForRefresh,
  type EmailOtpEcdsaPublicationPorts,
} from './ecdsaPublication';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

export class EmailOtpSealedSessionRegistry {
  constructor(
    private readonly ports: {
      configs: SeamsConfigsReadonly;
      getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
      commitEvmFamilyThresholdEcdsaSessions: (args: {
        walletId: WalletId;
        chainTarget: ThresholdEcdsaChainTarget;
        bootstrap: ThresholdEcdsaSessionBootstrapResult;
        source: 'email_otp';
        authority: WalletAuthAuthorityRef;
        emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      }) => Promise<{
        bootstrap: ThresholdEcdsaSessionBootstrapResult;
        authorization: ExactWalletSessionAuthorization;
      }>;
      writeExactSealedSession: typeof writeExactSealedSession;
      readExactSealedSession: typeof readExactSealedSession;
      listActiveEcdsaCapabilityManifestsForWallet: EmailOtpEcdsaPublicationPorts['listActiveEcdsaCapabilityManifestsForWallet'];
      clearEcdsaRestoreCaches: () => void;
    },
  ) {}

  async registerSigningSession(record: BuildCurrentSealedSessionRecordInput): Promise<void> {
    const currentRecord = buildCurrentSealedSessionRecord(record);
    if (!currentRecord) {
      throw new Error('[SigningSessionSealedStore] invalid sealed session record write input');
    }
    await this.ports.writeExactSealedSession(currentRecord);
    this.ports.clearEcdsaRestoreCaches();
  }

  ecdsaPublicationPorts(): EmailOtpEcdsaPublicationPorts {
    return {
      configs: this.ports.configs,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      commitEvmFamilyThresholdEcdsaSessions: this.ports.commitEvmFamilyThresholdEcdsaSessions,
      registerSigningSession: (record) => this.registerSigningSession(record),
      readExactSealedSession: this.ports.readExactSealedSession,
      listActiveEcdsaCapabilityManifestsForWallet:
        this.ports.listActiveEcdsaCapabilityManifestsForWallet,
    };
  }

  async persistEcdsaSessionForRefresh(args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    runtimePolicyScope: Parameters<
      typeof persistEmailOtpEcdsaSigningSessionForRefresh
    >[0]['runtimePolicyScope'];
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  }): Promise<void> {
    await persistEmailOtpEcdsaSigningSessionForRefresh(
      {
        walletId: args.walletId,
        chainTarget: args.chainTarget,
        bootstrap: args.bootstrap,
        runtimePolicyScope: args.runtimePolicyScope,
        emailOtpAuthContext: args.emailOtpAuthContext,
        relayerUrl: this.ports.configs.network.relayer?.url || '',
        groupId: SIGNING_SESSION_SEAL_GROUP_ID,
      },
      this.ecdsaPublicationPorts(),
    );
  }
}
