import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  buildCurrentSealedSessionRecord,
  type BuildCurrentSealedSessionRecordInput,
  type readExactEd25519SealedSession,
  type readExactSealedSession,
  type writeExactSealedSession,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  persistEmailOtpEcdsaSigningSessionForRefresh,
  type EmailOtpEcdsaPublicationPorts,
} from './ecdsaPublication';
import {
  persistEmailOtpEd25519YaoCapabilityForRefresh,
  type EmailOtpEd25519YaoPublicationPorts,
} from './ed25519YaoPublication';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';

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
        emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      }) => Promise<{
        bootstrap: ThresholdEcdsaSessionBootstrapResult;
        authorization: ActiveWalletSessionAuthorizationProjection;
      }>;
      writeExactSealedSession: typeof writeExactSealedSession;
      readExactEd25519SealedSession: typeof readExactEd25519SealedSession;
      readExactSealedSession: typeof readExactSealedSession;
      listActiveEcdsaCapabilityManifestsForWallet: EmailOtpEcdsaPublicationPorts['listActiveEcdsaCapabilityManifestsForWallet'];
      clearEcdsaRestoreCaches: () => void;
    },
  ) {}

  async registerSigningSession(
    record: BuildCurrentSealedSessionRecordInput,
  ): Promise<void> {
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
      commitEvmFamilyThresholdEcdsaSessions:
        this.ports.commitEvmFamilyThresholdEcdsaSessions,
      registerSigningSession: (record) => this.registerSigningSession(record),
      readExactSealedSession: this.ports.readExactSealedSession,
      listActiveEcdsaCapabilityManifestsForWallet:
        this.ports.listActiveEcdsaCapabilityManifestsForWallet,
    };
  }

  async persistEd25519YaoCapabilityForRefresh(
    args: Parameters<typeof persistEmailOtpEd25519YaoCapabilityForRefresh>[0],
  ): Promise<void> {
    await persistEmailOtpEd25519YaoCapabilityForRefresh(args, this.ed25519YaoPublicationPorts());
  }

  async persistEcdsaSessionForRefresh(args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    runtimePolicyScope: Parameters<typeof persistEmailOtpEcdsaSigningSessionForRefresh>[0]['runtimePolicyScope'];
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

  private ed25519YaoPublicationPorts(): EmailOtpEd25519YaoPublicationPorts {
    return {
      configs: this.ports.configs,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      registerSigningSession: (record) => this.registerSigningSession(record),
      readExactEd25519SealedSession: this.ports.readExactEd25519SealedSession,
    };
  }
}
