import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
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
import {
  persistEmailOtpEd25519YaoSessionForRefresh,
  type EmailOtpEd25519YaoPublicationPorts,
} from './ed25519YaoPublication';
import type { ThresholdEd25519SessionRecord } from '../persistence/records';

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
        warmCapability: WarmSessionEcdsaCapabilityState;
      }>;
      writeExactSealedSession: typeof writeExactSealedSession;
      readExactSealedSession: typeof readExactSealedSession;
      listThresholdEcdsaSessionRecordsForWallet: EmailOtpEcdsaPublicationPorts['listThresholdEcdsaSessionRecordsForWallet'];
      listActiveEcdsaSignersForWallet: EmailOtpEcdsaPublicationPorts['listActiveEcdsaSignersForWallet'];
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
      listThresholdEcdsaSessionRecordsForWallet:
        this.ports.listThresholdEcdsaSessionRecordsForWallet,
      listActiveEcdsaSignersForWallet: this.ports.listActiveEcdsaSignersForWallet,
    };
  }

  async persistEd25519YaoSessionForRefresh(args: {
    record: ThresholdEd25519SessionRecord;
    rpId: string;
  }): Promise<void> {
    await persistEmailOtpEd25519YaoSessionForRefresh(args, this.ed25519YaoPublicationPorts());
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
        shamirPrimeB64u: this.ports.configs.signing.sessionSeal?.shamirPrimeB64u || '',
      },
      this.ecdsaPublicationPorts(),
    );
  }

  private ed25519YaoPublicationPorts(): EmailOtpEd25519YaoPublicationPorts {
    return {
      configs: this.ports.configs,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      registerSigningSession: (record) => this.registerSigningSession(record),
      readExactSealedSession: this.ports.readExactSealedSession,
    };
  }
}
