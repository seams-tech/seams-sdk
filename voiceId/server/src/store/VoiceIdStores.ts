import type {
  VoiceIdEnrollmentRecord,
  VoiceIdVerificationRecord,
} from '../../../shared/src/records.ts';
import type {
  UserId,
  VoiceIdEnrollmentId,
  VoiceIdVerificationId,
} from '../../../shared/src/ids.ts';

export type VoiceIdEnrollmentStore = {
  getByUserId(userId: UserId): Promise<VoiceIdEnrollmentRecord | null>;
  getByEnrollmentId(enrollmentId: VoiceIdEnrollmentId): Promise<VoiceIdEnrollmentRecord | null>;
  create(record: Extract<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }>): Promise<boolean>;
  claimPending(record: Extract<VoiceIdEnrollmentRecord, { state: 'analyzing_continuous_recording' }>): Promise<boolean>;
  failPending(record: Extract<VoiceIdEnrollmentRecord, { state: 'failed' }>): Promise<boolean>;
  completeAnalysis(record: Extract<VoiceIdEnrollmentRecord, { state: 'failed' | 'enrolled' }>): Promise<boolean>;
  disable(record: Extract<VoiceIdEnrollmentRecord, { state: 'disabled' }>): Promise<boolean>;
};

export type VoiceIdVerificationStore = {
  getByVerificationId(verificationId: VoiceIdVerificationId): Promise<VoiceIdVerificationRecord | null>;
  create(record: Extract<VoiceIdVerificationRecord, { state: 'issued' }>): Promise<boolean>;
  claimIssued(record: Extract<VoiceIdVerificationRecord, { state: 'analyzing' }>): Promise<boolean>;
  expireIssued(record: Extract<VoiceIdVerificationRecord, { state: 'expired' }>): Promise<boolean>;
  completeAnalysis(record: Extract<VoiceIdVerificationRecord, { state: 'evidence_observed' | 'rejected' | 'uncertain' | 'analysis_failed' }>): Promise<boolean>;
};

export class InMemoryVoiceIdEnrollmentStore implements VoiceIdEnrollmentStore {
  private readonly byUserId = new Map<UserId, VoiceIdEnrollmentRecord>();
  private readonly byEnrollmentId = new Map<VoiceIdEnrollmentId, VoiceIdEnrollmentRecord>();

  async getByUserId(userId: UserId): Promise<VoiceIdEnrollmentRecord | null> {
    return this.byUserId.get(userId) ?? null;
  }

  async getByEnrollmentId(enrollmentId: VoiceIdEnrollmentId): Promise<VoiceIdEnrollmentRecord | null> {
    return this.byEnrollmentId.get(enrollmentId) ?? null;
  }

  async create(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }>,
  ): Promise<boolean> {
    if (this.byEnrollmentId.has(record.enrollmentId)) return false;
    this.byUserId.set(record.userId, record);
    this.byEnrollmentId.set(record.enrollmentId, record);
    return true;
  }

  async claimPending(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'analyzing_continuous_recording' }>,
  ): Promise<boolean> {
    return this.transition(record, 'pending_continuous_recording');
  }

  async failPending(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'failed' }>,
  ): Promise<boolean> {
    return this.transition(record, 'pending_continuous_recording');
  }

  async completeAnalysis(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'failed' | 'enrolled' }>,
  ): Promise<boolean> {
    return this.transition(record, 'analyzing_continuous_recording');
  }

  private transition(
    record: Exclude<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }>,
    expectedState: 'pending_continuous_recording' | 'analyzing_continuous_recording',
  ): boolean {
    const current = this.byEnrollmentId.get(record.enrollmentId);
    if (
      current?.state !== expectedState
      || current.userId !== record.userId
    ) return false;
    this.byUserId.set(record.userId, record);
    this.byEnrollmentId.set(record.enrollmentId, record);
    return true;
  }

  async disable(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'disabled' }>,
  ): Promise<boolean> {
    const current = this.byEnrollmentId.get(record.enrollmentId);
    if (current?.state !== 'enrolled' || current.userId !== record.userId) return false;
    this.byUserId.set(record.userId, record);
    this.byEnrollmentId.set(record.enrollmentId, record);
    return true;
  }
}

export class InMemoryVoiceIdVerificationStore implements VoiceIdVerificationStore {
  private readonly byVerificationId = new Map<VoiceIdVerificationId, VoiceIdVerificationRecord>();

  async getByVerificationId(verificationId: VoiceIdVerificationId): Promise<VoiceIdVerificationRecord | null> {
    return this.byVerificationId.get(verificationId) ?? null;
  }

  async create(
    record: Extract<VoiceIdVerificationRecord, { state: 'issued' }>,
  ): Promise<boolean> {
    if (this.byVerificationId.has(record.verificationId)) return false;
    this.byVerificationId.set(record.verificationId, record);
    return true;
  }

  async claimIssued(
    record: Extract<VoiceIdVerificationRecord, { state: 'analyzing' }>,
  ): Promise<boolean> {
    return this.transition(record, 'issued');
  }

  async expireIssued(
    record: Extract<VoiceIdVerificationRecord, { state: 'expired' }>,
  ): Promise<boolean> {
    return this.transition(record, 'issued');
  }

  async completeAnalysis(
    record: Extract<VoiceIdVerificationRecord, { state: 'evidence_observed' | 'rejected' | 'uncertain' | 'analysis_failed' }>,
  ): Promise<boolean> {
    return this.transition(record, 'analyzing');
  }

  private transition(
    record: Exclude<VoiceIdVerificationRecord, { state: 'issued' }>,
    expectedState: 'issued' | 'analyzing',
  ): boolean {
    const current = this.byVerificationId.get(record.verificationId);
    if (
      current?.state !== expectedState
      || current.userId !== record.userId
      || current.enrollmentId !== record.enrollmentId
    ) return false;
    this.byVerificationId.set(record.verificationId, record);
    return true;
  }
}
