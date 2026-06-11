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
  save(record: VoiceIdEnrollmentRecord): Promise<void>;
};

export type VoiceIdVerificationStore = {
  getByVerificationId(verificationId: VoiceIdVerificationId): Promise<VoiceIdVerificationRecord | null>;
  save(record: VoiceIdVerificationRecord): Promise<void>;
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

  async save(record: VoiceIdEnrollmentRecord): Promise<void> {
    this.byUserId.set(record.userId, record);
    this.byEnrollmentId.set(record.enrollmentId, record);
  }
}

export class InMemoryVoiceIdVerificationStore implements VoiceIdVerificationStore {
  private readonly byVerificationId = new Map<VoiceIdVerificationId, VoiceIdVerificationRecord>();

  async getByVerificationId(verificationId: VoiceIdVerificationId): Promise<VoiceIdVerificationRecord | null> {
    return this.byVerificationId.get(verificationId) ?? null;
  }

  async save(record: VoiceIdVerificationRecord): Promise<void> {
    this.byVerificationId.set(record.verificationId, record);
  }
}
