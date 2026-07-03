import type { IdentityStore, LinkIdentityResult, UnlinkIdentityResult } from '../IdentityStore';
import {
  getOrCreateAppSessionVersionWithStore,
  linkIdentityWithStore,
  listIdentitiesWithStore,
  rotateAppSessionVersionWithStore,
  unlinkIdentityWithStore,
  validateAppSessionVersionWithStore,
  type AppSessionVersionMutationResult,
  type AppSessionVersionValidationResult,
  type ListIdentitiesResult,
} from './identity';

export class IdentityOperations {
  constructor(private readonly store: IdentityStore) {}

  async listIdentities(input: { userId: string }): Promise<ListIdentitiesResult> {
    return await listIdentitiesWithStore({
      store: this.store,
      userId: input.userId,
    });
  }

  async linkIdentity(input: {
    userId: string;
    subject: string;
    allowMoveIfSoleIdentity?: boolean;
  }): Promise<LinkIdentityResult> {
    return await linkIdentityWithStore({
      store: this.store,
      userId: input.userId,
      subject: input.subject,
      allowMoveIfSoleIdentity: Boolean(input.allowMoveIfSoleIdentity),
    });
  }

  async unlinkIdentity(input: { userId: string; subject: string }): Promise<UnlinkIdentityResult> {
    return await unlinkIdentityWithStore({
      store: this.store,
      userId: input.userId,
      subject: input.subject,
    });
  }

  async getOrCreateAppSessionVersion(input: {
    userId: string;
  }): Promise<AppSessionVersionMutationResult> {
    return await getOrCreateAppSessionVersionWithStore({
      store: this.store,
      userId: input.userId,
    });
  }

  async rotateAppSessionVersion(input: { userId: string }): Promise<AppSessionVersionMutationResult> {
    return await rotateAppSessionVersionWithStore({
      store: this.store,
      userId: input.userId,
    });
  }

  async validateAppSessionVersion(input: {
    userId: string;
    appSessionVersion: string;
  }): Promise<AppSessionVersionValidationResult> {
    return await validateAppSessionVersionWithStore({
      store: this.store,
      userId: input.userId,
      appSessionVersion: input.appSessionVersion,
    });
  }
}
