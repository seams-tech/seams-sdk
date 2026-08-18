import type { IdentityStore, LinkIdentityResult, UnlinkIdentityResult } from '../IdentityStore';
import {
  linkIdentityWithStore,
  listIdentitiesWithStore,
  unlinkIdentityWithStore,
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

}
