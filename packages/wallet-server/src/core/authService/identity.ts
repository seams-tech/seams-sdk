import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { IdentityStore, LinkIdentityResult, UnlinkIdentityResult } from '../IdentityStore';

export type ListIdentitiesResult =
  | { ok: true; subjects: string[] }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string };

export async function listIdentitiesWithStore(input: {
  readonly store: IdentityStore;
  readonly userId: string;
}): Promise<ListIdentitiesResult> {
  try {
    const userId = toOptionalTrimmedString(input.userId);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    return { ok: true, subjects: await input.store.listSubjectsByUserId(userId) };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to list identities',
    };
  }
}

export async function linkIdentityWithStore(input: {
  readonly store: IdentityStore;
  readonly userId: string;
  readonly subject: string;
  readonly allowMoveIfSoleIdentity: boolean;
}): Promise<LinkIdentityResult> {
  try {
    return await input.store.linkSubjectToUserId({
      userId: input.userId,
      subject: input.subject,
      allowMoveIfSoleIdentity: input.allowMoveIfSoleIdentity,
    });
  } catch (e: unknown) {
    return { ok: false, code: 'internal', message: errorMessage(e) || 'Failed to link identity' };
  }
}

export async function unlinkIdentityWithStore(input: {
  readonly store: IdentityStore;
  readonly userId: string;
  readonly subject: string;
}): Promise<UnlinkIdentityResult> {
  try {
    return await input.store.unlinkSubjectFromUserId({
      userId: input.userId,
      subject: input.subject,
    });
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to unlink identity',
    };
  }
}
