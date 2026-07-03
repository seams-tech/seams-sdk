import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { IdentityStore, LinkIdentityResult, UnlinkIdentityResult } from '../IdentityStore';

export type ListIdentitiesResult =
  | { ok: true; subjects: string[] }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string };

export type AppSessionVersionMutationResult =
  | { ok: true; appSessionVersion: string }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string };

export type AppSessionVersionValidationResult =
  | { ok: true }
  | {
      ok: false;
      code: 'invalid_session_version' | 'unauthorized' | 'internal';
      message: string;
    };

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

export async function getOrCreateAppSessionVersionWithStore(input: {
  readonly store: IdentityStore;
  readonly userId: string;
}): Promise<AppSessionVersionMutationResult> {
  try {
    const userId = toOptionalTrimmedString(input.userId);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    return {
      ok: true,
      appSessionVersion: await input.store.ensureAppSessionVersionByUserId(userId),
    };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to ensure app session version',
    };
  }
}

export async function rotateAppSessionVersionWithStore(input: {
  readonly store: IdentityStore;
  readonly userId: string;
}): Promise<AppSessionVersionMutationResult> {
  try {
    const userId = toOptionalTrimmedString(input.userId);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    return {
      ok: true,
      appSessionVersion: await input.store.rotateAppSessionVersionByUserId(userId),
    };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to rotate app session version',
    };
  }
}

export async function validateAppSessionVersionWithStore(input: {
  readonly store: IdentityStore;
  readonly userId: string;
  readonly appSessionVersion: string;
}): Promise<AppSessionVersionValidationResult> {
  try {
    const userId = toOptionalTrimmedString(input.userId);
    const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
    if (!userId || !appSessionVersion) {
      return { ok: false, code: 'unauthorized', message: 'Invalid app session' };
    }
    const current = await input.store.getAppSessionVersionByUserId(userId);
    if (!current || current !== appSessionVersion) {
      return { ok: false, code: 'invalid_session_version', message: 'App session revoked' };
    }
    return { ok: true };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to validate app session version',
    };
  }
}
