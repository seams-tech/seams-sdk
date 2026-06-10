import type { DashboardConsoleSessionClaims } from '../consoleSession';

export interface DashboardIdentitySource {
  userId?: string | null;
  email?: string | null;
  displayName?: string | null;
}

function readIdentityUserId(identity: DashboardIdentitySource): string {
  return String(identity.userId || '').trim();
}

export function isConsoleLocalEmail(value: string): boolean {
  return String(value || '')
    .trim()
    .toLowerCase()
    .endsWith('@console.local');
}

export function resolveDashboardIdentityEmail(
  identity: DashboardIdentitySource,
  sessionClaims?: DashboardConsoleSessionClaims | null,
): string {
  const email = String(identity.email || '').trim();
  const userId = readIdentityUserId(identity);
  const sessionUserId = String(sessionClaims?.userId || '').trim();
  const sessionEmail = String(sessionClaims?.email || '').trim();
  if (sessionUserId && sessionEmail && userId === sessionUserId && isConsoleLocalEmail(email)) {
    return sessionEmail;
  }
  return email;
}

export function resolveDashboardIdentityDisplayName(
  identity: DashboardIdentitySource,
  sessionClaims?: DashboardConsoleSessionClaims | null,
): string {
  const displayName = String(identity.displayName || '').trim();
  if (displayName) return displayName;
  const userId = readIdentityUserId(identity);
  const sessionUserId = String(sessionClaims?.userId || '').trim();
  const sessionName = String(sessionClaims?.name || '').trim();
  if (sessionUserId && sessionName && userId === sessionUserId) {
    return sessionName;
  }
  return '';
}

export function resolveDashboardIdentityPrimaryLabel(
  identity: DashboardIdentitySource,
  sessionClaims?: DashboardConsoleSessionClaims | null,
): string {
  const displayName = resolveDashboardIdentityDisplayName(identity, sessionClaims);
  if (displayName) return displayName;
  const email = resolveDashboardIdentityEmail(identity, sessionClaims);
  if (email) return email;
  const userId = readIdentityUserId(identity);
  return userId || '-';
}

export function buildDashboardIdentityProfile(
  identity: DashboardIdentitySource,
  sessionClaims?: DashboardConsoleSessionClaims | null,
): {
  title: string;
  subtitle: string;
  detail: string;
} {
  const displayName = resolveDashboardIdentityDisplayName(identity, sessionClaims);
  const email = resolveDashboardIdentityEmail(identity, sessionClaims);
  const userId = readIdentityUserId(identity);
  const normalizedDisplayName = displayName.toLowerCase();
  const normalizedEmail = email.toLowerCase();
  const normalizedUserId = userId.toLowerCase();
  const title = displayName || email || userId || '-';

  if (!displayName) {
    const nextLine =
      email && email !== title
        ? email
        : userId && normalizedUserId !== title.toLowerCase()
          ? userId
          : '';
    return {
      title,
      detail: nextLine,
      subtitle: '',
    };
  }

  const detail =
    email && normalizedEmail !== normalizedDisplayName
      ? email
      : userId && normalizedUserId !== normalizedDisplayName
        ? userId
        : '';
  const subtitle =
    userId &&
    normalizedUserId !== normalizedDisplayName &&
    normalizedUserId !== normalizedEmail &&
    userId !== detail
      ? userId
      : '';
  return {
    title,
    detail,
    subtitle,
  };
}
