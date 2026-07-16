/**
 * Device metadata captured when a WebAuthn credential is registered.
 *
 * Derived once, server-side, at registration verification time from three
 * sources the router already receives:
 * - the `User-Agent` header of the registration request (browser/os),
 * - the verified attestation (AAGUID -> passkey provider, BE flag -> synced),
 * - the credential response transports.
 *
 * Stored on the authenticator row and returned by the authenticators listing
 * so profile UIs can label signers ("Chrome on macOS", "iCloud Keychain").
 */

export type WebAuthnDeviceBrowser = 'chrome' | 'safari' | 'firefox' | 'edge' | 'other';

export type WebAuthnDeviceOs = 'macos' | 'ios' | 'windows' | 'android' | 'linux' | 'other';

export type WebAuthnAuthenticatorDeviceInfo = {
  /** Display-ready label, e.g. "Chrome on macOS". Never empty. */
  label: string;
  browser: WebAuthnDeviceBrowser;
  os: WebAuthnDeviceOs;
  /** BE (backup eligible) flag: true for synced passkeys (iCloud Keychain, GPM). */
  synced: boolean;
  /** Credential response transports, e.g. ["internal"], ["hybrid"]. */
  transports: string[];
  /** Passkey provider id from the AAGUID map, when the AAGUID is known. */
  provider?: string;
  /** Display name for the provider, e.g. "iCloud Keychain". */
  providerLabel?: string;
};

/** Community-documented AAGUIDs for the passkey providers that matter here.
 * Source: github.com/passkeydeveloper/passkey-authenticator-aaguids */
const WEBAUTHN_AAGUID_PROVIDERS: Record<string, { id: string; label: string }> = {
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': { id: 'icloud-keychain', label: 'iCloud Keychain' },
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': {
    id: 'icloud-keychain-managed',
    label: 'iCloud Keychain (Managed)',
  },
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': {
    id: 'google-password-manager',
    label: 'Google Password Manager',
  },
  'adce0002-35bc-c60a-648b-0b25f1f05503': { id: 'chrome-on-mac', label: 'Chrome on Mac' },
  '08987058-cadc-4b81-b6e1-30de50dcbe96': { id: 'windows-hello', label: 'Windows Hello' },
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': { id: 'windows-hello', label: 'Windows Hello' },
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': { id: 'windows-hello', label: 'Windows Hello' },
  'bada5566-a7aa-401f-bd96-45619a55120d': { id: '1password', label: '1Password' },
  'd548826e-79b4-db40-a3d8-11116f7e8349': { id: 'bitwarden', label: 'Bitwarden' },
  '531126d6-e717-415c-9320-3d9aa6981239': { id: 'dashlane', label: 'Dashlane' },
  '53414d53-554e-4700-0000-000000000000': { id: 'samsung-pass', label: 'Samsung Pass' },
  'b84e4048-15dc-4dd0-8640-f4f60813c8af': { id: 'nordpass', label: 'NordPass' },
  'f3809540-7f14-49c1-a8b3-8f813b225541': { id: 'enpass', label: 'Enpass' },
  'b5397666-4885-aa6b-cebf-e52262a439a2': { id: 'chromium', label: 'Chromium Browser' },
  '771b48fd-d3d4-4f74-9232-fc157ab0507a': { id: 'edge-on-mac', label: 'Edge on Mac' },
};

const WEBAUTHN_DEVICE_BROWSERS: readonly WebAuthnDeviceBrowser[] = [
  'chrome',
  'safari',
  'firefox',
  'edge',
  'other',
];

const WEBAUTHN_DEVICE_OSES: readonly WebAuthnDeviceOs[] = [
  'macos',
  'ios',
  'windows',
  'android',
  'linux',
  'other',
];

const BROWSER_DISPLAY: Record<WebAuthnDeviceBrowser, string> = {
  chrome: 'Chrome',
  safari: 'Safari',
  firefox: 'Firefox',
  edge: 'Edge',
  other: 'Browser',
};

const OS_DISPLAY: Record<WebAuthnDeviceOs, string> = {
  macos: 'macOS',
  ios: 'iOS',
  windows: 'Windows',
  android: 'Android',
  linux: 'Linux',
  other: '',
};

export function webAuthnDeviceBrowserFromUserAgent(userAgent: string): WebAuthnDeviceBrowser {
  const ua = userAgent.toLowerCase();
  if (!ua) return 'other';
  // Order matters: Edge and Chrome both contain "chrome"; everything on iOS
  // contains "safari".
  if (ua.includes('edg/') || ua.includes('edge/') || ua.includes('edgios/')) return 'edge';
  if (ua.includes('firefox/') || ua.includes('fxios/')) return 'firefox';
  if (ua.includes('crios/') || ua.includes('chrome/') || ua.includes('chromium/')) return 'chrome';
  if (ua.includes('safari/')) return 'safari';
  return 'other';
}

export function webAuthnDeviceOsFromUserAgent(userAgent: string): WebAuthnDeviceOs {
  const ua = userAgent.toLowerCase();
  if (!ua) return 'other';
  // iPad Safari masquerades as macOS; genuine iPadOS UAs contain "ipad".
  if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ipod')) return 'ios';
  if (ua.includes('android')) return 'android';
  if (ua.includes('mac os x') || ua.includes('macintosh')) return 'macos';
  if (ua.includes('windows')) return 'windows';
  if (ua.includes('linux') || ua.includes('cros')) return 'linux';
  return 'other';
}

function webAuthnDeviceLabel(input: {
  browser: WebAuthnDeviceBrowser;
  os: WebAuthnDeviceOs;
  providerLabel?: string;
}): string {
  const browser = BROWSER_DISPLAY[input.browser];
  const os = OS_DISPLAY[input.os];
  if (input.browser === 'other' && input.os === 'other') {
    return input.providerLabel || 'Unknown device';
  }
  return os ? `${browser} on ${os}` : browser;
}

function normalizedAaguid(aaguid: string): string {
  return aaguid.trim().toLowerCase();
}

/** True for the all-zero AAGUID some platforms report under attestation "none". */
function isZeroAaguid(aaguid: string): boolean {
  return /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(aaguid) || aaguid === '';
}

export function deriveWebAuthnAuthenticatorDeviceInfo(input: {
  userAgent?: string;
  aaguid?: string;
  backedUp?: boolean;
  transports?: readonly string[];
}): WebAuthnAuthenticatorDeviceInfo {
  const userAgent = String(input.userAgent || '').trim();
  const browser = webAuthnDeviceBrowserFromUserAgent(userAgent);
  const os = webAuthnDeviceOsFromUserAgent(userAgent);
  const aaguid = normalizedAaguid(String(input.aaguid || ''));
  const providerEntry = isZeroAaguid(aaguid) ? undefined : WEBAUTHN_AAGUID_PROVIDERS[aaguid];
  const transports = Array.isArray(input.transports)
    ? input.transports.map((t) => String(t || '').trim()).filter((t) => t.length > 0)
    : [];
  return {
    label: webAuthnDeviceLabel({ browser, os, providerLabel: providerEntry?.label }),
    browser,
    os,
    synced: !!input.backedUp,
    transports,
    ...(providerEntry ? { provider: providerEntry.id, providerLabel: providerEntry.label } : {}),
  };
}

/** Fallback for authenticator rows written before device capture existed. */
export function unknownWebAuthnAuthenticatorDeviceInfo(): WebAuthnAuthenticatorDeviceInfo {
  return {
    label: 'Unknown device',
    browser: 'other',
    os: 'other',
    synced: false,
    transports: [],
  };
}

function isWebAuthnDeviceBrowser(value: unknown): value is WebAuthnDeviceBrowser {
  return typeof value === 'string' && WEBAUTHN_DEVICE_BROWSERS.includes(value as never);
}

function isWebAuthnDeviceOs(value: unknown): value is WebAuthnDeviceOs {
  return typeof value === 'string' && WEBAUTHN_DEVICE_OSES.includes(value as never);
}

/** Strict parse of a stored/transported device-info record; null when the
 * shape is not a valid WebAuthnAuthenticatorDeviceInfo. */
export function parseWebAuthnAuthenticatorDeviceInfo(
  raw: unknown,
): WebAuthnAuthenticatorDeviceInfo | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const label = typeof record.label === 'string' ? record.label.trim() : '';
  if (!label) return null;
  if (!isWebAuthnDeviceBrowser(record.browser)) return null;
  if (!isWebAuthnDeviceOs(record.os)) return null;
  if (typeof record.synced !== 'boolean') return null;
  if (!Array.isArray(record.transports)) return null;
  const transports = record.transports
    .map((t) => (typeof t === 'string' ? t.trim() : ''))
    .filter((t) => t.length > 0);
  const provider = typeof record.provider === 'string' ? record.provider.trim() : '';
  const providerLabel =
    typeof record.providerLabel === 'string' ? record.providerLabel.trim() : '';
  return {
    label,
    browser: record.browser,
    os: record.os,
    synced: record.synced,
    transports,
    ...(provider ? { provider } : {}),
    ...(providerLabel ? { providerLabel } : {}),
  };
}
