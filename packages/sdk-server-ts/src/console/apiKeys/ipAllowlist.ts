function parseIpv4ToInt(raw: string): number | null {
  const text = String(raw || '').trim();
  if (!text) return null;
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    value = (value << 8) | octet;
  }
  return value >>> 0;
}

function ipv4CidrContains(input: { cidr: string; ip: string }): boolean {
  const trimmed = String(input.cidr || '').trim();
  const slash = trimmed.indexOf('/');
  if (slash <= 0) return false;
  const base = trimmed.slice(0, slash).trim();
  const bitsRaw = trimmed.slice(slash + 1).trim();
  if (!/^\d+$/.test(bitsRaw)) return false;
  const bits = Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const baseInt = parseIpv4ToInt(base);
  const ipInt = parseIpv4ToInt(input.ip);
  if (baseInt == null || ipInt == null) return false;
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0;
  return (baseInt & mask) === (ipInt & mask);
}

export function isIpAllowlistMatch(input: {
  allowlist: string[];
  sourceIp?: string;
}): boolean {
  if (!input.allowlist.length) return true;
  const sourceIp = normalizeSourceIp(input.sourceIp);
  if (!sourceIp) return false;
  const sourceLower = sourceIp.toLowerCase();
  for (const entryRaw of input.allowlist) {
    const entry = String(entryRaw || '').trim();
    if (!entry) continue;
    if (entry.includes('/')) {
      if (ipv4CidrContains({ cidr: entry, ip: sourceIp })) return true;
      continue;
    }
    if (entry.toLowerCase() === sourceLower) return true;
  }
  return false;
}
import { normalizeSourceIp } from '../../router/routerApiKeyAuth';
