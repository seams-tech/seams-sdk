import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const MAX_BUNDLE_BYTES = 256 * 1024;
const BUNDLE_PATH = fileURLToPath(
  new URL('../docs/phase13a-local-preflight-evidence-v1.json', import.meta.url),
);

export function loadLocalReadinessBundle() {
  const size = statSync(BUNDLE_PATH).size;
  if (size <= 0 || size > MAX_BUNDLE_BYTES) {
    throw new Error('local-readiness evidence bundle has an invalid size');
  }
  const bytes = readFileSync(BUNDLE_PATH);
  let evidence;
  try {
    evidence = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('local-readiness evidence bundle is not valid JSON');
  }
  return Object.freeze({
    evidence,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  });
}
