import { readFile } from 'node:fs/promises';

const checks = [
  {
    filePath: 'deploy/robot-local/sidecar/README.md',
    required: [
      { name: 'robot-local scope', pattern: /robot-local/i },
      { name: 'Reachy example', pattern: /Reachy/ },
      { name: 'robot app boundary', pattern: /reachy_app\.py/ },
      { name: 'wallet sidecar boundary', pattern: /wallet_sidecar/ },
      { name: 'same Python HTTP verifier API', pattern: /same Python HTTP verifier API/ },
      { name: 'python-http transport', pattern: /VOICEID_VERIFIER_TRANSPORT=python-http/ },
      { name: 'localhost verifier URL', pattern: /VOICEID_PYTHON_VERIFIER_URL=http:\/\/127\.0\.0\.1:5051\/voice-id\/verifier\// },
      { name: 'verifier sidecar backend', pattern: /VOICEID_VERIFIER_BACKEND=ecapa/ },
      { name: 'microphone capture', pattern: /microphone/ },
      { name: 'source attestation', pattern: /source attestation/ },
      { name: 'owner presence evidence', pattern: /ownerPresence/ },
      { name: 'intent digest binding', pattern: /intentDigest/ },
      { name: 'liveness result', pattern: /liveness/ },
      { name: 'raw audio retention boundary', pattern: /Raw audio stays local/ },
      { name: 'verifier extract endpoint', pattern: /extract-enrollment-embedding/ },
      { name: 'verifier build endpoint', pattern: /build-template/ },
      { name: 'verifier verify endpoint', pattern: /verify-speaker/ },
      { name: 'Router A/B boundary', pattern: /Router A\/B/ },
      { name: 'SigningWorker boundary', pattern: /SigningWorker/ },
    ],
  },
  {
    filePath: 'deploy/cloudflare/verifier-container/Dockerfile',
    required: [
      { name: 'generic bind host', pattern: /VOICEID_VERIFIER_HOST=0\.0\.0\.0/ },
      { name: 'HTTP verifier command', pattern: /voiceid_verifier\.app", "serve_http/ },
    ],
  },
];

const failures = [];

for (const check of checks) {
  const content = await readFile(check.filePath, 'utf8');
  for (const required of check.required) {
    if (!required.pattern.test(content)) {
      failures.push(`${check.filePath}: missing ${required.name}`);
    }
  }
}

if (failures.length > 0) {
  console.error('Robot-local sidecar check failed:');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log('Robot-local sidecar check passed.');
