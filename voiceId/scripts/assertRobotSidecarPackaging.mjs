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
      {
        name: 'localhost verifier URL',
        pattern: /VOICEID_PYTHON_VERIFIER_URL=http:\/\/127\.0\.0\.1:5051\/voice-id\/verifier\//,
      },
      { name: 'verifier sidecar backend', pattern: /VOICEID_VERIFIER_BACKEND=ecapa/ },
      { name: 'microphone capture', pattern: /microphone/ },
      { name: 'device capture proof', pattern: /device (signature|proof)|capture statement/i },
      { name: 'evidence tiers', pattern: /E0\/E1\/E2|E1 or future E2/ },
      { name: 'Router intent binding', pattern: /RouterVoiceIntentBinding/ },
      { name: 'PAD result', pattern: /\bPAD\b/ },
      { name: 'server challenge', pattern: /server challenge/i },
      {
        name: 'evidence authorization separation',
        pattern: /E0\/E1\/E2 cannot construct wallet signing authorization/i,
      },
      {
        name: 'browser passkey boundary',
        pattern: /wallet operations require passkey|unapproved profile returns E1 and passkey/i,
      },
      {
        name: 'capture profile and calibration',
        pattern: /capture profile.*calibrat|calibrat.*capture profile/is,
      },
      { name: 'independent robot safety controller', pattern: /independent.*safety controller/is },
      { name: 'raw audio retention boundary', pattern: /Raw audio stays local/ },
      { name: 'atomic verifier enrollment endpoint', pattern: /build-enrollment-template/ },
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
