import { readFile } from 'node:fs/promises';

const checks = [
  {
    filePath: 'deploy/aws/verifier-service/README.md',
    required: [
      { name: 'ordinary-server scope', pattern: /ordinary-server/i },
      { name: 'same verifier image', pattern: /deploy\/cloudflare\/verifier-container\/Dockerfile/ },
      { name: 'python-http transport', pattern: /python-http/ },
      { name: 'verifier URL env', pattern: /VOICEID_PYTHON_VERIFIER_URL/ },
      { name: 'ECAPA backend env', pattern: /VOICEID_VERIFIER_BACKEND=ecapa/ },
      { name: 'health endpoint', pattern: /\/health/ },
      { name: 'verifier port', pattern: /8797/ },
      { name: 'ECS option', pattern: /\bECS\b/ },
      { name: 'EC2 option', pattern: /\bEC2\b/ },
      { name: 'KMS envelope boundary', pattern: /\bKMS\b/ },
      { name: 'Nitro Enclave separation', pattern: /Nitro Enclave/ },
      { name: 'Router A/B signer boundary', pattern: /Router A\/B/ },
      { name: 'SigningWorker boundary', pattern: /SigningWorker/ },
    ],
  },
  {
    filePath: 'deploy/cloudflare/verifier-container/Dockerfile',
    required: [
      { name: 'generic container bind host', pattern: /VOICEID_VERIFIER_HOST=0\.0\.0\.0/ },
      { name: 'HTTP sidecar command', pattern: /voiceid_verifier\.app", "serve_http/ },
      { name: 'HTTP health check', pattern: /\/health/ },
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
  console.error('AWS ordinary-server deployment check failed:');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log('AWS ordinary-server deployment check passed.');
