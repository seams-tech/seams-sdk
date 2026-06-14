import { readFile } from 'node:fs/promises';

const checks = [
  {
    filePath: 'deploy/aws/nitro-enclave-bridge/README.md',
    required: [
      { name: 'Nitro Enclave scope', pattern: /Nitro Enclave/ },
      { name: 'parent instance bridge', pattern: /parent-instance bridge/ },
      { name: 'vsock transport', pattern: /\bvsock\b/ },
      { name: 'no raw audio rule', pattern: /Raw audio never enters the enclave/ },
      { name: 'no ECAPA model rule', pattern: /ECAPA model runtime stays outside the\s+enclave/ },
      { name: 'no persistent storage rule', pattern: /no persistent storage/i },
      { name: 'no external networking rule', pattern: /no external networking/i },
      { name: 'attestation boundary', pattern: /attestation/i },
      { name: 'KMS boundary', pattern: /\bKMS\b/ },
      { name: 'intent digest field', pattern: /intentDigest/ },
      { name: 'owner presence evidence', pattern: /ownerPresence/ },
      { name: 'policy decision request', pattern: /policy_decision/ },
      { name: 'template key unwrap request', pattern: /template_key_unwrap/ },
      { name: 'signing worker authorization request', pattern: /signing_worker_authorization/ },
      { name: 'Router A/B boundary', pattern: /Router A\/B/ },
      { name: 'SigningWorker boundary', pattern: /SigningWorker/ },
    ],
  },
  {
    filePath: 'deploy/aws/verifier-service/README.md',
    required: [
      { name: 'ordinary verifier remains outside enclave', pattern: /ordinary-server verifier\nservice can stay outside the enclave/ },
      { name: 'parent bridge callout', pattern: /parent EC2 instance as the bridge/ },
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
  console.error('Nitro Enclave bridge check failed:');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log('Nitro Enclave bridge check passed.');
