#!/usr/bin/env node

import { readFileSync } from 'node:fs';

const [outputPath, expectedProject] = process.argv.slice(2);

if (!outputPath || !expectedProject) {
  throw new Error(
    'usage: wrangler-pages-deployment-url.mjs <wrangler-output.ndjson> <pages-project>',
  );
}

const records = readFileSync(outputPath, 'utf8')
  .split(/\r?\n/u)
  .filter(Boolean)
  .map((line) => JSON.parse(line));

const deployment = records.findLast(
  (record) =>
    (record.type === 'pages-deploy-detailed' || record.type === 'pages-deploy') &&
    record.pages_project === expectedProject &&
    typeof record.url === 'string',
);

if (!deployment) {
  throw new Error(`Wrangler did not report a Pages deployment for ${expectedProject}`);
}

const deploymentUrl = new URL(deployment.url);
if (
  deploymentUrl.protocol !== 'https:' ||
  !deploymentUrl.hostname.endsWith('.pages.dev') ||
  deploymentUrl.username ||
  deploymentUrl.password
) {
  throw new Error(`Wrangler reported an invalid Pages deployment URL for ${expectedProject}`);
}

process.stdout.write(deploymentUrl.origin);
