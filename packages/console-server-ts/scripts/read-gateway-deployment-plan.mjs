import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { parseGatewayDeploymentPlan } from './gateway-deployment-config.mjs';

function main() {
  const options = parseArguments(process.argv.slice(2));
  const plan = parseGatewayDeploymentPlan(fs.readFileSync(options.plan, 'utf8'));
  switch (options.field) {
    case 'gateway-origin':
      process.stdout.write(plan.gatewayOrigin);
      return;
    default:
      throw new Error(`Unsupported field: ${options.field}`);
  }
}

function parseArguments(args) {
  let plan = '';
  let field = '';
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--plan') {
      plan = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    if (argument === '--field') {
      field = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${argument}`);
  }
  if (!plan) throw new Error('--plan is required');
  if (!field) throw new Error('--field is required');
  return {
    plan: path.resolve(process.cwd(), plan),
    field,
  };
}

function requireArgumentValue(args, index, name) {
  const value = String(args[index + 1] || '').trim();
  if (!value) throw new Error(`${name} requires a value`);
  return value;
}

main();
