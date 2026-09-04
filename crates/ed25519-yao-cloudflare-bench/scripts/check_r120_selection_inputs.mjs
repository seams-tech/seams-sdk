import { pathToFileURL } from 'node:url';

import {
  buildR120SelectionInputChecklist,
  loadR120SelectionInput,
} from './evaluate_r120_architecture_selection.mjs';

function main() {
  const input = loadR120SelectionInput(process.env);
  const checklist = buildR120SelectionInputChecklist(input);
  process.stdout.write(`${JSON.stringify(checklist, null, 2)}\n`);
}

function handleFatal(error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
  try {
    main();
  } catch (error) {
    handleFatal(error);
  }
}
