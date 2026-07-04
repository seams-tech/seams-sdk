const INDENT_UNIT = '  ';

export type LogCategory = 'setup' | 'flow' | 'intercept' | 'console' | 'test' | 'harness';

export interface LogFormatOptions {
  step?: string | number;
  indent?: number;
  scope?: string;
}

export function formatLog(
  category: LogCategory,
  message: string,
  options: LogFormatOptions = {},
): string {
  const { step, indent = 0, scope } = options;
  const parts: string[] = [`[${category}`];

  if (scope) {
    parts.push(`:${scope}`);
  }

  if (typeof step !== 'undefined') {
    parts.push(` - step ${step}`);
  }

  parts.push(']');

  const header = parts.join('');
  const padding = indent > 0 ? INDENT_UNIT.repeat(indent) : '';
  return `${header} ${padding}${message}`;
}

export function printLog(
  category: LogCategory,
  message: string,
  options: LogFormatOptions = {},
): void {
  console.log(formatLog(category, message, options));
}

// Indented step line like:
//   [step 1] message
export function printStepLine(
  step: string | number,
  message: string,
  indent = 1,
  category: LogCategory = 'setup',
): void {
  const pad = INDENT_UNIT.repeat(Math.max(0, indent));
  const label = `${category}: ${step}`;
  console.log(`${pad}[${label}] ${message}`);
}
