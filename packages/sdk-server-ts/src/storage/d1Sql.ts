function collapseD1SchemaWhitespace(statement: string): string {
  let output = '';
  let inSingleQuote = false;
  let pendingSpace = false;
  for (let index = 0; index < statement.length; index += 1) {
    const char = statement[index];
    if (char === "'") {
      if (pendingSpace && output) output += ' ';
      pendingSpace = false;
      output += char;
      if (inSingleQuote && statement[index + 1] === "'") {
        output += "'";
        index += 1;
      } else {
        inSingleQuote = !inSingleQuote;
      }
      continue;
    }
    if (!inSingleQuote && /\s/.test(char)) {
      pendingSpace = Boolean(output);
      continue;
    }
    if (pendingSpace && output) output += ' ';
    pendingSpace = false;
    output += char;
  }
  return output.trim();
}

export function formatD1ExecStatement(statement: string): string {
  const sql = collapseD1SchemaWhitespace(statement);
  if (!sql) throw new Error('D1 exec statement must be non-empty');
  return sql.endsWith(';') ? sql : `${sql};`;
}
