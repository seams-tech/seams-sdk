import type { BillingInvoice, BillingInvoiceLineItem } from './types';

export const CONSOLE_BILLING_INVOICE_PDF_EXPORT_POLICY =
  'CUSTOMER_FACING_EXCLUDES_INTERNAL_ACTIVITY' as const;

const PDF_PAGE_WIDTH = 612;
const PDF_PAGE_HEIGHT = 792;
const PDF_MARGIN_X = 48;
const PDF_TOP_Y = 744;
const PDF_BOTTOM_Y = 56;

type PdfLine = {
  text: string;
  size: number;
  indent?: number;
};

function toAscii(value: string): string {
  return value.replace(/[^\x20-\x7e]/g, '?');
}

function escapePdfText(value: string): string {
  return toAscii(value).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

function formatUtcTimestamp(value: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  const day = String(date.getUTCDate()).padStart(2, '0');
  const hours = String(date.getUTCHours()).padStart(2, '0');
  const minutes = String(date.getUTCMinutes()).padStart(2, '0');
  return `${year}-${month}-${day} ${hours}:${minutes} UTC`;
}

function formatInvoiceStatusLabel(status: string): string {
  const normalized = String(status || '')
    .trim()
    .toUpperCase();
  if (normalized === 'UNCOLLECTIBLE') return 'Uncollectible';
  if (normalized === 'PAST_DUE') return 'Past due';
  return normalized ? `${normalized[0]}${normalized.slice(1).toLowerCase()}` : 'Unknown';
}

function formatUsdMinor(value: number): string {
  const amount = Number.isFinite(value) ? Math.round(value) : 0;
  const sign = amount < 0 ? '-' : '';
  const absolute = Math.abs(amount);
  const dollars = Math.floor(absolute / 100);
  const cents = String(absolute % 100).padStart(2, '0');
  return `${sign}$${dollars}.${cents}`;
}

function wrapText(value: string, maxChars: number): string[] {
  const normalized = toAscii(String(value || '').trim()).replace(/\s+/g, ' ');
  if (!normalized) return ['-'];
  if (normalized.length <= maxChars) return [normalized];

  const words = normalized.split(' ');
  const lines: string[] = [];
  let current = '';
  for (const word of words) {
    if (!word) continue;
    if (!current) {
      if (word.length <= maxChars) {
        current = word;
      } else {
        for (let index = 0; index < word.length; index += maxChars) {
          lines.push(word.slice(index, index + maxChars));
        }
      }
      continue;
    }
    const next = `${current} ${word}`;
    if (next.length <= maxChars) {
      current = next;
      continue;
    }
    lines.push(current);
    if (word.length <= maxChars) {
      current = word;
      continue;
    }
    for (let index = 0; index < word.length; index += maxChars) {
      const chunk = word.slice(index, index + maxChars);
      if (chunk.length === maxChars || index + maxChars < word.length) {
        lines.push(chunk);
      } else {
        current = chunk;
      }
    }
    if (word.length % maxChars === 0) {
      current = '';
    }
  }
  if (current) lines.push(current);
  return lines.length ? lines : ['-'];
}

function pushWrapped(
  target: PdfLine[],
  prefix: string,
  value: string,
  maxChars: number,
  size = 11,
): void {
  const wrapped = wrapText(`${prefix}${value}`, maxChars);
  wrapped.forEach((line, index) => {
    target.push({
      text: line,
      size,
      indent: index === 0 ? 0 : 14,
    });
  });
}

function buildInvoicePdfLines(input: {
  orgId: string;
  invoice: BillingInvoice;
  lineItems: BillingInvoiceLineItem[];
  exportedAt?: Date;
}): PdfLine[] {
  const { orgId, invoice, lineItems, exportedAt } = input;
  const outstandingMinor = Math.max(0, invoice.amountDueMinor - invoice.amountPaidMinor);
  const subtotalMinor = lineItems.reduce(
    (sum, lineItem) => sum + Number(lineItem.amountMinor || 0),
    0,
  );
  const title =
    invoice.documentType === 'PURCHASE_RECEIPT' ? 'Purchase receipt' : 'Usage statement';
  const lines: PdfLine[] = [
    { text: title, size: 20 },
    { text: `Exported ${formatUtcTimestamp((exportedAt || new Date()).toISOString())}`, size: 10 },
    { text: '', size: 8 },
    { text: `Organization: ${orgId}`, size: 11 },
    { text: `Document ID: ${invoice.id}`, size: 11 },
    { text: `Document type: ${title}`, size: 11 },
    { text: `Status: ${formatInvoiceStatusLabel(invoice.status)}`, size: 11 },
    { text: `Billing period: ${invoice.periodMonthUtc || '-'}`, size: 11 },
    { text: `Issued: ${formatUtcTimestamp(invoice.createdAt)}`, size: 11 },
    { text: `Due: ${formatUtcTimestamp(invoice.dueAt)}`, size: 11 },
    { text: '', size: 8 },
    { text: 'Amounts', size: 13 },
    { text: `Subtotal: ${formatUsdMinor(subtotalMinor)}`, size: 11 },
    { text: 'Credits: $0.00', size: 11 },
    { text: `Total due: ${formatUsdMinor(invoice.amountDueMinor)}`, size: 11 },
    { text: `Amount paid: ${formatUsdMinor(invoice.amountPaidMinor)}`, size: 11 },
    { text: `Outstanding balance: ${formatUsdMinor(outstandingMinor)}`, size: 11 },
    { text: '', size: 8 },
    { text: 'Line items', size: 13 },
  ];

  if (lineItems.length === 0) {
    lines.push({ text: 'No line items on this invoice.', size: 11 });
  } else {
    lineItems.forEach((lineItem, index) => {
      const summary =
        `${index + 1}. ${lineItem.itemType} | qty ${lineItem.quantity} | ` +
        `${formatUsdMinor(lineItem.unitAmountMinor)} each | total ${formatUsdMinor(lineItem.amountMinor)}`;
      pushWrapped(lines, '', summary, 78, 11);
      pushWrapped(lines, '   Description: ', lineItem.description || '-', 74, 10);
      pushWrapped(lines, '   Period: ', lineItem.periodMonthUtc || '-', 74, 10);
      lines.push({ text: `   Line item ID: ${lineItem.id}`, size: 10 });
      lines.push({ text: '', size: 8 });
    });
  }

  lines.push({ text: 'Payment summary', size: 13 });
  lines.push({
    text:
      outstandingMinor > 0
        ? 'This document still has an outstanding balance.'
        : 'This document balance is fully settled.',
    size: 11,
  });
  lines.push({
    text: `Document status at export: ${formatInvoiceStatusLabel(invoice.status)}`,
    size: 11,
  });
  lines.push({
    text: 'Visibility: Customer-facing export (internal ledger adjustments excluded).',
    size: 11,
  });

  return lines;
}

function lineHeightFor(size: number): number {
  return size + (size >= 18 ? 8 : size >= 13 ? 6 : 4);
}

function renderPages(lines: PdfLine[]): string[] {
  const pages: string[] = [];
  let commands: string[] = [];
  let cursorY = PDF_TOP_Y;

  const flushPage = (): void => {
    if (!commands.length) return;
    pages.push(commands.join('\n'));
    commands = [];
    cursorY = PDF_TOP_Y;
  };

  for (const line of lines) {
    const height = line.text ? lineHeightFor(line.size) : 10;
    if (cursorY - height < PDF_BOTTOM_Y) flushPage();
    if (!line.text) {
      cursorY -= height;
      continue;
    }
    const x = PDF_MARGIN_X + Number(line.indent || 0);
    commands.push('BT');
    commands.push(`/F1 ${line.size} Tf`);
    commands.push(`1 0 0 1 ${x} ${cursorY} Tm`);
    commands.push(`(${escapePdfText(line.text)}) Tj`);
    commands.push('ET');
    cursorY -= height;
  }

  flushPage();
  return pages.length ? pages : ['BT /F1 12 Tf 1 0 0 1 48 744 Tm (Billing document) Tj ET'];
}

function concatPdf(parts: string[]): Uint8Array {
  const body = parts.join('');
  return new TextEncoder().encode(body);
}

export function buildConsoleBillingInvoicePdfFilename(invoice: BillingInvoice): string {
  const period = String(invoice.periodMonthUtc || 'unknown')
    .trim()
    .replace(/[^a-zA-Z0-9_-]+/g, '_');
  const invoiceId = String(invoice.id || 'invoice')
    .trim()
    .replace(/[^a-zA-Z0-9_-]+/g, '_');
  const prefix = invoice.documentType === 'PURCHASE_RECEIPT' ? 'receipt' : 'statement';
  return `${prefix}_${period}_${invoiceId}.pdf`;
}

export function buildConsoleBillingInvoicePdf(input: {
  orgId: string;
  invoice: BillingInvoice;
  lineItems: BillingInvoiceLineItem[];
  exportedAt?: Date;
}): Uint8Array {
  const lines = buildInvoicePdfLines(input);
  const pageStreams = renderPages(lines);
  const pageCount = pageStreams.length;
  const catalogObjectId = 1;
  const pagesObjectId = 2;
  const pageStartObjectId = 3;
  const fontObjectId = pageStartObjectId + pageCount * 2;

  const objects: string[] = [];
  objects[catalogObjectId] = `<< /Type /Catalog /Pages ${pagesObjectId} 0 R >>`;

  const pageRefs: string[] = [];
  for (let index = 0; index < pageCount; index += 1) {
    const pageObjectId = pageStartObjectId + index * 2;
    pageRefs.push(`${pageObjectId} 0 R`);
  }
  objects[pagesObjectId] = `<< /Type /Pages /Kids [${pageRefs.join(' ')}] /Count ${pageCount} >>`;

  for (let index = 0; index < pageCount; index += 1) {
    const pageObjectId = pageStartObjectId + index * 2;
    const contentObjectId = pageObjectId + 1;
    const stream = pageStreams[index];
    objects[pageObjectId] =
      `<< /Type /Page /Parent ${pagesObjectId} 0 R /MediaBox [0 0 ${PDF_PAGE_WIDTH} ${PDF_PAGE_HEIGHT}] ` +
      `/Resources << /Font << /F1 ${fontObjectId} 0 R >> >> /Contents ${contentObjectId} 0 R >>`;
    objects[contentObjectId] = `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`;
  }

  objects[fontObjectId] = '<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>';

  const partList: string[] = ['%PDF-1.4\n'];
  const offsets: number[] = [0];
  const lastObjectId = fontObjectId;
  let currentOffset = partList[0].length;

  for (let objectId = 1; objectId <= lastObjectId; objectId += 1) {
    const objectBody = `${objectId} 0 obj\n${objects[objectId]}\nendobj\n`;
    offsets[objectId] = currentOffset;
    partList.push(objectBody);
    currentOffset += objectBody.length;
  }

  const xrefOffset = currentOffset;
  partList.push(`xref\n0 ${lastObjectId + 1}\n`);
  partList.push('0000000000 65535 f \n');
  for (let objectId = 1; objectId <= lastObjectId; objectId += 1) {
    partList.push(`${String(offsets[objectId]).padStart(10, '0')} 00000 n \n`);
  }
  partList.push(`trailer\n<< /Size ${lastObjectId + 1} /Root ${catalogObjectId} 0 R >>\n`);
  partList.push(`startxref\n${xrefOffset}\n%%EOF`);

  return concatPdf(partList);
}
