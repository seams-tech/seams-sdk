// Node-friendly runtime variant for build scripts and generators.
// Loads palette.json via fs and exports the same constants as base-styles.js
// without relying on ESM JSON import assertions.

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createThemeTokens } from './base-styles.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const palettePath = path.join(__dirname, 'palette.json');
const palette = JSON.parse(fs.readFileSync(palettePath, 'utf-8'));

const built = createThemeTokens(palette);

export const CHROMA_COLORS = built.CHROMA_COLORS;
export const GREY_COLORS = built.GREY_COLORS;
export const GRADIENTS = built.GRADIENTS;
export const DARK_THEME = built.DARK_THEME;
export const LIGHT_THEME = built.LIGHT_THEME;

export default {
  palette,
  ...built,
};
