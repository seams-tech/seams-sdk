export type ThemeTokenSet = {
  CHROMA_COLORS: Record<string, string>;
  GREY_COLORS: Record<string, string>;
  GRADIENTS: Record<string, string>;
  DARK_THEME: any;
  LIGHT_THEME: any;
};

export function createThemeTokens(palette: unknown): ThemeTokenSet;
