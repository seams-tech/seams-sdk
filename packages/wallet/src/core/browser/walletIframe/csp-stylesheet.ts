type GlobalWithNonce = typeof window & { litNonce?: string; w3aNonce?: string };

type NonceSource = string | (() => string | undefined);

export type CspStylesheetManager = {
  ensureBase(): void;
  setDynamicRule(id: string, rule: string): void;
  /**
   * Per-frame variant of setDynamicRule.
   *
   * setDynamicRule stores rule *text*, so every write reserialises and reparses
   * the whole dynamic sheet. That is fine for rules that change on a state
   * transition, and far too expensive for ones that change on every animation
   * frame: an overlay tracking a resizing surface rewrote the entire sheet
   * 15+ times across a 250ms transition, and the frames the host dropped
   * flattened the surface's easing into something that read as linear.
   *
   * These declarations live on their own retained CSSStyleRule, mutated in
   * place through CSSOM. No text is reparsed, no other rule is touched, and
   * nothing here is an inline style attribute, so a strict CSP is unaffected.
   * Falls back to the text path where constructable stylesheets are missing.
   */
  setDynamicDeclarations(id: string, selector: string, declarations: Declarations): void;
  deleteDynamicRule(id: string): void;
  clearDynamicRules(): void;
  hasDynamicRule(id: string): boolean;
};

type Declarations = Readonly<Record<string, string>>;

function declarationsToCssText(selector: string, declarations: Declarations): string {
  const body = Object.entries(declarations)
    .map(([property, value]) => `${property}:${value};`)
    .join('');
  return `${selector}{${body}}`;
}

export function getDefaultCspNonce(): string | undefined {
  if (typeof window === 'undefined') return undefined;
  const w = window as GlobalWithNonce;
  return w.w3aNonce || w.litNonce || undefined;
}

export function createCspStylesheetManager(opts: {
  doc: Document;
  baseCss: string;
  baseStyleDataAttr?: string;
  dynamicStyleDataAttr?: string;
  nonce?: NonceSource;
}): CspStylesheetManager {
  const { doc, baseCss, baseStyleDataAttr, dynamicStyleDataAttr, nonce } = opts;

  const state: {
    baseSheet: CSSStyleSheet | null;
    dynamicSheet: CSSStyleSheet | null;
    // Declaration rules get their own sheet so a text rebuild of the dynamic
    // sheet can never invalidate the CSSStyleRule handles retained here.
    declarationSheet: CSSStyleSheet | null;
    baseStyleEl: HTMLStyleElement | null;
    dynamicStyleEl: HTMLStyleElement | null;
    rules: Map<string, string>;
    declarationRules: Map<string, { selector: string; rule: CSSStyleRule; applied: Declarations }>;
    supportConstructable: boolean | null;
  } = {
    baseSheet: null,
    dynamicSheet: null,
    declarationSheet: null,
    baseStyleEl: null,
    dynamicStyleEl: null,
    rules: new Map(),
    declarationRules: new Map(),
    supportConstructable: null,
  };

  const resolveNonce = (): string | undefined => {
    if (!nonce) return undefined;
    return typeof nonce === 'function' ? nonce() : nonce;
  };

  const supportsConstructable = (): boolean => {
    if (state.supportConstructable != null) return state.supportConstructable;
    state.supportConstructable =
      typeof CSSStyleSheet !== 'undefined' && 'adoptedStyleSheets' in doc;
    return state.supportConstructable;
  };

  const adoptSheets = (sheets: CSSStyleSheet[]): void => {
    const current = (doc.adoptedStyleSheets || []) as CSSStyleSheet[];
    const next = [...current];
    for (const sheet of sheets) {
      if (!current.includes(sheet)) next.push(sheet);
    }
    doc.adoptedStyleSheets = next;
  };

  const appendStyleEl = (el: HTMLStyleElement): void => {
    const target = doc.head || doc.documentElement || doc.body;
    target?.appendChild(el);
  };

  const createStyleEl = (dataAttr?: string, cssText?: string): HTMLStyleElement => {
    const el = doc.createElement('style');
    const resolvedNonce = resolveNonce();
    if (resolvedNonce) {
      try {
        el.setAttribute('nonce', resolvedNonce);
      } catch {}
    }
    if (dataAttr) {
      try {
        el.setAttribute(dataAttr, '');
      } catch {}
    }
    if (cssText != null) {
      el.textContent = cssText;
    }
    return el;
  };

  const ensureBase = (): void => {
    if (state.baseSheet || state.baseStyleEl) return;
    if (supportsConstructable()) {
      try {
        state.baseSheet = new CSSStyleSheet();
        state.baseSheet.replaceSync(baseCss);
        adoptSheets([state.baseSheet]);
        return;
      } catch {
        state.baseSheet = null;
        state.supportConstructable = false;
      }
    }
    const styleEl = createStyleEl(baseStyleDataAttr, baseCss);
    appendStyleEl(styleEl);
    state.baseStyleEl = styleEl;
  };

  const buildDynamicCss = (): string => Array.from(state.rules.values()).join('\n');

  const ensureDynamic = (): void => {
    if (supportsConstructable()) {
      if (!state.dynamicSheet) {
        state.dynamicSheet = new CSSStyleSheet();
        adoptSheets([state.dynamicSheet]);
      }
      return;
    }
    if (!state.dynamicStyleEl) {
      const el = createStyleEl(dynamicStyleDataAttr);
      appendStyleEl(el);
      state.dynamicStyleEl = el;
    }
  };

  const syncDynamic = (): void => {
    const css = buildDynamicCss();
    if (supportsConstructable()) {
      try {
        ensureDynamic();
        state.dynamicSheet?.replaceSync(css);
        return;
      } catch {
        state.supportConstructable = false;
        state.dynamicSheet = null;
      }
    }
    ensureDynamic();
    if (state.dynamicStyleEl) {
      state.dynamicStyleEl.textContent = css;
    }
  };

  const ensureDeclarationRule = (id: string, selector: string): CSSStyleRule | null => {
    const existing = state.declarationRules.get(id);
    if (existing && existing.selector === selector) return existing.rule;
    if (!supportsConstructable()) return null;
    try {
      if (!state.declarationSheet) {
        state.declarationSheet = new CSSStyleSheet();
        adoptSheets([state.declarationSheet]);
      }
      const sheet = state.declarationSheet;
      if (existing) {
        // The selector changed, so the retained rule no longer describes it.
        const index = Array.prototype.indexOf.call(sheet.cssRules, existing.rule);
        if (index >= 0) sheet.deleteRule(index);
        state.declarationRules.delete(id);
      }
      const index = sheet.insertRule(`${selector}{}`, sheet.cssRules.length);
      const rule = sheet.cssRules[index];
      if (!(rule instanceof CSSStyleRule)) {
        sheet.deleteRule(index);
        return null;
      }
      state.declarationRules.set(id, { selector, rule, applied: {} });
      return rule;
    } catch {
      state.declarationSheet = null;
      state.declarationRules.clear();
      return null;
    }
  };

  const deleteDeclarationRule = (id: string): boolean => {
    const entry = state.declarationRules.get(id);
    if (!entry) return false;
    state.declarationRules.delete(id);
    const sheet = state.declarationSheet;
    if (!sheet) return true;
    try {
      const index = Array.prototype.indexOf.call(sheet.cssRules, entry.rule);
      if (index >= 0) sheet.deleteRule(index);
    } catch {}
    return true;
  };

  return {
    ensureBase: () => {
      ensureBase();
    },
    setDynamicDeclarations: (id: string, selector: string, declarations: Declarations) => {
      ensureBase();
      const rule = ensureDeclarationRule(id, selector);
      if (!rule) {
        // No constructable stylesheets: correctness over frame cost.
        const cssText = declarationsToCssText(selector, declarations);
        if (state.rules.get(id) === cssText) return;
        state.rules.set(id, cssText);
        syncDynamic();
        return;
      }
      const entry = state.declarationRules.get(id);
      const applied = entry ? entry.applied : {};
      for (const [property, value] of Object.entries(declarations)) {
        if (applied[property] === value) continue;
        rule.style.setProperty(property, value);
      }
      for (const property of Object.keys(applied)) {
        if (property in declarations) continue;
        rule.style.removeProperty(property);
      }
      if (entry) entry.applied = { ...declarations };
    },
    setDynamicRule: (id: string, rule: string) => {
      ensureBase();
      // Callers re-derive rules on scroll/resize; skip the stylesheet rebuild
      // when the rule text is unchanged.
      if (state.rules.get(id) === rule) return;
      state.rules.set(id, rule);
      syncDynamic();
    },
    deleteDynamicRule: (id: string) => {
      // An id lives in exactly one of the two maps, but which one depends on
      // whether constructable stylesheets were available when it was written.
      deleteDeclarationRule(id);
      if (!state.rules.delete(id)) return;
      syncDynamic();
    },
    clearDynamicRules: () => {
      for (const id of Array.from(state.declarationRules.keys())) deleteDeclarationRule(id);
      if (state.rules.size === 0) return;
      state.rules.clear();
      syncDynamic();
    },
    hasDynamicRule: (id: string) => state.rules.has(id) || state.declarationRules.has(id),
  };
}
