import DefaultTheme from 'vitepress/theme';
import type { Theme } from 'vitepress';
import type { Mermaid, MermaidConfig } from 'mermaid';
import { h } from 'vue';
import SeamsFooter from './SeamsFooter.vue';
import DocHeader from './DocHeader.vue';
import './custom.css';

function createMermaidRenderer() {
  let mermaidRef: Mermaid | null = null;

  const isDark = () => document.documentElement.classList.contains('dark');

  const lightVariables = (): MermaidConfig['themeVariables'] => ({
    primaryColor: '#edf3fa',
    primaryTextColor: '#0a0a0a',
    primaryBorderColor: '#4a6fa5',
    secondaryColor: '#f5f3f1',
    secondaryTextColor: '#44403b',
    secondaryBorderColor: '#a59f97',
    tertiaryColor: '#e4f0eb',
    tertiaryTextColor: '#0a0a0a',
    tertiaryBorderColor: '#157f5f',
    lineColor: '#777169',
    textColor: '#0a0a0a',
    actorTextColor: '#0a0a0a',
    labelTextColor: '#0a0a0a',
    noteTextColor: '#44403b',
    actorBkg: '#edf3fa',
    actorBorder: '#4a6fa5',
    noteBkgColor: '#f7ecdd',
    noteBorderColor: '#b45309',
    clusterBkg: '#f8f8f7',
    clusterBorder: '#d6d1cb',
    edgeLabelBackground: '#ffffff',
    fontFamily: "'Inter', ui-sans-serif, system-ui, sans-serif",
  });

  const darkVariables = (): MermaidConfig['themeVariables'] => ({
    background: '#121110',
    primaryColor: '#1f2a3a',
    primaryTextColor: '#f1ede8',
    primaryBorderColor: '#9db8e3',
    secondaryColor: '#221f1c',
    secondaryTextColor: '#b5aea5',
    secondaryBorderColor: '#4a453f',
    tertiaryColor: '#16291f',
    tertiaryTextColor: '#f1ede8',
    tertiaryBorderColor: '#6ec7a4',
    lineColor: '#857e76',
    textColor: '#f1ede8',
    actorTextColor: '#f1ede8',
    labelTextColor: '#f1ede8',
    noteTextColor: '#f1ede8',
    actorBkg: '#1f2a3a',
    actorBorder: '#9db8e3',
    noteBkgColor: '#2c231a',
    noteBorderColor: '#e0ac68',
    clusterBkg: '#1a1917',
    clusterBorder: '#2d2a27',
    edgeLabelBackground: '#1a1917',
    fontFamily: "'Inter', ui-sans-serif, system-ui, sans-serif",
  });

  const themeVariables = (): MermaidConfig['themeVariables'] =>
    isDark() ? darkVariables() : lightVariables();

  const configure = async () => {
    if (!mermaidRef) {
      const mod = await import('mermaid').catch(() => null);
      mermaidRef = mod?.default ?? null;
    }
    if (!mermaidRef) return false;

    const config: MermaidConfig = {
      startOnLoad: false,
      theme: 'base',
      themeVariables: themeVariables(),
    };
    mermaidRef.initialize(config);
    return true;
  };

  const restoreCodeBlocks = () => {
    document.querySelectorAll('.mermaid-figure[data-mermaid-source]').forEach((figure) => {
      const source = figure.getAttribute('data-mermaid-source');
      if (!source) return;
      const wrapper = document.createElement('div');
      wrapper.className = 'language-mermaid';
      const pre = document.createElement('pre');
      const code = document.createElement('code');
      code.textContent = source;
      pre.appendChild(code);
      wrapper.appendChild(pre);
      figure.replaceWith(wrapper);
    });
  };

  const diagramLabel = (block: Element): string => {
    let sibling = block.previousElementSibling;
    while (sibling) {
      if (/^H[1-6]$/.test(sibling.tagName) && sibling.textContent?.trim()) {
        return `${sibling.textContent.trim()} diagram`;
      }
      sibling = sibling.previousElementSibling;
    }
    const pageTitle = document.querySelector('main h1')?.textContent?.trim();
    return pageTitle ? `${pageTitle} diagram` : 'Architecture diagram';
  };

  const diagramSummary = (source: string): string => {
    const labels = [...source.matchAll(/(?:\[|\(|\{)["']?([^\]})"']{2,80})["']?(?:\]|\)|\})/g)]
      .map((match) => match[1]?.replace(/<br\s*\/?\s*>/gi, ', ').trim())
      .filter((label): label is string => Boolean(label));
    const uniqueLabels = [...new Set(labels)].slice(0, 8);
    return uniqueLabels.length > 0
      ? `The diagram connects ${uniqueLabels.join(', ')}.`
      : 'The diagram presents the flow described in the surrounding section.';
  };

  const createDiagramFigure = (source: string, svg: string, label: string): HTMLElement => {
    const figure = document.createElement('figure');
    figure.className = 'mermaid-figure';
    figure.setAttribute('data-mermaid-source', source);

    const container = document.createElement('div');
    container.className = 'mermaid';
    container.setAttribute('role', 'img');
    container.setAttribute('aria-label', label);
    container.innerHTML = svg;

    const caption = document.createElement('figcaption');
    const captionTitle = document.createElement('strong');
    captionTitle.textContent = label;
    const captionSummary = document.createElement('span');
    captionSummary.textContent = ` ${diagramSummary(source)}`;
    caption.append(captionTitle, captionSummary);

    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = 'View diagram source';
    const sourceBlock = document.createElement('div');
    sourceBlock.className = 'language-mermaid';
    const pre = document.createElement('pre');
    const code = document.createElement('code');
    code.textContent = source;
    pre.appendChild(code);
    sourceBlock.appendChild(pre);
    details.append(summary, sourceBlock);
    figure.append(container, caption, details);
    return figure;
  };

  const render = async () => {
    const configured = await configure();
    if (!configured || !mermaidRef) return;

    const blocks = Array.from(document.querySelectorAll('.language-mermaid'));
    for (const block of blocks) {
      const code = block.querySelector('pre code');
      if (!code) continue;
      const source = code.textContent || '';
      if (!source.trim()) continue;
      const id = `mermaid-${Math.random().toString(36).slice(2)}`;
      const label = diagramLabel(block);

      try {
        const { svg } = await mermaidRef.render(id, source);
        block.replaceWith(createDiagramFigure(source, svg, label));
      } catch (error) {
        console.error('[docs] Mermaid render failed:', error);
      }
    }
  };

  const rerender = async () => {
    restoreCodeBlocks();
    await render();
  };

  return { rerender };
}

const theme: Theme = {
  ...DefaultTheme,
  Layout: () =>
    h(DefaultTheme.Layout, null, {
      'doc-before': () => h(DocHeader),
      'layout-bottom': () => h(SeamsFooter),
    }),
  enhanceApp: async (ctx) => {
    await DefaultTheme.enhanceApp?.(ctx);
    if (import.meta.env.SSR || typeof window === 'undefined') return;

    const { rerender } = createMermaidRenderer();
    await rerender();

    ctx.router.onAfterRouteChanged = () => {
      setTimeout(() => {
        void rerender();
      }, 0);
    };

    // Diagram colors are baked into the rendered SVG, so redraw them whenever
    // the appearance toggle flips the root class.
    let wasDark = document.documentElement.classList.contains('dark');
    new MutationObserver(() => {
      const isDark = document.documentElement.classList.contains('dark');
      if (isDark === wasDark) return;
      wasDark = isDark;
      void rerender();
    }).observe(document.documentElement, { attributeFilter: ['class'] });
  },
};

export default theme;
