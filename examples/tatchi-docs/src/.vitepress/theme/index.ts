import DefaultTheme from 'vitepress/theme';
import type { Theme } from 'vitepress';
import './custom.css';

function isServerRender(): boolean {
  return !!(import.meta as any)?.env?.SSR;
}

function readIsDark(): boolean {
  return document.documentElement.classList.contains('dark');
}

function createMermaidRenderer() {
  let mermaidRef: any = null;

  const configure = async () => {
    if (!mermaidRef) {
      const mod = await import('mermaid').catch(() => null);
      mermaidRef = mod?.default;
    }
    if (!mermaidRef) return false;

    const isDark = readIsDark();
    mermaidRef.initialize({
      startOnLoad: false,
      theme: 'base',
      themeVariables: {
        primaryColor: '#f0f9ff',
        primaryBorderColor: '#60a5fa',
        lineColor: '#94a3b8',
        fontSize: '16px',
        primaryTextColor: isDark ? '#e2e8f0' : '#1e293b',
        secondaryTextColor: isDark ? '#cbd5e1' : '#334155',
        tertiaryTextColor: isDark ? '#94a3b8' : '#64748b',
        textColor: isDark ? '#e2e8f0' : '#1e293b',
        actorTextColor: isDark ? '#e2e8f0' : '#1e293b',
        labelTextColor: isDark ? '#e2e8f0' : '#1e293b',
        noteTextColor: isDark ? '#e2e8f0' : '#1e293b',
        actorBkg: isDark ? '#2c6cbc' : '#f0f9ff',
        actorBorder: isDark ? '#5896d9' : '#60a5fa',
        noteBkgColor: isDark ? '#b46e3c' : '#fef3c7',
        noteBorderColor: isDark ? '#c88755' : '#f59e0b',
      },
    });
    return true;
  };

  const restoreCodeBlocks = () => {
    document.querySelectorAll('.mermaid[data-mermaid-source]').forEach((el) => {
      const source = el.getAttribute('data-mermaid-source');
      if (!source) return;
      const wrapper = document.createElement('div');
      wrapper.className = 'language-mermaid';
      const pre = document.createElement('pre');
      const code = document.createElement('code');
      code.textContent = source;
      pre.appendChild(code);
      wrapper.appendChild(pre);
      el.replaceWith(wrapper);
    });
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

      try {
        const { svg } = await mermaidRef.render(id, source);
        const container = document.createElement('div');
        container.className = 'mermaid';
        container.setAttribute('data-mermaid-source', source);
        container.innerHTML = svg;
        block.replaceWith(container);
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
  enhanceApp: async (ctx) => {
    await (DefaultTheme as any).enhanceApp?.(ctx);
    if (isServerRender() || typeof window === 'undefined') return;

    const { rerender } = createMermaidRenderer();
    await rerender();

    ctx.router.onAfterRouteChanged = () => {
      setTimeout(() => {
        void rerender();
      }, 0);
    };

    const themeObserver = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'attributes' && mutation.attributeName === 'class') {
          void rerender();
          break;
        }
      }
    });
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class'],
    });

    if ((import.meta as any).hot) {
      (import.meta as any).hot.dispose(() => {
        themeObserver.disconnect();
      });
    }
  },
};

export default theme;
