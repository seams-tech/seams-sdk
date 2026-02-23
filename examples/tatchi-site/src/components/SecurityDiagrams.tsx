import React from 'react';

type InlineSvgProps = {
    className?: string;
    style?: React.CSSProperties;
    alt: string;
};

function createInlineSvgComponent(markup: string): React.ComponentType<InlineSvgProps> {
    return function InlineSvg({ className, style, alt }: InlineSvgProps) {
        return (
            <div
                className={className}
                style={style}
                role="img"
                aria-label={alt}
                dangerouslySetInnerHTML={{ __html: markup }}
            />
        );
    };
}

function loadInlineSvg(importer: () => Promise<{ default: string }>) {
    return React.lazy(async () => {
        const module = await importer();
        return { default: createInlineSvgComponent(module.default) };
    });
}

const SecurityCustodySvg = loadInlineSvg(() => import('../assets/diagrams/security-custody.svg?raw'));
const SecurityDefenseSvg = loadInlineSvg(() => import('../assets/diagrams/security-defense.svg?raw'));
const SecurityScaleSvg = loadInlineSvg(() => import('../assets/diagrams/security-scale.svg?raw'));
const SecurityFrictionSvg = loadInlineSvg(() => import('../assets/diagrams/security-friction.svg?raw'));

export type SecurityDiagramProps = {
    className?: string;
    /** Primary glow or accent color for moving particles and paths */
    glowColor?: string;
    /** Secondary node or accent point color */
    nodeColor?: string;
    /** Background canvas color */
    canvasColor?: string;
    /** Base line or grid color */
    lineColor?: string;
    style?: React.CSSProperties;
};

function useDiagramStyle(props: SecurityDiagramProps): React.CSSProperties {
    const vars: Record<string, string> = {};

    if (props.glowColor) vars['--diagram-glow'] = props.glowColor;
    if (props.nodeColor) vars['--diagram-node'] = props.nodeColor;
    if (props.canvasColor) {
        vars['--security-diagram-canvas'] = props.canvasColor;
        vars['--security-diagram-canvas-top'] = `color-mix(in srgb, ${props.canvasColor} 86%, var(--site-canvas) 14%)`;
        vars['--security-diagram-canvas-bottom'] = `color-mix(in srgb, ${props.canvasColor} 68%, var(--site-canvas) 32%)`;
    }
    if (props.lineColor) {
        vars['--security-diagram-line'] = props.lineColor;
        vars['--security-diagram-line-strong'] = `color-mix(in srgb, ${props.lineColor} 78%, var(--site-text-primary) 22%)`;
    }

    return { ...props.style, ...vars } as React.CSSProperties;
}

type SecuritySvgComponent = React.LazyExoticComponent<React.ComponentType<InlineSvgProps>>;

function renderSecurityDiagram(
    Component: SecuritySvgComponent,
    alt: string,
    fallbackSrc: string,
    props: SecurityDiagramProps,
) {
    const style = useDiagramStyle(props);

    return (
        <React.Suspense fallback={<img className={props.className} src={fallbackSrc} alt={alt} loading="lazy" style={style} />}>
            <Component
                className={props.className}
                style={style}
                alt={alt}
            />
        </React.Suspense>
    );
}

export function SecurityCustodyDiagram(props: SecurityDiagramProps) {
    return renderSecurityDiagram(
        SecurityCustodySvg,
        'Hardware-isolated self custody diagram',
        '/diagrams/security-custody.png',
        props,
    );
}

export function SecurityDefenseDiagram(props: SecurityDiagramProps) {
    return renderSecurityDiagram(
        SecurityDefenseSvg,
        'Defense in depth diagram',
        '/diagrams/security-defense.png',
        props,
    );
}

export function SecurityScaleDiagram(props: SecurityDiagramProps) {
    return renderSecurityDiagram(
        SecurityScaleSvg,
        'Battle-tested at scale diagram',
        '/diagrams/security-scale.png',
        props,
    );
}

export function SecurityFrictionDiagram(props: SecurityDiagramProps) {
    return renderSecurityDiagram(
        SecurityFrictionSvg,
        'Friction where it matters diagram',
        '/diagrams/security-friction.png',
        props,
    );
}
