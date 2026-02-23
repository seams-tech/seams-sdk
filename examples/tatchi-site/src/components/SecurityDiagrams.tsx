import React from 'react';
import { ThemedSecuritySvg } from './ThemedSecuritySvg';

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

export function SecurityCustodyDiagram(props: SecurityDiagramProps) {
    return (
        <ThemedSecuritySvg
            src="/diagrams/security-custody.svg"
            alt="Hardware-isolated self custody diagram"
            className={props.className}
            style={useDiagramStyle(props)}
        />
    );
}

export function SecurityDefenseDiagram(props: SecurityDiagramProps) {
    return (
        <ThemedSecuritySvg
            src="/diagrams/security-defense.svg"
            alt="Defense in depth diagram"
            className={props.className}
            style={useDiagramStyle(props)}
        />
    );
}

export function SecurityScaleDiagram(props: SecurityDiagramProps) {
    return (
        <ThemedSecuritySvg
            src="/diagrams/security-scale.svg"
            alt="Battle-tested at scale diagram"
            className={props.className}
            style={useDiagramStyle(props)}
        />
    );
}

export function SecurityFrictionDiagram(props: SecurityDiagramProps) {
    return (
        <ThemedSecuritySvg
            src="/diagrams/security-friction.svg"
            alt="Friction where it matters diagram"
            className={props.className}
            style={useDiagramStyle(props)}
        />
    );
}
