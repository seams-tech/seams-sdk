import React from 'react';

export interface SegmentedControlItem {
  value: unknown;
  label?: React.ReactNode;
  className?: string;
  disabled?: boolean;
}

export interface SegmentedControlProps {
  items: SegmentedControlItem[];
  value: unknown;
  onValueChange: (value: unknown) => void;
  activeBg: string;
  height?: number | string;
  radius?: number | string;
  buttonFontSize?: number | string;
  buttonPadding?: number | string;
  containerStyle?: React.CSSProperties;
  buttonStyle?: React.CSSProperties;
  activeButtonStyle?: React.CSSProperties;
  className?: string;
  buttonClassName?: string;
}

function toCssDim(value?: number | string): string | undefined {
  if (value === undefined) return undefined;
  return typeof value === 'number' ? `${value}px` : value;
}

function activeIndexFor(items: SegmentedControlItem[], value: unknown): number {
  const index = items.findIndex((item) => Object.is(item.value, value));
  return index < 0 ? 0 : index;
}

function createRootStyle(input: {
  activeBg: string;
  activeIndex: number;
  count: number;
  height?: number | string;
  radius?: number | string;
  containerStyle?: React.CSSProperties;
}): React.CSSProperties {
  return {
    '--w3a-account-seg-active-bg': input.activeBg,
    '--w3a-account-seg-active-index': input.activeIndex,
    '--w3a-account-seg-count': input.count,
    height: toCssDim(input.height),
    minHeight: toCssDim(input.height),
    borderRadius: toCssDim(input.radius),
    ...(input.containerStyle || {}),
  } as React.CSSProperties;
}

function createButtonStyle(input: {
  isActive: boolean;
  buttonFontSize?: number | string;
  buttonPadding?: number | string;
  buttonStyle?: React.CSSProperties;
  activeButtonStyle?: React.CSSProperties;
  hasCustomHeight: boolean;
}): React.CSSProperties {
  return {
    fontSize: toCssDim(input.buttonFontSize),
    padding: toCssDim(input.buttonPadding),
    height: '100%',
    minHeight: input.hasCustomHeight ? 0 : undefined,
    ...(input.buttonStyle || {}),
    ...(input.isActive ? input.activeButtonStyle || {} : {}),
  };
}

export const SegmentedControl: React.FC<SegmentedControlProps> = ({
  items,
  value,
  onValueChange,
  activeBg,
  height,
  radius,
  buttonFontSize,
  buttonPadding,
  containerStyle,
  buttonStyle,
  activeButtonStyle,
  className,
  buttonClassName,
}) => {
  const count = Math.max(1, items.length);
  const activeIndex = activeIndexFor(items, value);
  const hasCustomHeight = height !== undefined;
  const rootStyle = createRootStyle({
    activeBg,
    activeIndex,
    count,
    height,
    radius,
    containerStyle,
  });

  return (
    <div className={`w3a-account-seg${className ? ` ${className}` : ''}`} style={rootStyle}>
      <div className="w3a-account-seg-active" />
      <div className="w3a-account-seg-grid">
        {items.map((item, index) => {
          const isActive = index === activeIndex;
          const itemStyle = createButtonStyle({
            isActive,
            buttonFontSize,
            buttonPadding,
            buttonStyle,
            activeButtonStyle,
            hasCustomHeight,
          });

          return (
            <button
              key={String(item.value)}
              type="button"
              aria-pressed={isActive}
              className={`w3a-account-seg-btn${isActive ? ' is-active' : ''}${buttonClassName ? ` ${buttonClassName}` : ''}${item.className ? ` ${item.className}` : ''}`}
              disabled={!!item.disabled}
              onClick={() => onValueChange(item.value)}
              style={itemStyle}
            >
              {item.label ?? String(item.value)}
            </button>
          );
        })}
      </div>
    </div>
  );
};

export default SegmentedControl;
