import React from 'react';

interface UriListEditorProps {
  label: string;
  description?: React.ReactNode;
  values: string[];
  onChange(next: string[]): void;
  placeholder?: string;
  addLabel?: string;
  disabled?: boolean;
}

export function UriListEditor(props: UriListEditorProps): React.JSX.Element {
  const {
    label,
    description,
    values,
    onChange,
    placeholder = 'https://app.example.com',
    addLabel = 'Add URI',
    disabled = false,
  } = props;

  const rows = values.length > 0 ? values : [];

  return (
    <div className="dashboard-uri-list-editor">
      <div className="dashboard-uri-list-editor__header">
        <span>{label}</span>
        {description ? (
          <div className="dashboard-uri-list-editor__description">{description}</div>
        ) : null}
      </div>

      <div className="dashboard-uri-list-editor__rows">
        {rows.map((value, index) => (
          <div className="dashboard-uri-list-editor__row" key={`uri-row-${index}`}>
            <label className="dashboard-form-field dashboard-uri-list-editor__field">
              <span>{`URIs ${index + 1} *`}</span>
              <input
                className="dashboard-input"
                value={value}
                onChange={(event) => {
                  const next = [...rows];
                  next[index] = event.target.value;
                  onChange(next);
                }}
                placeholder={placeholder}
                disabled={disabled}
                aria-label={`${label} URI ${index + 1}`}
              />
            </label>
            <div className="dashboard-uri-list-editor__actions">
              <button
                type="button"
                className="dashboard-inline-link dashboard-inline-link--danger"
                onClick={() => {
                  onChange(rows.filter((_, rowIndex) => rowIndex !== index));
                }}
                disabled={disabled}
                aria-label={`Delete URI ${index + 1}`}
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className="dashboard-form-actions">
        <button
          type="button"
          className="dashboard-pagination-button dashboard-pagination-button--secondary"
          onClick={() => onChange([...rows, ''])}
          disabled={disabled}
        >
          {`+ ${addLabel}`}
        </button>
      </div>
    </div>
  );
}

export default UriListEditor;
