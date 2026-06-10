import React from 'react';
import {
  buildDashboardDraftStorageKey,
  clearSessionDashboardDraft,
  readSessionDashboardDraft,
  writeSessionDashboardDraft,
  type DashboardDraftIdentity,
} from './sessionDraftStore';

export interface UseSessionDraftArgs<TForm> {
  identity: DashboardDraftIdentity | null;
  initialForm: TForm;
  isOpen: boolean;
  parseForm: (raw: unknown) => TForm | null;
}

export interface UseSessionDraftResult<TForm> {
  form: TForm;
  setForm: React.Dispatch<React.SetStateAction<TForm>>;
  restoreState: 'default' | 'restored';
  clearDraft: () => void;
  resetToInitial: () => void;
}

export function useSessionDraft<TForm>({
  identity,
  initialForm,
  isOpen,
  parseForm,
}: UseSessionDraftArgs<TForm>): UseSessionDraftResult<TForm> {
  const [form, setForm] = React.useState<TForm>(initialForm);
  const [restoreState, setRestoreState] = React.useState<'default' | 'restored'>('default');

  const draftStorageKey = React.useMemo(() => {
    if (!identity) return '';
    return buildDashboardDraftStorageKey(identity);
  }, [identity]);

  const loadedDraftStorageKeyRef = React.useRef<string>('');

  React.useEffect(() => {
    if (!isOpen) {
      loadedDraftStorageKeyRef.current = '';
      setRestoreState('default');
      return;
    }
    if (!identity || !draftStorageKey) {
      setForm(initialForm);
      setRestoreState('default');
      return;
    }

    if (loadedDraftStorageKeyRef.current === draftStorageKey) return;

    loadedDraftStorageKeyRef.current = draftStorageKey;
    const stored = readSessionDashboardDraft({
      identity,
      parseForm,
    });
    if (stored) {
      setForm(stored.form);
      setRestoreState('restored');
      return;
    }
    setForm(initialForm);
    setRestoreState('default');
  }, [draftStorageKey, identity, initialForm, isOpen, parseForm]);

  React.useEffect(() => {
    if (!isOpen || !identity || !draftStorageKey) return;
    writeSessionDashboardDraft(identity, form);
  }, [draftStorageKey, form, identity, isOpen]);

  const clearDraft = React.useCallback(() => {
    if (!identity) return;
    clearSessionDashboardDraft(identity);
    setRestoreState('default');
  }, [identity]);

  const resetToInitial = React.useCallback(() => {
    setForm(initialForm);
    if (identity) clearSessionDashboardDraft(identity);
    setRestoreState('default');
  }, [identity, initialForm]);

  return {
    form,
    setForm,
    restoreState,
    clearDraft,
    resetToInitial,
  };
}
