export type VersionedJsonValue =
  | null
  | boolean
  | number
  | string
  | readonly VersionedJsonValue[]
  | { readonly [key: string]: VersionedJsonValue };

export type VersionedJsonObject = {
  readonly [key: string]: VersionedJsonValue;
};

export type VersionedJsonRecordReadResult<T> =
  | { readonly kind: 'missing' }
  | { readonly kind: 'present'; readonly value: T; readonly version: string };

export type VersionedJsonRecordPutResult =
  | { readonly kind: 'stored'; readonly version: string }
  | { readonly kind: 'version_mismatch' };
