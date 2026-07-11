# Ed25519 Yao Benchmark Artifact Filesystem Policy v1

Status: **normative for Phase 2 benchmark artifact emission and checking**.

This document defines the host-filesystem authority required by the
generator-owned `EYAOBA01` artifact bundle. It applies only to benchmark and
verification tooling. It grants no production authority to the provisional
artifacts or the `EYAOBM01` candidate manifest.

## Supported hosts

The policy supports Linux and macOS. Compilation fails on every other target.
Every decision is made from an already-open descriptor. The policy layer
accepts no path strings and performs no path lookup.

The bundle layer opens the path anchor, each namespace component, the bundle
directory, and every expected regular file with descriptor-relative
`NOFOLLOW` operations. It applies this policy to every resulting descriptor.
The existing owner, mode, sticky-directory, single-link, metadata-snapshot,
bounded-read, and same-parent atomic no-replace rules remain mandatory.

## Local-filesystem requirement

Remote, stacked, and unrecognized filesystems are outside the v1 semantics.
Their cache coherence, link-count reporting, metadata ordering, and rename
behavior are not assumed.

On macOS, descriptor-based `fstatfs` must report `MNT_LOCAL`. Every descriptor
without that flag is rejected.

On Linux, descriptor-based `fstatfs` must report one of this closed set of
filesystem magic values:

| Filesystem family | Magic |
| --- | ---: |
| ext2/ext3/ext4 | `0x0000ef53` |
| tmpfs | `0x01021994` |
| ZFS | `0x2fc12fc1` |
| UBIFS | `0x24051905` |
| JFS | `0x3153464a` |
| XFS | `0x58465342` |
| ramfs | `0x858458f6` |
| Btrfs | `0x9123683e` |
| F2FS | `0xf2f52010` |

NFS/NFSv4, CIFS/SMB, 9p, Ceph, AFS, FUSE, OverlayFS, network filesystems, and
unknown magic values are rejected. Supporting another filesystem requires a
reviewed specification change, a policy-code change, and counted tests. There
is no runtime override or compatibility flag.

## ACL authority requirement

Mode bits are authoritative only when no additional ACL can grant access.

On Linux, descriptor-based `flistxattr` rejects these ACL representations:

- `system.posix_acl_access`
- `system.posix_acl_default`
- `system.nfs4_acl`
- `security.NTACL`
- `trusted.SGI_ACL_FILE`
- `trusted.SGI_ACL_DEFAULT`

The attribute-name list is bounded at 64 KiB and may be retried three times
when it changes between the sizing and read calls. Oversize, repeated change,
and inspection errors fail closed.

On macOS, the isolated host policy crate calls `acl_get_fd_np` with
`ACL_TYPE_EXTENDED` on the open descriptor. It enumerates at most the platform's
128-entry bound and rejects every `ACL_EXTENDED_ALLOW` entry because it can
expand authority beyond mode bits. Deny-only ACLs are accepted; they can reduce
authority and are present on standard macOS home directories. Unknown tags,
oversize ACLs, and inspection errors fail closed. Every returned ACL is freed
exactly once. APFS represents an absent ACL with a null result and either zero
or `ENOENT` in `errno`; those two null-result cases alone mean absence.

The unsafe macOS ABI boundary exists only in
`artifact-fs-policy/src/lib.rs`. The generator crate retains
`#![forbid(unsafe_code)]` and consumes the wrapper's safe descriptor API.

## Failure behavior

Policy rejection occurs before artifact bytes are trusted or a staging
directory is published. The public generator error distinguishes an
unsupported filesystem, an ACL, and an inspection failure. No rejection can
fall back to a weaker path-based check.

## Counted evidence

The host policy crate has three platform-stable tests:

1. the current temporary filesystem descriptor satisfies the local policy;
2. remote and unknown identifiers or mount flags are rejected; and
3. the platform authority-expanding ACL representation is rejected.

The macOS ACL test creates real deny and allow entries with the system `chmod`
utility, accepts the deny-only descriptor, and rejects the authority-expanding
descriptor. Linux tests exercise the closed filesystem classifier and exact
ACL-name parser. The formal parity gate requires all three tests in addition to
the generator's artifact-bundle regressions.

## Security exclusions

This policy does not authenticate the compiler, approve circuit semantics,
promote benchmark artifacts into production, or replace independent artifact
review. It closes only the local host-filesystem assumptions for deterministic
Phase 2 artifact generation and checking.
