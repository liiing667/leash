# Policy generations: recoverable, transactional policy writes

## Problem

Policy writes used to mutate in-memory enforcement first and persist Cedar
afterwards, treating persistence errors as best-effort:

1. The public API returned success after updating the runtime/file layers.
2. A later post-processing failure (LSM/proxy) or a failed disk write left the
   durable Cedar (`cedar-runtime.cedar` / canonical file) representing the
   previous policy.
3. On the next cold start the daemon recovered that older, stale policy even
   though the operator had been told the new policy was applied.

There was no single notion of a complete, committed policy "generation", so a
partial failure could produce mixed in-memory vs. on-disk state.

## Model

A **generation** is one complete, validated Cedar document addressed by the
SHA-256 of its content. Identical content always maps to the same generation
id, which makes re-writing the same policy an idempotent no-op.

### On-disk layout (`internal/policygen`)

Under the leash state directory (`LEASH_DIR`):

```
policy-generations/
  gen-<sha256>.cedar   immutable, fsync'd generation objects
  current              pointer file naming the committed generation id
cedar-runtime.cedar    legacy snapshot, kept in sync for older builds
```

The operator-facing canonical Cedar file (e.g. `/cfg/leash.cedar`) is replaced
atomically with the same bytes as part of every commit.

### Commit ordering (the transaction boundary)

`Store.Commit` performs, in order:

1. Write and fsync the immutable generation object in full.
2. Atomically publish the canonical file and legacy snapshot from those bytes.
3. Atomically flip the `current` pointer.

Until step 3 succeeds, the previous generation remains the single committed,
restorable state. Every file move is a temp-file + fsync + rename, so readers
never observe a partially written document.

### Recovery

`Store.Current` resolves the active generation by:

1. The `current` pointer plus its content-verified generation object. A torn
   pointer (missing object, hash mismatch, path traversal) is not trusted.
2. The canonical Cedar file.
3. The legacy `cedar-runtime.cedar` snapshot (for deployments predating
   generations).

Cold start therefore always lands on one complete generation, never a mix.

## Request transaction

Every public policy write (`POST /api/policies`, `PATCH`, `persist`, `add`,
`add-from-action`, `delete`) on both `leashd` (Linux) and `darwind` (macOS)
runs `commitPolicyTransaction`:

1. Validate/compile the Cedar (unchanged guards).
2. **Persist the complete generation first.** A disk error aborts before any
   in-memory change, so the previous generation stays authoritative.
3. Apply the in-memory layers (runtime overlay, file layer, mode changes).
4. On any post-processing failure, restore every in-memory layer
   (`layerSnapshot` rollback) and return an error. The durable generation is
   already safely on disk and remains recoverable.

Cold start only tracks the recovered generation as the operative Cedar text;
the runtime bootstrap independently loads the canonical file into the file
layer, so rules are never double-applied via a stale runtime overlay.

## Persistent consumer (`WatchCedar`)

The file watcher publishes an update only when a file change is fully readable
and compiles successfully. It additionally tracks a content fingerprint, so
re-writing identical policy (even with a newer mtime) does not re-publish a
generation. Invalid/torn writes keep the previous configuration active and are
surfaced through the error callback while the watcher keeps retrying.

## Guarantees

- **Complete generations only:** public writes and persistent consumers never
  publish partial policy.
- **Recoverable:** a crash or post-processing failure resumes from the last
  fully committed generation instead of reverting to the prior policy.
- **Legitimate old policies survive:** legacy canonical/runtime files are
  still recovered, and old generation objects are retained.
- **Idempotent same-policy writes:** identical Cedar reuses the same
  generation id and does not churn enforcement or create new objects.
