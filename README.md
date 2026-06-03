# Pulp-ext-fs

Filesystem storage capability for Pulp cells. Each cell gets its own scoped filesystem rooted at `<storage-root>/<cell-name>`, keyed by cell name at Register time so no cell can reach another cell's files. Path traversal is rejected at the host boundary before any syscall fires.

From [BananaLabs OSS](https://github.com/BananaLabs-OSS).

## Deployment

```go
import _ "github.com/BananaLabs-OSS/Pulp-ext-fs"
```

## Capability

- `storage.fs` — `fs_read`, `fs_write`, `fs_delete`, `fs_list`, `fs_stat`, `fs_rename`, `fs_remove_all`, `fs_mkdir_all`, `fs_chmod`, `fs_create_temp`, `fs_mkdir_temp`

## Migration

Earlier builds rooted a single shared filesystem at `<storage-root>` itself (the union of every cell's tree). This version scopes each cell to `<storage-root>/<cell-name>`. Files written under the old flat layout now live outside the new per-cell roots; move each cell's files into `<storage-root>/<cell-name>/...` before deploying.
