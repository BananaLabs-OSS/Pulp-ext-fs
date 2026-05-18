# Pulp-ext-fs

Filesystem storage capability for Pulp cells. Each cell gets a scoped filesystem rooted at `<storage-root>/<cell-name>`. Path traversal is rejected at the host boundary before any syscall fires.

From [BananaLabs OSS](https://github.com/BananaLabs-OSS).

## Deployment

```go
import _ "github.com/BananaLabs-OSS/Pulp-ext-fs"
```

## Capability

- `storage.fs` — `fs_read`, `fs_write`, `fs_delete`, `fs_list`, `fs_stat`, `fs_rename`, `fs_remove_all`, `fs_mkdir_all`, `fs_chmod`
