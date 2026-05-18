// Package fsext provides the storage.fs capability for Pulp cells,
// giving them a scoped filesystem rooted at <storage-root>/<cell-name>.
// All paths are relative; traversal attempts are rejected at the host
// boundary before any syscall fires.
//
// Deployment:
//
//	import _ "github.com/BananaLabs-OSS/Pulp-ext-fs"
//
// Host imports exposed:
//
//	fs_read(path_ptr, path_len, data_ptr_out, data_len_out) -> error_code
//	fs_write(path_ptr, path_len, data_ptr, data_len) -> error_code
//	fs_delete(path_ptr, path_len) -> error_code
//	fs_list(path_ptr, path_len, entries_ptr_out, entries_len_out) -> error_code
//	fs_stat(req_ptr, req_len, data_ptr_out, data_len_out) -> error_code
//	fs_rename(req_ptr, req_len) -> error_code
//	fs_remove_all(path_ptr, path_len) -> error_code
//	fs_mkdir_all(req_ptr, req_len) -> error_code
//	fs_chmod(req_ptr, req_len) -> error_code
//	fs_create_temp(req_ptr, req_len, data_ptr_out, data_len_out) -> error_code
//	fs_mkdir_temp(req_ptr, req_len, data_ptr_out, data_len_out) -> error_code
package fsext

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/vmihailenco/msgpack/v5"
)

var fsInstance *scopedFS

func init() {
	ext.Register(ext.Capability{
		Name:     "storage.fs",
		Setup:    setup,
		Register: bindActive,
		Stub:     bindStub,
	})
}

func setup(env ext.SetupEnv) error {
	root := filepath.Join(env.StorageRoot, env.CellName)
	abs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve root: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return fmt.Errorf("create root: %w", err)
	}
	fsInstance = &scopedFS{root: abs}
	env.Logger.Info("storage.fs ready", "root", abs)
	return nil
}

// ---- scoped filesystem ----------------------------------------------------

type scopedFS struct {
	root string
}

type FileEntry struct {
	Name  string `msgpack:"name"`
	IsDir bool   `msgpack:"is_dir"`
}

type FileInfo struct {
	Name      string `msgpack:"name"`
	Size      int64  `msgpack:"size"`
	ModTimeNs int64  `msgpack:"mod_time_ns"`
	Mode      uint32 `msgpack:"mode"`
	IsDir     bool   `msgpack:"is_dir"`
}

type statReq struct {
	Path string `msgpack:"path"`
}

type renameReq struct {
	Old string `msgpack:"old"`
	New string `msgpack:"new"`
}

type mkdirAllReq struct {
	Path string `msgpack:"path"`
	Mode uint32 `msgpack:"mode"`
}

type writeReq struct {
	Mode uint32 `msgpack:"mode"`
}

type chmodReq struct {
	Path string `msgpack:"path"`
	Mode uint32 `msgpack:"mode"`
}

type tempReq struct {
	Dir     string `msgpack:"dir"`
	Pattern string `msgpack:"pattern"`
}

type tempResp struct {
	Path string `msgpack:"path"`
}

func (f *scopedFS) resolve(rel string) (string, error) {
	if rel == "" {
		return "", errors.New("empty path")
	}
	if strings.ContainsRune(rel, 0) {
		return "", errors.New("null byte in path")
	}
	if strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, `\`) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute path %q not allowed", rel)
	}
	clean := filepath.Clean(filepath.Join(f.root, rel))
	rootWithSep := f.root + string(filepath.Separator)
	if clean != f.root && !strings.HasPrefix(clean+string(filepath.Separator), rootWithSep) {
		return "", fmt.Errorf("path %q escapes root", rel)
	}
	// Defence in depth: if any component on the path already exists and
	// is a symlink, refuse to follow it. A symlink planted inside the
	// root (e.g., via an earlier Write that restored a tarball) would
	// otherwise let os.ReadFile / os.Remove / etc. escape the scope,
	// since filepath.Clean is purely lexical.
	if err := f.checkNoSymlinkEscape(clean); err != nil {
		return "", err
	}
	return clean, nil
}

// checkNoSymlinkEscape walks each existing ancestor of target (up to
// but not including f.root) and fails if any of them is a symlink
// whose resolved target lies outside f.root. Non-existent components
// are allowed — they cannot currently escape, and a later syscall
// will either create a regular file/dir or fail cleanly.
func (f *scopedFS) checkNoSymlinkEscape(target string) error {
	if target == f.root {
		return nil
	}
	rel, err := filepath.Rel(f.root, target)
	if err != nil {
		return fmt.Errorf("path %q escapes root", target)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	cur := f.root
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				// Remaining components don't exist yet; nothing to follow.
				return nil
			}
			return fmt.Errorf("stat %q: %w", cur, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		resolved, err := filepath.EvalSymlinks(cur)
		if err != nil {
			return fmt.Errorf("resolve symlink %q: %w", cur, err)
		}
		absResolved, err := filepath.Abs(resolved)
		if err != nil {
			return fmt.Errorf("abs symlink %q: %w", cur, err)
		}
		rootWithSep := f.root + string(filepath.Separator)
		if absResolved != f.root && !strings.HasPrefix(absResolved+string(filepath.Separator), rootWithSep) {
			return fmt.Errorf("path %q escapes root via symlink", target)
		}
	}
	return nil
}

func (f *scopedFS) Read(rel string) ([]byte, error) {
	abs, err := f.resolve(rel)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(abs)
}

func (f *scopedFS) Write(rel string, data []byte, mode os.FileMode) error {
	abs, err := f.resolve(rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	return os.WriteFile(abs, data, mode)
}

func (f *scopedFS) Delete(rel string) error {
	abs, err := f.resolve(rel)
	if err != nil {
		return err
	}
	return os.Remove(abs)
}

func (f *scopedFS) List(rel string) ([]FileEntry, error) {
	abs, err := f.resolve(rel)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	result := make([]FileEntry, len(entries))
	for i, e := range entries {
		result[i] = FileEntry{Name: e.Name(), IsDir: e.IsDir()}
	}
	return result, nil
}

func (f *scopedFS) Stat(rel string) (FileInfo, error) {
	abs, err := f.resolve(rel)
	if err != nil {
		return FileInfo{}, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{
		Name:      info.Name(),
		Size:      info.Size(),
		ModTimeNs: info.ModTime().UnixNano(),
		Mode:      uint32(info.Mode()),
		IsDir:     info.IsDir(),
	}, nil
}

func (f *scopedFS) Rename(oldRel, newRel string) error {
	oldAbs, err := f.resolve(oldRel)
	if err != nil {
		return err
	}
	newAbs, err := f.resolve(newRel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(newAbs), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	return os.Rename(oldAbs, newAbs)
}

func (f *scopedFS) RemoveAll(rel string) error {
	abs, err := f.resolve(rel)
	if err != nil {
		return err
	}
	return os.RemoveAll(abs)
}

func (f *scopedFS) MkdirAll(rel string, mode os.FileMode) error {
	abs, err := f.resolve(rel)
	if err != nil {
		return err
	}
	return os.MkdirAll(abs, mode)
}

func (f *scopedFS) Chmod(rel string, mode os.FileMode) error {
	abs, err := f.resolve(rel)
	if err != nil {
		return err
	}
	return os.Chmod(abs, mode&0o777)
}

// relFromRoot returns abs as a forward-slash path relative to f.root.
func (f *scopedFS) relFromRoot(abs string) (string, error) {
	rel, err := filepath.Rel(f.root, abs)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// CreateTemp creates a temp file inside the cell's scoped root and returns
// the resulting path relative to that root. If dir is empty, the default
// "tmp/" directory under the scoped root is used (and created if missing).
func (f *scopedFS) CreateTemp(dir, pattern string) (string, error) {
	var parent string
	if dir == "" {
		parent = filepath.Join(f.root, "tmp")
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return "", fmt.Errorf("mkdir tmp: %w", err)
		}
	} else {
		abs, err := f.resolve(dir)
		if err != nil {
			return "", err
		}
		parent = abs
	}
	file, err := os.CreateTemp(parent, pattern)
	if err != nil {
		return "", err
	}
	name := file.Name()
	_ = file.Close()
	return f.relFromRoot(name)
}

// MkdirTemp creates a temp dir inside the cell's scoped root and returns
// the resulting path relative to that root. If dir is empty, the default
// "tmp/" directory under the scoped root is used (and created if missing).
func (f *scopedFS) MkdirTemp(dir, pattern string) (string, error) {
	var parent string
	if dir == "" {
		parent = filepath.Join(f.root, "tmp")
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return "", fmt.Errorf("mkdir tmp: %w", err)
		}
	} else {
		abs, err := f.resolve(dir)
		if err != nil {
			return "", err
		}
		parent = abs
	}
	created, err := os.MkdirTemp(parent, pattern)
	if err != nil {
		return "", err
	}
	return f.relFromRoot(created)
}

// ---- capability binding ----------------------------------------------------

func bindActive(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().WithFunc(fsRead).Export("fs_read")
	b.NewFunctionBuilder().WithFunc(fsWrite).Export("fs_write")
	b.NewFunctionBuilder().WithFunc(fsDelete).Export("fs_delete")
	b.NewFunctionBuilder().WithFunc(fsList).Export("fs_list")
	b.NewFunctionBuilder().WithFunc(fsStat).Export("fs_stat")
	b.NewFunctionBuilder().WithFunc(fsRename).Export("fs_rename")
	b.NewFunctionBuilder().WithFunc(fsRemoveAll).Export("fs_remove_all")
	b.NewFunctionBuilder().WithFunc(fsMkdirAll).Export("fs_mkdir_all")
	b.NewFunctionBuilder().WithFunc(fsChmod).Export("fs_chmod")
	b.NewFunctionBuilder().WithFunc(fsCreateTemp).Export("fs_create_temp")
	b.NewFunctionBuilder().WithFunc(fsMkdirTemp).Export("fs_mkdir_temp")
	return nil
}

func bindStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	nop6 := func(_ context.Context, _ api.Module, _, _, _, _, _, _ uint32) uint32 { return 99 }
	nop4 := func(_ context.Context, _ api.Module, _, _, _, _ uint32) uint32 { return 99 }
	nop2 := func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }
	b.NewFunctionBuilder().WithFunc(nop4).Export("fs_read")
	b.NewFunctionBuilder().WithFunc(nop6).Export("fs_write")
	b.NewFunctionBuilder().WithFunc(nop2).Export("fs_delete")
	b.NewFunctionBuilder().WithFunc(nop4).Export("fs_list")
	b.NewFunctionBuilder().WithFunc(nop4).Export("fs_stat")
	b.NewFunctionBuilder().WithFunc(nop2).Export("fs_rename")
	b.NewFunctionBuilder().WithFunc(nop2).Export("fs_remove_all")
	b.NewFunctionBuilder().WithFunc(nop2).Export("fs_mkdir_all")
	b.NewFunctionBuilder().WithFunc(nop2).Export("fs_chmod")
	b.NewFunctionBuilder().WithFunc(nop4).Export("fs_create_temp")
	b.NewFunctionBuilder().WithFunc(nop4).Export("fs_mkdir_temp")
	return nil
}

// ---- handlers --------------------------------------------------------------

func fsRead(ctx context.Context, m api.Module, pathPtr, pathLen, dataPtrOut, dataLenOut uint32) uint32 {
	if pathLen == 0 {
		return 1
	}
	pathData, ok := m.Memory().Read(pathPtr, pathLen)
	if !ok {
		return 2
	}
	content, err := fsInstance.Read(string(pathData))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 6
		}
		return pathErrCode(err)
	}
	return writeResponse(ctx, m, content, dataPtrOut, dataLenOut)
}

// fsWrite now takes six args: path_ptr, path_len, data_ptr, data_len, req_ptr, req_len.
// The req buffer carries optional mode via msgpack; absent/zero defaults to 0o644.
func fsWrite(_ context.Context, m api.Module, pathPtr, pathLen, dataPtr, dataLen, reqPtr, reqLen uint32) uint32 {
	if pathLen == 0 {
		return 1
	}
	pathData, ok := m.Memory().Read(pathPtr, pathLen)
	if !ok {
		return 2
	}
	var content []byte
	if dataLen > 0 {
		content, ok = m.Memory().Read(dataPtr, dataLen)
		if !ok {
			return 2
		}
	}
	mode := os.FileMode(0o644)
	if reqLen > 0 {
		reqBytes, ok := m.Memory().Read(reqPtr, reqLen)
		if !ok {
			return 2
		}
		var req writeReq
		if err := msgpack.Unmarshal(reqBytes, &req); err != nil {
			return 3
		}
		if req.Mode != 0 {
			mode = os.FileMode(req.Mode)
		}
	}
	if err := fsInstance.Write(string(pathData), content, mode); err != nil {
		return pathErrCode(err)
	}
	return 0
}

func fsDelete(_ context.Context, m api.Module, pathPtr, pathLen uint32) uint32 {
	if pathLen == 0 {
		return 1
	}
	pathData, ok := m.Memory().Read(pathPtr, pathLen)
	if !ok {
		return 2
	}
	if err := fsInstance.Delete(string(pathData)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 6
		}
		return pathErrCode(err)
	}
	return 0
}

func fsList(ctx context.Context, m api.Module, pathPtr, pathLen, dataPtrOut, dataLenOut uint32) uint32 {
	if pathLen == 0 {
		return 1
	}
	pathData, ok := m.Memory().Read(pathPtr, pathLen)
	if !ok {
		return 2
	}
	entries, err := fsInstance.List(string(pathData))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 6
		}
		return pathErrCode(err)
	}
	encoded, err := msgpack.Marshal(entries)
	if err != nil {
		return 4
	}
	return writeResponse(ctx, m, encoded, dataPtrOut, dataLenOut)
}

func fsStat(ctx context.Context, m api.Module, reqPtr, reqLen, dataPtrOut, dataLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	reqBytes, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req statReq
	if err := msgpack.Unmarshal(reqBytes, &req); err != nil {
		return 3
	}
	info, err := fsInstance.Stat(req.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 6
		}
		return pathErrCode(err)
	}
	encoded, err := msgpack.Marshal(info)
	if err != nil {
		return 4
	}
	return writeResponse(ctx, m, encoded, dataPtrOut, dataLenOut)
}

func fsRename(_ context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	reqBytes, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req renameReq
	if err := msgpack.Unmarshal(reqBytes, &req); err != nil {
		return 3
	}
	if err := fsInstance.Rename(req.Old, req.New); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 6
		}
		return pathErrCode(err)
	}
	return 0
}

func fsRemoveAll(_ context.Context, m api.Module, pathPtr, pathLen uint32) uint32 {
	if pathLen == 0 {
		return 1
	}
	pathData, ok := m.Memory().Read(pathPtr, pathLen)
	if !ok {
		return 2
	}
	if err := fsInstance.RemoveAll(string(pathData)); err != nil {
		return pathErrCode(err)
	}
	return 0
}

func fsMkdirAll(_ context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	reqBytes, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req mkdirAllReq
	if err := msgpack.Unmarshal(reqBytes, &req); err != nil {
		return 3
	}
	mode := os.FileMode(0o755)
	if req.Mode != 0 {
		mode = os.FileMode(req.Mode)
	}
	if err := fsInstance.MkdirAll(req.Path, mode); err != nil {
		return pathErrCode(err)
	}
	return 0
}

func fsChmod(_ context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	reqBytes, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req chmodReq
	if err := msgpack.Unmarshal(reqBytes, &req); err != nil {
		return 3
	}
	if err := fsInstance.Chmod(req.Path, os.FileMode(req.Mode)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 6
		}
		return pathErrCode(err)
	}
	return 0
}

func fsCreateTemp(ctx context.Context, m api.Module, reqPtr, reqLen, dataPtrOut, dataLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	reqBytes, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req tempReq
	if err := msgpack.Unmarshal(reqBytes, &req); err != nil {
		return 3
	}
	rel, err := fsInstance.CreateTemp(req.Dir, req.Pattern)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 6
		}
		return pathErrCode(err)
	}
	encoded, err := msgpack.Marshal(tempResp{Path: rel})
	if err != nil {
		return 4
	}
	return writeResponse(ctx, m, encoded, dataPtrOut, dataLenOut)
}

func fsMkdirTemp(ctx context.Context, m api.Module, reqPtr, reqLen, dataPtrOut, dataLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	reqBytes, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req tempReq
	if err := msgpack.Unmarshal(reqBytes, &req); err != nil {
		return 3
	}
	rel, err := fsInstance.MkdirTemp(req.Dir, req.Pattern)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 6
		}
		return pathErrCode(err)
	}
	encoded, err := msgpack.Marshal(tempResp{Path: rel})
	if err != nil {
		return 4
	}
	return writeResponse(ctx, m, encoded, dataPtrOut, dataLenOut)
}

// ---- helpers ---------------------------------------------------------------

func writeResponse(ctx context.Context, m api.Module, data []byte, ptrOut, lenOut uint32) uint32 {
	allocFn := m.ExportedFunction("pulp_alloc")
	if allocFn == nil {
		return 7
	}
	var ptr uint32
	if len(data) > 0 {
		results, err := allocFn.Call(ctx, uint64(len(data)))
		if err != nil || len(results) == 0 {
			return 7
		}
		ptr = uint32(results[0])
		if ptr == 0 {
			return 7
		}
		if !m.Memory().Write(ptr, data) {
			return 8
		}
	}
	if !m.Memory().WriteUint32Le(ptrOut, ptr) {
		return 8
	}
	if !m.Memory().WriteUint32Le(lenOut, uint32(len(data))) {
		return 8
	}
	return 0
}

func pathErrCode(err error) uint32 {
	if err == nil {
		return 0
	}
	msg := err.Error()
	if strings.Contains(msg, "absolute path") || strings.Contains(msg, "escapes root") ||
		strings.Contains(msg, "escapes root via symlink") ||
		strings.Contains(msg, "null byte") || strings.Contains(msg, "empty path") {
		return 5
	}
	return 4
}
