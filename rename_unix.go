//go:build !windows

package fsext

import "os"

func atomicReplace(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }
