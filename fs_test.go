package fsext

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/BananaLabs-OSS/Pulp/ext"
)

// newManager returns a fresh fsManager rooted at a temp storage dir, so
// tests don't share the package-global instance.
func newManager(t *testing.T) *fsManager {
	t.Helper()
	mgr := newFSManager()
	mgr.storageRoot = t.TempDir()
	mgr.logger = slog.Default()
	return mgr
}

func testScope(t *testing.T, app, appInstance, cell, cellInstance string) ext.Scope {
	t.Helper()
	scope, err := ext.NewScope(app, appInstance, cell, cellInstance)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

// TestCellCannotReachSiblingPath is the core tenant-isolation guarantee:
// cell A must not be able to read, write, list, or delete cell B's
// files, including via ../ traversal that targets the sibling's root.
func TestCellCannotReachSiblingPath(t *testing.T) {
	mgr := newManager(t)

	fsA, err := mgr.forCell("alpha")
	if err != nil {
		t.Fatalf("forCell(alpha): %v", err)
	}
	fsB, err := mgr.forCell("beta")
	if err != nil {
		t.Fatalf("forCell(beta): %v", err)
	}

	// Roots must be distinct per-cell subdirs, not the shared parent.
	if fsA.root == fsB.root {
		t.Fatalf("cells share a root: %q", fsA.root)
	}
	if filepath.Base(fsA.root) != "alpha" || filepath.Base(fsB.root) != "beta" {
		t.Fatalf("unexpected roots: alpha=%q beta=%q", fsA.root, fsB.root)
	}
	if got := filepath.Dir(fsA.root); got != mgr.storageRoot {
		t.Fatalf("alpha root not under storage root: %q vs %q", got, mgr.storageRoot)
	}

	// Cell B writes a secret in its own root.
	const secret = "cross-tenant secret"
	if err := fsB.Write("secrets.env", []byte(secret), 0o600); err != nil {
		t.Fatalf("beta write: %v", err)
	}

	// Cell A tries to traverse into beta's root. Every variant must be
	// rejected by resolve before any syscall, regardless of whether the
	// target file exists.
	escapes := []string{
		"../beta/secrets.env",
		"../../beta/secrets.env",
		"./../beta/secrets.env",
		"../beta",
		"..",
	}
	for _, p := range escapes {
		if _, err := fsA.Read(p); err == nil {
			t.Errorf("alpha Read(%q) succeeded; expected escape rejection", p)
		} else if !strings.Contains(err.Error(), "escapes root") {
			t.Errorf("alpha Read(%q) wrong error: %v", p, err)
		}
		if err := fsA.Write(p, []byte("pwned"), 0o644); err == nil {
			t.Errorf("alpha Write(%q) succeeded; expected escape rejection", p)
		}
		if err := fsA.Delete(p); err == nil {
			t.Errorf("alpha Delete(%q) succeeded; expected escape rejection", p)
		}
		if _, err := fsA.List(p); err == nil {
			t.Errorf("alpha List(%q) succeeded; expected escape rejection", p)
		}
		if err := fsA.RemoveAll(p); err == nil {
			t.Errorf("alpha RemoveAll(%q) succeeded; expected escape rejection", p)
		}
	}

	// Beta's secret must be intact and unreadable from alpha's view.
	got, err := fsB.Read("secrets.env")
	if err != nil {
		t.Fatalf("beta re-read: %v", err)
	}
	if string(got) != secret {
		t.Fatalf("beta secret corrupted: %q", got)
	}

	// Alpha listing "." must only see alpha's own tree, never "beta".
	if err := fsA.Write("mine.txt", []byte("hi"), 0o644); err != nil {
		t.Fatalf("alpha write: %v", err)
	}
	entries, err := fsA.List(".")
	if err != nil {
		t.Fatalf("alpha list: %v", err)
	}
	for _, e := range entries {
		if e.Name == "beta" || e.Name == "secrets.env" {
			t.Errorf("alpha List(.) leaked sibling entry %q", e.Name)
		}
	}
}

// TestRemoveAllRootGuard verifies that RemoveAll(".")/root-equivalent paths
// are rejected so a cell cannot nuke its entire storage root (audit B5).
func TestRemoveAllRootGuard(t *testing.T) {
	mgr := newManager(t)
	fs, err := mgr.forCell("alpha")
	if err != nil {
		t.Fatalf("forCell: %v", err)
	}

	// Write a file so the root is non-empty; the guard should fire before
	// any filesystem mutation.
	if err := fs.Write("canary.txt", []byte("alive"), 0o644); err != nil {
		t.Fatalf("write canary: %v", err)
	}

	rootEquiv := []string{".", "./", "./."}
	for _, p := range rootEquiv {
		if err := fs.RemoveAll(p); err == nil {
			t.Errorf("RemoveAll(%q) succeeded; expected root-guard rejection", p)
		}
	}

	// Canary must still exist — no deletion should have occurred.
	if _, err := fs.Read("canary.txt"); err != nil {
		t.Fatalf("canary.txt missing after root-guard test: %v", err)
	}

	// Subdirectory deletes must still work.
	if err := fs.MkdirAll("subdir", 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := fs.RemoveAll("subdir"); err != nil {
		t.Fatalf("RemoveAll(subdir) failed: %v", err)
	}
}

// TestManagerScopesByCellID confirms forCell is idempotent per cell and
// that get() only returns a registered cell.
func TestManagerScopesByCellID(t *testing.T) {
	mgr := newManager(t)

	first, err := mgr.forCell("alpha")
	if err != nil {
		t.Fatalf("forCell: %v", err)
	}
	second, err := mgr.forCell("alpha")
	if err != nil {
		t.Fatalf("forCell again: %v", err)
	}
	if first != second {
		t.Fatalf("forCell not idempotent: %p vs %p", first, second)
	}
	if _, ok := mgr.get("alpha"); !ok {
		t.Fatalf("get(alpha) missing after register")
	}
	if _, ok := mgr.get("ghost"); ok {
		t.Fatalf("get(ghost) returned an instance for an unregistered cell")
	}
}

// TestSanitizeCellID rejects names that would escape the storage root
// when used as a single path component.
func TestSanitizeCellID(t *testing.T) {
	bad := []string{"", ".", "..", "a/b", `a\b`, "../evil", "/abs", "a:b", "x\x00y"}
	for _, name := range bad {
		if err := sanitizeCellID(name); err == nil {
			t.Errorf("sanitizeCellID(%q) accepted a malicious cell id", name)
		}
	}
	good := []string{"alpha", "cell-1", "cell_2", "a.b.c", "AbC123"}
	for _, name := range good {
		if err := sanitizeCellID(name); err != nil {
			t.Errorf("sanitizeCellID(%q) rejected a valid cell id: %v", name, err)
		}
	}

	// A malicious cell name must never be turned into a root outside the
	// storage tree.
	mgr := newManager(t)
	if _, err := mgr.forCell("../escape"); err == nil {
		t.Fatalf("forCell(../escape) succeeded; expected rejection")
	}
	if _, err := os.Stat(filepath.Join(mgr.storageRoot, "..", "escape")); err == nil {
		t.Fatalf("forCell created a directory outside the storage root")
	}
}

func TestTwoApplicationScopeLifecycle(t *testing.T) {
	mgr := newManager(t)
	evolutionHost := testScope(t, "evolution", "blue", "host", "primary")
	sessionsHost := testScope(t, "sessions", "green", "host", "primary")
	evolutionRoot := filepath.Join(mgr.storageRoot, "evolution-store", "blue")
	sessionsRoot := filepath.Join(mgr.storageRoot, "sessions-store", "green")
	if err := mgr.setup(ext.SetupEnv{Scope: evolutionHost, StorageRoot: evolutionRoot}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.setup(ext.SetupEnv{Scope: sessionsHost, StorageRoot: sessionsRoot}); err != nil {
		t.Fatal(err)
	}
	evolution := testScope(t, "evolution", "blue", "storage", "primary")
	sessions := testScope(t, "sessions", "green", "storage", "primary")
	left, err := mgr.forScope(evolution)
	if err != nil {
		t.Fatal(err)
	}
	right, err := mgr.forScope(sessions)
	if err != nil {
		t.Fatal(err)
	}
	if left == right || left.root == right.root {
		t.Fatal("two applications share mutable filesystem state")
	}
	if err := left.Write("owner.txt", []byte("evolution"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := right.Read("owner.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Sessions observed Evolution state: %v", err)
	}
	if err := mgr.teardownScope(evolutionHost); err != nil {
		t.Fatal(err)
	}
	if _, ok := mgr.getScope(evolution); ok {
		t.Fatal("Evolution instance survived scoped teardown")
	}
	if _, ok := mgr.getScope(sessions); !ok {
		t.Fatal("Evolution teardown removed Sessions")
	}
	if err := mgr.teardownScope(evolutionHost); err != nil {
		t.Fatalf("repeated teardown is not idempotent: %v", err)
	}
	if err := mgr.setup(ext.SetupEnv{Scope: sessionsHost, StorageRoot: filepath.Join(mgr.storageRoot, "replacement")}); err == nil {
		t.Fatal("live Sessions root was replaced")
	}
}

func TestLegacyLifecycleReleasesOnlyLegacySetup(t *testing.T) {
	mgr := newManager(t)
	firstLegacyRoot := filepath.Join(mgr.storageRoot, "legacy-one")
	if err := mgr.setup(ext.SetupEnv{StorageRoot: firstLegacyRoot}); err != nil {
		t.Fatal(err)
	}
	sessionsHost := testScope(t, "sessions", "green", "host", "primary")
	sessionsRoot := filepath.Join(mgr.storageRoot, "sessions")
	if err := mgr.setup(ext.SetupEnv{Scope: sessionsHost, StorageRoot: sessionsRoot}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.teardownScope(ext.LegacyScope("default")); err != nil {
		t.Fatal(err)
	}
	if err := mgr.setup(ext.SetupEnv{StorageRoot: filepath.Join(mgr.storageRoot, "legacy-two")}); err != nil {
		t.Fatalf("legacy setup lease survived teardown: %v", err)
	}
	if err := mgr.setup(ext.SetupEnv{Scope: sessionsHost, StorageRoot: filepath.Join(mgr.storageRoot, "wrong")}); err == nil {
		t.Fatal("legacy teardown released a live scoped setup")
	}
}

func TestTwoApplicationScopeRace(t *testing.T) {
	mgr := newManager(t)
	aHost := testScope(t, "evolution", "blue", "host", "primary")
	bHost := testScope(t, "sessions", "green", "host", "primary")
	aRoot := filepath.Join(mgr.storageRoot, "a")
	bRoot := filepath.Join(mgr.storageRoot, "b")
	aCell := testScope(t, "evolution", "blue", "storage", "primary")
	bCell := testScope(t, "sessions", "green", "storage", "primary")
	if err := mgr.setup(ext.SetupEnv{Scope: bHost, StorageRoot: bRoot}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.forScope(bCell); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if err := mgr.setup(ext.SetupEnv{Scope: aHost, StorageRoot: aRoot}); err != nil {
				errCh <- err
				return
			}
			if _, err := mgr.forScope(aCell); err != nil {
				errCh <- err
				return
			}
			if err := mgr.teardownScope(aHost); err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if _, ok := mgr.getScope(bCell); !ok {
				errCh <- fmt.Errorf("Sessions disappeared during Evolution lifecycle")
				return
			}
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
