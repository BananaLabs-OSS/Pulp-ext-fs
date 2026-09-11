package fsext

import (
	"github.com/BananaLabs-OSS/Pulp/ext"
	"os"
	"path/filepath"
	"testing"
)

func grantedManager(t *testing.T, scope ext.Scope, root string, rights ...string) *fsManager {
	t.Helper()
	grants, err := ext.NewStaticPlacementGrants([]ext.PlacementGrant{{Scope: scope, Capability: "storage.fs", Resource: "source", Rights: rights, Attributes: map[string]string{"root": root}}})
	if err != nil {
		t.Fatal(err)
	}
	m := newFSManager()
	host, err := ext.NewScope(scope.ApplicationID(), scope.ApplicationInstanceID(), "host", "primary")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.setup(ext.SetupEnv{Scope: host, StorageRoot: t.TempDir(), PlacementGrants: grants}); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPlacementGrantBindsCanonicalRootAndRights(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	s := testScope(t, "projx", "one", "files", "primary")
	m := grantedManager(t, s, root, "read", "list", "stat")
	f, err := m.forScope(s)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.Read("a.txt"); err != nil || string(got) != "ok" {
		t.Fatal(string(got), err)
	}
	if _, err := f.List("."); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat("a.txt"); err != nil {
		t.Fatal(err)
	}
	if err := f.Write("x", []byte("x"), 0600); err == nil {
		t.Fatal("write allowed")
	}
	if err := f.Delete("a.txt"); err == nil {
		t.Fatal("delete allowed")
	}
	if _, err := f.CreateTemp("", "x"); err == nil {
		t.Fatal("temp allowed")
	}
}

func TestPlacementGrantExactScopeIsolationAndLegacyFallback(t *testing.T) {
	root := t.TempDir()
	s := testScope(t, "projx", "one", "files", "primary")
	other := testScope(t, "projx", "one", "files", "secondary")
	m := grantedManager(t, s, root, "read")
	f, _ := m.forScope(s)
	if f.root != root {
		t.Fatalf("root %q", f.root)
	}
	legacy, err := m.forScope(other)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.root == root {
		t.Fatal("grant crossed application scope")
	}
	if err := legacy.Write("legacy", []byte("ok"), 0600); err != nil {
		t.Fatal("missing explicit grant did not retain legacy behavior", err)
	}
}

func TestPlacementGrantStillRejectsTraversalAndSymlinkEscape(t *testing.T) {
	root, out := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "secret"), []byte("no"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(root, "escape")); err != nil {
		t.Skip(err)
	}
	s := testScope(t, "projx", "one", "files", "primary")
	f, err := grantedManager(t, s, root, "read").forScope(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../secret", "escape/secret"} {
		if _, err := f.Read(p); err == nil {
			t.Fatalf("read %q escaped", p)
		}
	}
}

func TestPlacementGrantRequiresExistingCanonicalRoot(t *testing.T) {
	base := t.TempDir()
	s := testScope(t, "projx", "one", "files", "primary")
	m := grantedManager(t, s, filepath.Join(base, "missing"), "read")
	if _, err := m.forScope(s); err == nil {
		t.Fatal("created missing granted root")
	}
}
