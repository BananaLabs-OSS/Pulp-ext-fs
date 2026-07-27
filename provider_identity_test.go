package fsext

import (
	"testing"

	"github.com/BananaLabs-OSS/Pulp/ext"
)

func TestStorageFSCapabilityHasExactProviderIdentity(t *testing.T) {
	const provider = "github.com/BananaLabs-OSS/Pulp-ext-fs"
	for _, capability := range ext.All() {
		if capability.Name != "storage.fs" {
			continue
		}
		if capability.Provider != provider {
			t.Fatalf("storage.fs provider = %q, want exact module identity %q", capability.Provider, provider)
		}
		return
	}
	t.Fatal("storage.fs capability was not registered")
}
