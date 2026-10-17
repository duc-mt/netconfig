package memory

import (
	"path/filepath"
	"testing"
)

func TestStoreOperations(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test_memory.json")

	store, err := Load(path)
	if err != nil {
		t.Fatalf("Load empty failed: %v", err)
	}

	// 1. Record route
	if err := store.Record("NHG-VYOS", "10.255.255.1", "NHG-TRANSIT-GW-01", "10.255.255.4:22", "auto-fallback"); err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	// 2. Lookup by IP
	rec, ok := store.Get("10.255.255.1")
	if !ok {
		t.Fatal("Get by IP failed")
	}
	if rec.JumpEndpoint != "10.255.255.4:22" {
		t.Fatalf("unexpected jump endpoint: %s", rec.JumpEndpoint)
	}
	if rec.JumpHost != "NHG-TRANSIT-GW-01" {
		t.Fatalf("unexpected jump host: %s", rec.JumpHost)
	}

	// 3. Lookup by Hostname
	rec2, ok := store.Get("NHG-VYOS")
	if !ok {
		t.Fatal("Get by Hostname failed")
	}
	if rec2.JumpEndpoint != "10.255.255.4:22" {
		t.Fatalf("unexpected jump endpoint: %s", rec2.JumpEndpoint)
	}

	// 4. Persistence reload
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	rec3, ok := reloaded.Get("10.255.255.1")
	if !ok {
		t.Fatal("Get after reload failed")
	}
	if rec3.JumpEndpoint != "10.255.255.4:22" {
		t.Fatalf("reloaded jump endpoint mismatch: %s", rec3.JumpEndpoint)
	}
	if rec3.SuccessCount != 1 {
		t.Fatalf("success count mismatch: %d", rec3.SuccessCount)
	}

	// 5. Update route
	if err := reloaded.Record("NHG-VYOS", "10.255.255.1", "NHG-TRANSIT-GW-02", "10.255.255.5:22", "auto-fallback-updated"); err != nil {
		t.Fatalf("Record update failed: %v", err)
	}
	rec4, _ := reloaded.Get("10.255.255.1")
	if rec4.SuccessCount != 2 || rec4.JumpEndpoint != "10.255.255.5:22" {
		t.Fatalf("updated record mismatch: %+v", rec4)
	}

	// 6. List
	list := reloaded.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 record in list, got %d", len(list))
	}

	// 7. Forget
	if err := reloaded.Forget("10.255.255.1", "NHG-VYOS"); err != nil {
		t.Fatalf("Forget failed: %v", err)
	}
	if _, ok := reloaded.Get("10.255.255.1"); ok {
		t.Fatal("route still exists after Forget")
	}

	// 8. Clear
	if err := reloaded.Clear(); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}
	if len(reloaded.List()) != 0 {
		t.Fatal("list not empty after Clear")
	}
}
