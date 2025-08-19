package passwort

import (
	"testing"
)

func TestInmemoryStore_SetGetDelete(t *testing.T) {
	s := NewInmemoryStore()

	// Test Set and Get
	key, value := "foo", "bar"
	err := s.Set(key, value)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	got, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != value {
		t.Errorf("Get returned %q, want %q", got, value)
	}

	// Test Delete
	err = s.Delete(key)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, err = s.Get(key)
	if err == nil {
		t.Errorf("Get after Delete should return error, got nil")
	}
}

func TestInmemoryStore_ListKeys(t *testing.T) {
	s := NewInmemoryStore()
	keys := []string{"a", "b", "c"}
	for _, k := range keys {
		err := s.Set(k, "val"+k)
		if err != nil {
			t.Fatalf("Set failed: %v", err)
		}
	}
	gotKeys := s.ListKeys()
	keyMap := make(map[string]bool)
	for _, k := range gotKeys {
		keyMap[k] = true
	}
	for _, k := range keys {
		if !keyMap[k] {
			t.Errorf("ListKeys missing key %q", k)
		}
	}
}
