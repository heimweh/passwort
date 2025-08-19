package passwort

import (
	"testing"
)

func TestInmemoryStore_SetGetDelete(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		value     string
		doDelete  bool
		expectErr bool
	}{
		{"set and get", "foo", "bar", false, false},
		{"set, get, delete", "baz", "qux", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewInmemoryStore()
			err := s.Set(tt.key, tt.value)
			if err != nil {
				t.Fatalf("Set failed: %v", err)
			}

			if tt.doDelete {
				// Get before delete should succeed
				got, err := s.Get(tt.key)
				if err != nil {
					t.Fatalf("Get before Delete failed: %v", err)
				}
				if got != tt.value {
					t.Errorf("Get before Delete returned %q, want %q", got, tt.value)
				}
				err = s.Delete(tt.key)
				if err != nil {
					t.Fatalf("Delete failed: %v", err)
				}
				_, err = s.Get(tt.key)
				if (err == nil) != !tt.expectErr {
					t.Errorf("Get after Delete error = %v, want error: %v", err, tt.expectErr)
				}
			} else {
				got, err := s.Get(tt.key)
				if err != nil {
					t.Fatalf("Get failed: %v", err)
				}
				if got != tt.value {
					t.Errorf("Get returned %q, want %q", got, tt.value)
				}
			}
		})
	}
}

func TestInmemoryStore_List(t *testing.T) {
	tests := []struct {
		name  string
		keys  []string
	}{
		{"empty store", []string{}},
		{"multiple keys", []string{"a", "b", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewInmemoryStore()
			for _, k := range tt.keys {
				err := s.Set(k, "val"+k)
				if err != nil {
					t.Fatalf("Set failed: %v", err)
				}
			}
			gotKeys, err := s.List()
			if err != nil {
				t.Fatalf("List failed: %v", err)
			}
			keyMap := make(map[string]bool)
			for _, k := range gotKeys {
				keyMap[k] = true
			}
			for _, k := range tt.keys {
				if !keyMap[k] {
					t.Errorf("List missing key %q", k)
				}
			}
			if len(gotKeys) != len(tt.keys) {
				t.Errorf("List returned %d keys, want %d", len(gotKeys), len(tt.keys))
			}
		})
	}
}
