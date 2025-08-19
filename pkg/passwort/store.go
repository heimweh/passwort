package passwort

// Store defines the interface for a password storage system.
// Examples include in-memory storage, file-based storage, or database storage.
type Store interface {
	// Get retrieves a password by its ID.
	Get(id string) (string, error)
	// Set stores a password with the given ID.
	Set(id, password string) error
	// Delete removes a password by its ID.
	Delete(id string) error
	// List returns a list of all stored password IDs.
	List() ([]string, error)
}
