package vault

type Store interface {
	// Get retrieves a value from the vault by its key.
	Get(key string) (string, error)
	// Set stores a value in the vault with the specified key.
	Set(key, value string) error
	// Delete removes a value from the vault by its key.
	Delete(key string) error
	// List returns a list of all keys stored in the vault.
	List() ([]string, error)
	// Seal seals the vault, making it inaccessible until unsealed.
	Seal() error
	// Unseal unseals the vault using the provided keys.
	Unseal(keys ...string) error
	// Status returns the current status of the vault, such as whether it is sealed or unsealed.
	Status() (string, error)
}
