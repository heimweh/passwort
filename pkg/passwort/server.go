package passwort

type Server struct {
	// store is the storage backend for the server.
	store Store

	// cipher is the encryption/decryption mechanism used by the server.
	cipher Cipher
}

// Option defines a function type for configuring the Server.
type Option func(*Server)

// NewServer creates a new Server instance with the provided store and options.
func NewServer(store Store, options ...Option) *Server {
	s := &Server{
		store: store,
	}

	for _, opt := range options {
		opt(s)
	}

	return s
}
