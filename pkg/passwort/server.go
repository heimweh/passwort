package passwort

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

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

// Handler returns a gin.Engine that exposes endpoints for the store operations using Gin.
func (s *Server) Handler() http.Handler {
	r := gin.New()

	api := r.Group("/api/v1")

	api.POST("/set", func(c *gin.Context) {
		key := c.Query("key")
		val := c.Query("value")
		if key == "" || val == "" {
			c.Status(http.StatusBadRequest)
			return
		}
		if err := s.store.Set(key, val); err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	api.GET("/get", func(c *gin.Context) {
		key := c.Query("key")
		if key == "" {
			c.Status(http.StatusBadRequest)
			return
		}
		val, err := s.store.Get(key)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.String(http.StatusOK, val)
	})

	api.POST("/delete", func(c *gin.Context) {
		key := c.Query("key")
		if key == "" {
			c.Status(http.StatusBadRequest)
			return
		}
		if err := s.store.Delete(key); err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	api.GET("/list", func(c *gin.Context) {
		keys, err := s.store.List()
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.String(http.StatusOK, "%s", gin.H{"keys": keys})
	})

	return r
}

// Run starts the Gin web server on the given address.
func (s *Server) Run(addr string) error {
	return s.Handler().(*gin.Engine).Run(addr)
}
