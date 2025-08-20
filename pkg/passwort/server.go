package passwort

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type Server struct {
	// store is the storage backend for the server.
	store Store

	// cipher is the encryption/decryption mechanism used by the server.
	cipher Cipher

	// authToken is the token used for authenticating requests.
	authToken string
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

// Optionally, you can add an Option to set the auth token
func WithAuthToken(token string) Option {
	return func(s *Server) {
		s.authToken = token
	}
}

// Handler returns a gin.Engine that exposes endpoints for the store operations using Gin.
func (s *Server) Handler() http.Handler {
	r := gin.New()

	authMiddleware := func(c *gin.Context) {
		token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")

		if s.authToken != "" && token != s.authToken {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}

	api := r.Group("/api/v1", authMiddleware)

	type secretRequest struct {
		Value string `json:"value"`
	}

	// Create secret
	api.POST("/secrets", func(c *gin.Context) {
		var req secretRequest
		if err := c.ShouldBindJSON(&req); err != nil || req.Value == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		// Generate a new ID (for demo, use a UUID or similar in production)
		id := c.Query("id")
		if id == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
			return
		}
		if err := s.store.Set(id, req.Value); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"key": id, "value": req.Value})
	})

	// Get secret
	api.GET("/secrets/:id", func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
			return
		}
		val, err := s.store.Get(id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"key": id, "value": val})
	})

	// Update secret
	api.PUT("/secrets/:id", func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
			return
		}
		var req secretRequest
		if err := c.ShouldBindJSON(&req); err != nil || req.Value == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if err := s.store.Set(id, req.Value); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"key": id, "value": req.Value})
	})

	// Delete secret
	api.DELETE("/secrets/:id", func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
			return
		}
		if err := s.store.Delete(id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusNoContent)
	})

	// List secrets
	api.GET("/secrets", func(c *gin.Context) {
		keys, err := s.store.List()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"keys": keys})
	})

	return r
}

// Run starts the Gin web server on the given address.
func (s *Server) Run(addr string) error {
	return s.Handler().(*gin.Engine).Run(addr)
}
