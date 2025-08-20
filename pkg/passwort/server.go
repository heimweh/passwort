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

	type setRequest struct {
		Value string `json:"value"`
	}

	api.POST("/set/:id", func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			c.Status(http.StatusBadRequest)
			return
		}

		var req setRequest
		if err := c.ShouldBindJSON(&req); err != nil || id == "" || req.Value == "" {
			c.Status(http.StatusBadRequest)
			return
		}
		if err := s.store.Set(id, req.Value); err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	api.GET("/get/:id", func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			c.Status(http.StatusBadRequest)
			return
		}

		val, err := s.store.Get(id)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}

		c.JSON(http.StatusOK, gin.H{"key": id, "value": val})
	})

	api.POST("/delete/:id", func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			c.Status(http.StatusBadRequest)
			return
		}

		if err := s.store.Delete(id); err != nil {
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
		c.JSON(http.StatusOK, gin.H{"keys": keys})
	})

	return r
}

// Run starts the Gin web server on the given address.
func (s *Server) Run(addr string) error {
	return s.Handler().(*gin.Engine).Run(addr)
}
