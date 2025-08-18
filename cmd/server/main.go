package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	"github.com/heimweh/passwort/github.com/heimweh/passwort/api/vaultpb"
	"github.com/heimweh/passwort/pkg/vault"
)

var (
	logger *slog.Logger
	store  vault.Store
)

// vaultServer implements vaultpb.VaultServiceServer
type vaultServer struct {
	vaultpb.UnimplementedVaultServiceServer
	store vault.Store
}

func (s *vaultServer) Seal(ctx context.Context, req *vaultpb.SealRequest) (*vaultpb.SealResponse, error) {
	// If JSONStore, return shares if possible
	if js, ok := s.store.(*vault.JSONStore); ok {
		shares, err := js.SealAndGetShares()
		if err != nil {
			return &vaultpb.SealResponse{Error: err.Error()}, nil
		}
		return &vaultpb.SealResponse{Shares: shares}, nil
	}
	err := s.store.Seal()
	if err != nil {
		return &vaultpb.SealResponse{Error: err.Error()}, nil
	}
	return &vaultpb.SealResponse{}, nil
}

func (s *vaultServer) Unseal(ctx context.Context, req *vaultpb.UnsealRequest) (*vaultpb.UnsealResponse, error) {
	err := s.store.Unseal(req.Keys...)
	if err != nil {
		return &vaultpb.UnsealResponse{Error: err.Error()}, nil
	}
	return &vaultpb.UnsealResponse{}, nil
}

func (s *vaultServer) Status(ctx context.Context, req *vaultpb.StatusRequest) (*vaultpb.StatusResponse, error) {
	status, err := s.store.Status()
	if err != nil {
		return &vaultpb.StatusResponse{Error: err.Error()}, nil
	}
	return &vaultpb.StatusResponse{Status: status}, nil
}

func (s *vaultServer) Get(ctx context.Context, req *vaultpb.GetRequest) (*vaultpb.GetResponse, error) {
	val, err := s.store.Get(req.Key)
	if err != nil {
		return &vaultpb.GetResponse{Error: err.Error()}, nil
	}
	return &vaultpb.GetResponse{Value: val}, nil
}

func (s *vaultServer) Set(ctx context.Context, req *vaultpb.SetRequest) (*vaultpb.SetResponse, error) {
	err := s.store.Set(req.Key, req.Value)
	if err != nil {
		return &vaultpb.SetResponse{Error: err.Error()}, nil
	}
	return &vaultpb.SetResponse{}, nil
}

func (s *vaultServer) Delete(ctx context.Context, req *vaultpb.DeleteRequest) (*vaultpb.DeleteResponse, error) {
	err := s.store.Delete(req.Key)
	if err != nil {
		return &vaultpb.DeleteResponse{Error: err.Error()}, nil
	}
	return &vaultpb.DeleteResponse{}, nil
}

func (s *vaultServer) List(ctx context.Context, req *vaultpb.ListRequest) (*vaultpb.ListResponse, error) {
	keys, err := s.store.List()
	if err != nil {
		return &vaultpb.ListResponse{Error: err.Error()}, nil
	}
	return &vaultpb.ListResponse{Keys: keys}, nil
}

func (s *vaultServer) Init(ctx context.Context, req *vaultpb.InitRequest) (*vaultpb.InitResponse, error) {
	err := s.store.Init()
	if err != nil {
		return &vaultpb.InitResponse{Error: err.Error()}, nil
	}
	if ms, ok := s.store.(*vault.MemoryStore); ok {
		shares, err := ms.GetShares()
		if err != nil {
			return &vaultpb.InitResponse{Error: err.Error()}, nil
		}
		return &vaultpb.InitResponse{Shares: shares}, nil
	}
	if js, ok := s.store.(*vault.JSONStore); ok {
		shares, err := js.SealAndGetShares()
		if err != nil {
			return &vaultpb.InitResponse{Error: err.Error()}, nil
		}
		return &vaultpb.InitResponse{Shares: shares}, nil
	}
	return &vaultpb.InitResponse{Error: "internal error: unknown store type"}, nil
}

func main() {
	var storeType, filePath string
	flag.StringVar(&storeType, "store", "memory", "Store type: memory or json")
	flag.StringVar(&filePath, "file", "vault.json", "Path to JSON file (for json store)")
	flag.Parse()

	logger = slog.New(slog.NewTextHandler(os.Stdout, nil))

	var s vault.Store
	var jsonStore *vault.JSONStore
	if storeType == "json" {
		jsonStore = vault.NewJSONStore(filePath)
		s = jsonStore
		logger.Info("Using JSONStore", slog.String("file", filePath))
	} else {
		s = vault.NewMemoryStore()
		logger.Info("Using MemoryStore")
	}
	store = s

	if len(os.Args) > 1 && os.Args[1] == "init" {
		if storeType == "json" {
			if err := jsonStore.Init(); err != nil {
				logger.Error("Init can only be run once: ", slog.String("error", err.Error()))
				os.Exit(1)
			}
			shares, err := jsonStore.SealAndGetShares()
			if err != nil {
				logger.Error("Failed to get shares", slog.String("error", err.Error()))
				os.Exit(1)
			}
			fmt.Println("Distribute these shares securely. You need at least 2 to unseal:")
			for i, s := range shares {
				fmt.Printf("Share %d: %s\n", i+1, s)
			}
			return
		}
		ms, ok := s.(*vault.MemoryStore)
		if !ok {
			logger.Error("Internal error: not a MemoryStore")
			os.Exit(1)
		}
		if err := ms.Init(); err != nil {
			logger.Error("Init can only be run once: ", slog.String("error", err.Error()))
			os.Exit(1)
		}
		shares, err := ms.GetShares()
		if err != nil {
			logger.Error("Failed to get shares", slog.String("error", err.Error()))
			os.Exit(1)
		}
		fmt.Println("Distribute these shares securely. You need at least 2 to unseal:")
		for i, s := range shares {
			fmt.Printf("Share %d: %s\n", i+1, s)
		}
		return
	}

	// Start gRPC server
	grpcServer := grpc.NewServer()
	vaultpb.RegisterVaultServiceServer(grpcServer, &vaultServer{store: store})
	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		logger.Error("Failed to listen", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info("gRPC server listening on :50051")

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		logger.Info("Shutting down gRPC server...")
		grpcServer.GracefulStop()
	}()

	if err := grpcServer.Serve(listener); err != nil {
		logger.Error("gRPC server failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

// setMemoryStoreKey sets the key field of MemoryStore (helper for init)
func setMemoryStoreKey(ms *vault.MemoryStore, key []byte) {
	ms.SetKey(key)
}
