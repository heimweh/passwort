package main

import (
	"context"
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

func main() {
	logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	store = vault.NewMemoryStore()

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
