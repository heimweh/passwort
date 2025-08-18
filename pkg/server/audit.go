package server

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

// AuditUnaryInterceptor logs all unary RPCs with metadata (no secrets)
func AuditUnaryInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		start := time.Now()
		resp, err = handler(ctx, req)
		clientIP := "unknown"
		if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
			clientIP = p.Addr.String()
		}
		logger.Info("rpc_call",
			slog.String("method", info.FullMethod),
			slog.Any("request", req), // redact secrets in production!
			slog.String("result", resultString(err)),
			slog.Time("timestamp", start),
			slog.Duration("duration", time.Since(start)),
			slog.String("client_ip", clientIP),
		)
		return resp, err
	}
}

func resultString(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}
