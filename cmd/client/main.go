package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/heimweh/passwort/github.com/heimweh/passwort/api/vaultpb"
)

var serverAddr string

func main() {
	rootCmd := &cobra.Command{
		Use:   "vaultctl",
		Short: "CLI client for the vault gRPC server",
	}

	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "localhost:50051", "gRPC server address")

	rootCmd.AddCommand(
		sealCmd(),
		unsealCmd(),
		statusCmd(),
		getCmd(),
		setCmd(),
		deleteCmd(),
		listCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func dial() (vaultpb.VaultServiceClient, *grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, serverAddr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, nil, err
	}
	client := vaultpb.NewVaultServiceClient(conn)
	return client, conn, nil
}

func sealCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "seal",
		Short: "Seal the vault",
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := dial()
			if err != nil {
				fmt.Println("Dial error:", err)
				os.Exit(1)
			}
			defer conn.Close()
			resp, err := client.Seal(context.Background(), &vaultpb.SealRequest{})
			if err != nil || resp.Error != "" {
				fmt.Println("Seal error:", err, resp.GetError())
				os.Exit(1)
			}
			fmt.Println("Vault sealed")
		},
	}
}

func unsealCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unseal [keys...]",
		Short: "Unseal the vault",
		Args:  cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := dial()
			if err != nil {
				fmt.Println("Dial error:", err)
				os.Exit(1)
			}
			defer conn.Close()
			resp, err := client.Unseal(context.Background(), &vaultpb.UnsealRequest{Keys: args})
			if err != nil || resp.Error != "" {
				fmt.Println("Unseal error:", err, resp.GetError())
				os.Exit(1)
			}
			fmt.Println("Vault unsealed")
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show vault status",
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := dial()
			if err != nil {
				fmt.Println("Dial error:", err)
				os.Exit(1)
			}
			defer conn.Close()
			resp, err := client.Status(context.Background(), &vaultpb.StatusRequest{})
			if err != nil || resp.Error != "" {
				fmt.Println("Status error:", err, resp.GetError())
				os.Exit(1)
			}
			fmt.Println("Vault status:", resp.Status)
		},
	}
}

func getCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get [key]",
		Short: "Get a value by key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := dial()
			if err != nil {
				fmt.Println("Dial error:", err)
				os.Exit(1)
			}
			defer conn.Close()
			resp, err := client.Get(context.Background(), &vaultpb.GetRequest{Key: args[0]})
			if err != nil || resp.Error != "" {
				fmt.Println("Get error:", err, resp.GetError())
				os.Exit(1)
			}
			fmt.Println(resp.Value)
		},
	}
}

func setCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set [key] [value]",
		Short: "Set a value by key",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := dial()
			if err != nil {
				fmt.Println("Dial error:", err)
				os.Exit(1)
			}
			defer conn.Close()
			resp, err := client.Set(context.Background(), &vaultpb.SetRequest{Key: args[0], Value: args[1]})
			if err != nil || resp.Error != "" {
				fmt.Println("Set error:", err, resp.GetError())
				os.Exit(1)
			}
			fmt.Println("OK")
		},
	}
}

func deleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [key]",
		Short: "Delete a value by key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := dial()
			if err != nil {
				fmt.Println("Dial error:", err)
				os.Exit(1)
			}
			defer conn.Close()
			resp, err := client.Delete(context.Background(), &vaultpb.DeleteRequest{Key: args[0]})
			if err != nil || resp.Error != "" {
				fmt.Println("Delete error:", err, resp.GetError())
				os.Exit(1)
			}
			fmt.Println("Deleted")
		},
	}
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all keys",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := dial()
			if err != nil {
				fmt.Println("Dial error:", err)
				os.Exit(1)
			}
			defer conn.Close()
			resp, err := client.List(context.Background(), &vaultpb.ListRequest{})
			if err != nil || resp.Error != "" {
				fmt.Println("List error:", err, resp.GetError())
				os.Exit(1)
			}
			for _, k := range resp.Keys {
				fmt.Println(k)
			}
		},
	}
}
