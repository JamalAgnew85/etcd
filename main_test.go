package main

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type testKVServer struct {
	as *AuthStore
}

func (s *testKVServer) Put(ctx context.Context, req *PutRequest) (*PutResponse, error) {
	user, ok := ctx.Value(userKey).(*User)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	if user.Role != "admin" && user.Role != "writer" {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	return &PutResponse{Revision: 1}, nil
}

type testWatchServer struct {
	as     *AuthStore
	events chan *WatchResponse
}

func (s *testWatchServer) Watch(stream Watch_WatchServer) error {
	user, ok := stream.Context().Value(userKey).(*User)
	if !ok {
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}
	if user.Role != "admin" && user.Role != "reader" {
		return status.Error(codes.PermissionDenied, "permission denied")
	}

	// Read initial request
	_, err := stream.Recv()
	if err != nil {
		return err
	}

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case ev, ok := <-s.events:
			if !ok {
				return nil
			}
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

func TestAuthRevocationAndRefresh(t *testing.T) {
	as := NewAuthStore()
	as.AddUser("alice", "reader")
	as.AddUser("bob", "writer")

	// Generate tokens
	tokenAlice, err := as.GenerateToken("alice", 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	tokenBob, err := as.GenerateToken("bob", 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Start gRPC server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	s := grpc.NewServer(
		grpc.UnaryInterceptor(UnaryAuthInterceptor(as)),
		grpc.StreamInterceptor(StreamAuthInterceptor(as)),
	)

	kvSrv := &testKVServer{as: as}
	eventsChan := make(chan *WatchResponse, 10)
	watchSrv := &testWatchServer{as: as, events: eventsChan}

	s.RegisterService(&KVServiceDesc, kvSrv)
	s.RegisterService(&WatchServiceDesc, watchSrv)

	go func() {
		_ = s.Serve(lis)
	}()
	defer s.Stop()

	// Connect client
	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	kvClient := NewKVClient(conn)
	watchClient := NewWatchClient(conn)

	// Test Scenario 1: Revocation on Watch Stream
	ctxAlice := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", tokenAlice))
	stream, err := watchClient.Watch(ctxAlice)
	if err != nil {
		t.Fatalf("failed to open watch stream: %v", err)
	}

	// Send initial request
	if err := stream.Send(&WatchRequest{Key: "foo"}); err != nil {
		t.Fatalf("failed to send watch request: %v", err)
	}

	// Send an event and receive it
	eventsChan <- &WatchResponse{Key: "foo", Value: "bar"}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive watch response: %v", err)
	}
	if resp.Value != "bar" {
		t.Errorf("expected value 'bar', got '%s'", resp.Value)
	}

	// Revoke Alice's token
	as.RevokeToken(tokenAlice)

	// Wait for background re-validation to trigger context cancellation
	errChan := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		errChan <- err
	}()

	select {
	case recvErr := <-errChan:
		if recvErr == nil {
			t.Error("expected error after token revocation, got nil")
		} else {
			st, ok := status.FromError(recvErr)
			if !ok || st.Code() != codes.Unauthenticated {
				t.Errorf("expected Unauthenticated error, got: %v", recvErr)
			}
		}
	case <-time.After(1 * time.Second):
		t.Error("timeout waiting for stream termination after revocation")
	}

	// Test Scenario 2: Token Refresh / Permission Update over same connection
	ctxBob := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", tokenBob))
	_, err = kvClient.Put(ctxBob, &PutRequest{Key: "foo", Value: "bar"})
	if err != nil {
		t.Fatalf("failed to put: %v", err)
	}

	// Update Bob's role to "reader" (no longer has write permissions)
	as.UpdateUserRole("bob", "reader")

	// Try to Put again with the same token (which is still valid, but permissions changed)
	_, err = kvClient.Put(ctxBob, &PutRequest{Key: "foo", Value: "bar"})
	if err == nil {
		t.Error("expected permission denied error, got nil")
	}
}
