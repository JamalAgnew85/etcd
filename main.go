package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Context keys
type contextKey string

const (
	tokenKey contextKey = "token"
	userKey  contextKey = "user"
)

// User and Token structures
type User struct {
	Username string
	Role     string
	Revision int
}

type TokenInfo struct {
	Token     string
	Username  string
	ExpiresAt time.Time
}

// AuthStore manages users and tokens
type AuthStore struct {
	mu       sync.RWMutex
	users    map[string]*User
	tokens   map[string]*TokenInfo
	revoked  map[string]bool
	revision int
}

func NewAuthStore() *AuthStore {
	return &AuthStore{
		users:   make(map[string]*User),
		tokens:  make(map[string]*TokenInfo),
		revoked: make(map[string]bool),
	}
}

func (as *AuthStore) AddUser(username, role string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.revision++
	as.users[username] = &User{
		Username: username,
		Role:     role,
		Revision: as.revision,
	}
}

func (as *AuthStore) UpdateUserRole(username, role string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if u, ok := as.users[username]; ok {
		as.revision++
		u.Role = role
		u.Revision = as.revision
	}
}

func (as *AuthStore) GenerateToken(username string, ttl time.Duration) (string, error) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if _, ok := as.users[username]; !ok {
		return "", errors.New("user not found")
	}
	token := fmt.Sprintf("token-%s-%d", username, time.Now().UnixNano())
	as.tokens[token] = &TokenInfo{
		Token:     token,
		Username:  username,
		ExpiresAt: time.Now().Add(ttl),
	}
	return token, nil
}

func (as *AuthStore) RevokeToken(token string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.revoked[token] = true
}

func (as *AuthStore) ValidateToken(token string) (*User, error) {
	as.mu.RLock()
	defer as.mu.RUnlock()

	if as.revoked[token] {
		return nil, errors.New("token revoked")
	}

	tInfo, ok := as.tokens[token]
	if !ok {
		return nil, errors.New("token not found")
	}

	if time.Now().After(tInfo.ExpiresAt) {
		return nil, errors.New("token expired")
	}

	user, ok := as.users[tInfo.Username]
	if !ok {
		return nil, errors.New("user not found")
	}

	return &User{
		Username: user.Username,
		Role:     user.Role,
		Revision: user.Revision,
	}, nil
}

// Helper to extract token from context metadata
func extractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("no metadata in context")
	}
	tokens := md.Get("authorization")
	if len(tokens) == 0 {
		return "", errors.New("no authorization token in metadata")
	}
	return tokens[0], nil
}

// UnaryAuthInterceptor validates token for unary requests
func UnaryAuthInterceptor(as *AuthStore) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		token, err := extractToken(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
		}

		user, err := as.ValidateToken(token)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		newCtx := context.WithValue(ctx, userKey, user)
		newCtx = context.WithValue(newCtx, tokenKey, token)
		return handler(newCtx, req)
	}
}

// wrappedStream wraps grpc.ServerStream to support context cancellation and token validation
type wrappedStream struct {
	grpc.ServerStream
	ctx       context.Context
	cancel    context.CancelFunc
	authErr   error
	authErrMu sync.RWMutex
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}

func (w *wrappedStream) setAuthErr(err error) {
	w.authErrMu.Lock()
	defer w.authErrMu.Unlock()
	w.authErr = err
}

func (w *wrappedStream) getAuthErr() error {
	w.authErrMu.RLock()
	defer w.authErrMu.RUnlock()
	return w.authErr
}

func (w *wrappedStream) RecvMsg(m interface{}) error {
	if err := w.ctx.Err(); err != nil {
		if authErr := w.getAuthErr(); authErr != nil {
			return authErr
		}
		return status.Errorf(codes.Canceled, "stream canceled: %v", err)
	}
	return w.ServerStream.RecvMsg(m)
}

func (w *wrappedStream) SendMsg(m interface{}) error {
	if err := w.ctx.Err(); err != nil {
		if authErr := w.getAuthErr(); authErr != nil {
			return authErr
		}
		return status.Errorf(codes.Canceled, "stream canceled: %v", err)
	}
	return w.ServerStream.SendMsg(m)
}

// StreamAuthInterceptor validates token for stream requests and periodically re-validates
func StreamAuthInterceptor(as *AuthStore) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		token, err := extractToken(ss.Context())
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
		}

		user, err := as.ValidateToken(token)
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		ctx, cancel := context.WithCancel(ss.Context())
		defer cancel()

		ctx = context.WithValue(ctx, userKey, user)
		ctx = context.WithValue(ctx, tokenKey, token)

		ws := &wrappedStream{
			ServerStream: ss,
			ctx:          ctx,
			cancel:       cancel,
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					currentUser, err := as.ValidateToken(token)
					if err != nil {
						ws.setAuthErr(status.Errorf(codes.Unauthenticated, "token invalidated: %v", err))
						cancel()
						return
					}
					if currentUser.Revision != user.Revision {
						ws.setAuthErr(status.Errorf(codes.PermissionDenied, "user permissions updated"))
						cancel()
						return
					}
				}
			}
		}()

		err = handler(srv, ws)
		cancel()
		wg.Wait()

		if authErr := ws.getAuthErr(); authErr != nil {
			return authErr
		}
		return err
	}
}

// Protobuf definitions and gRPC service descriptors (manually written)

type PutRequest struct {
	Key   string
	Value string
}

type PutResponse struct {
	Revision int64
}

type WatchRequest struct {
	Key string
}

type WatchResponse struct {
	Key   string
	Value string
}

var KVServiceDesc = grpc.ServiceDesc{
	ServiceName: "etcdserverpb.KV",
	HandlerType: (*KVServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Put",
			Handler:    _KV_Put_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "kv.proto",
}

type KVServer interface {
	Put(context.Context, *PutRequest) (*PutResponse, error)
}

func _KV_Put_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PutRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KVServer).Put(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/etcdserverpb.KV/Put",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KVServer).Put(ctx, req.(*PutRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var WatchServiceDesc = grpc.ServiceDesc{
	ServiceName: "etcdserverpb.Watch",
	HandlerType: (*WatchServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Watch",
			Handler:       _Watch_Watch_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "watch.proto",
}

type WatchServer interface {
	Watch(Watch_WatchServer) error
}

type Watch_WatchServer interface {
	Send(*WatchResponse) error
	Recv() (*WatchRequest, error)
	grpc.ServerStream
}

type watchWatchServer struct {
	grpc.ServerStream
}

func (x *watchWatchServer) Send(m *WatchResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *watchWatchServer) Recv() (*WatchRequest, error) {
	m := new(WatchRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _Watch_Watch_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(WatchServer).Watch(&watchWatchServer{stream})
}

// Client implementations

type KVClient interface {
	Put(ctx context.Context, in *PutRequest, opts ...grpc.CallOption) (*PutResponse, error)
}

type kvClient struct {
	cc grpc.ClientConnInterface
}

func NewKVClient(cc grpc.ClientConnInterface) KVClient {
	return &kvClient{cc}
}

func (c *kvClient) Put(ctx context.Context, in *PutRequest, opts ...grpc.CallOption) (*PutResponse, error) {
	out := new(PutResponse)
	err := c.cc.Invoke(ctx, "/etcdserverpb.KV/Put", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

type WatchClient interface {
	Watch(ctx context.Context, opts ...grpc.CallOption) (Watch_WatchClient, error)
}

type watchClient struct {
	cc grpc.ClientConnInterface
}

func NewWatchClient(cc grpc.ClientConnInterface) WatchClient {
	return &watchClient{cc}
}

type Watch_WatchClient interface {
	Send(*WatchRequest) error
	Recv() (*WatchResponse, error)
	grpc.ClientStream
}

type watchWatchClient struct {
	grpc.ClientStream
}

func (x *watchWatchClient) Send(m *WatchRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *watchWatchClient) Recv() (*WatchResponse, error) {
	m := new(WatchResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *watchClient) Watch(ctx context.Context, opts ...grpc.CallOption) (Watch_WatchClient, error) {
	stream, err := c.cc.NewStream(ctx, &WatchServiceDesc.Streams[0], "/etcdserverpb.Watch/Watch", opts...)
	if err != nil {
		return nil, err
	}
	x := &watchWatchClient{stream}
	return x, nil
}

func main() {
	fmt.Println("Hello, Bounty Hunter!")
}
