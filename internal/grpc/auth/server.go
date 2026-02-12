package auth

import (
	"context"
	"errors"
	"grpc-service-ref/internal/services/auth"
	"grpc-service-ref/internal/storage"

	ssov1 "github.com/archefnx/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	emptyValue = 0
)

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int32,
	) (token string, err error)
	RegisterNewUser(
		ctx context.Context,
		email string,
		password string,
	) (userID int64, err error)
	IsAdmin(
		ctx context.Context,
		userID int64,
	) (bool, error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPCServer *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPCServer, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(
	ctx context.Context,
	req *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}

	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), req.GetAppId())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}

		return nil, status.Error(codes.Internal, "Invalid error")
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func validateRequest(req *ssov1.LoginRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email required")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password required")
	}

	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, "app_id required")
	}

	return nil
}

func (s *serverAPI) Register(
	ctx context.Context,
	req *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {
	if err := validateRegister(req); err != nil {
		return nil, err
	}

	userId, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "Invalid error")
	}

	return &ssov1.RegisterResponse{UserId: userId}, nil
}

func validateRegister(req *ssov1.RegisterRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email required")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password required")
	}

	return nil
}

func (s *serverAPI) IsAdmin(
	ctx context.Context,
	req *ssov1.IsAdminRequest,
) (*ssov1.IsAdminResponse, error) {
	if err := validateIsAdmin(req); err != nil {
		return nil, err
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, "Invalid error")
	}

	return &ssov1.IsAdminResponse{IsAdmin: isAdmin}, nil
}

func validateIsAdmin(req *ssov1.IsAdminRequest) error {
	if req.GetUserId() == emptyValue {
		return status.Error(codes.InvalidArgument, "user_id required")
	}

	return nil
}
