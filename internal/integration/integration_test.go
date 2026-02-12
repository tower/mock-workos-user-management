package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/workos/workos-go/v5/pkg/organizations"
	"github.com/workos/workos-go/v5/pkg/usermanagement"

	"github.com/tower/mock-workos-user-management/internal/handler"
	mockjwt "github.com/tower/mock-workos-user-management/internal/jwt"
	"github.com/tower/mock-workos-user-management/internal/seed"
	"github.com/tower/mock-workos-user-management/internal/store"
)

func setup(t *testing.T) (umClient *usermanagement.Client, orgClient *organizations.Client, issuer *mockjwt.Issuer) {
	t.Helper()
	s := store.New()
	issuer = mockjwt.NewIssuer("test-key")
	srv := httptest.NewServer(handler.New(s, issuer))
	t.Cleanup(srv.Close)

	httpClient := &http.Client{Timeout: 10 * time.Second}
	umClient = &usermanagement.Client{
		APIKey:     "test_api_key",
		Endpoint:   srv.URL,
		HTTPClient: httpClient,
		JSONEncode: json.Marshal,
	}
	orgClient = &organizations.Client{
		APIKey:     "test_api_key",
		Endpoint:   srv.URL,
		HTTPClient: httpClient,
		JSONEncode: json.Marshal,
	}
	return
}

func TestAuthenticateWithPassword(t *testing.T) {
	umClient, _, issuer := setup(t)
	ctx := context.Background()

	created, err := umClient.CreateUser(ctx, usermanagement.CreateUserOpts{
		Email:    "auth@example.com",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	resp, err := umClient.AuthenticateWithPassword(ctx, usermanagement.AuthenticateWithPasswordOpts{
		ClientID: "client_123",
		Email:    "auth@example.com",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("AuthenticateWithPassword: %v", err)
	}

	if resp.User.ID != created.ID {
		t.Errorf("user ID = %q, want %q", resp.User.ID, created.ID)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected non-empty refresh token")
	}

	claims, err := issuer.Verify(resp.AccessToken)
	if err != nil {
		t.Fatalf("verify JWT: %v", err)
	}
	if claims.Sub != created.ID {
		t.Errorf("JWT sub = %q, want %q", claims.Sub, created.ID)
	}
	if claims.Sid == "" {
		t.Error("expected non-empty JWT sid")
	}
}

func TestAuthenticateWrongPassword(t *testing.T) {
	umClient, _, _ := setup(t)
	ctx := context.Background()

	_, err := umClient.CreateUser(ctx, usermanagement.CreateUserOpts{
		Email:    "wrongpass@example.com",
		Password: "correct",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = umClient.AuthenticateWithPassword(ctx, usermanagement.AuthenticateWithPasswordOpts{
		ClientID: "client_123",
		Email:    "wrongpass@example.com",
		Password: "incorrect",
	})
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestFullFlow(t *testing.T) {
	umClient, orgClient, issuer := setup(t)
	ctx := context.Background()

	user, err := umClient.CreateUser(ctx, usermanagement.CreateUserOpts{
		Email:         "flow@example.com",
		Password:      "flowpass",
		FirstName:     "Flow",
		LastName:      "Test",
		EmailVerified: true,
		ExternalID:    "ext_flow",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.ID == "" {
		t.Fatal("expected non-empty user ID")
	}
	if user.FirstName != "Flow" {
		t.Errorf("first_name = %q, want %q", user.FirstName, "Flow")
	}

	got, err := umClient.GetUser(ctx, usermanagement.GetUserOpts{User: user.ID})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.Email != user.Email {
		t.Errorf("GetUser email = %q, want %q", got.Email, user.Email)
	}

	gotByExt, err := umClient.GetUserByExternalID(ctx, usermanagement.GetUserByExternalIDOpts{
		ExternalID: "ext_flow",
	})
	if err != nil {
		t.Fatalf("GetUserByExternalID: %v", err)
	}
	if gotByExt.ID != user.ID {
		t.Errorf("external ID lookup = %q, want %q", gotByExt.ID, user.ID)
	}

	org, err := orgClient.CreateOrganization(ctx, organizations.CreateOrganizationOpts{
		Name: "Flow Org",
	})
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	membership, err := umClient.CreateOrganizationMembership(ctx, usermanagement.CreateOrganizationMembershipOpts{
		UserID:         user.ID,
		OrganizationID: org.ID,
	})
	if err != nil {
		t.Fatalf("CreateOrganizationMembership: %v", err)
	}
	if membership.UserID != user.ID {
		t.Errorf("membership user_id = %q, want %q", membership.UserID, user.ID)
	}

	memberships, err := umClient.ListOrganizationMemberships(ctx, usermanagement.ListOrganizationMembershipsOpts{
		UserID: user.ID,
	})
	if err != nil {
		t.Fatalf("ListOrganizationMemberships: %v", err)
	}
	if len(memberships.Data) != 1 {
		t.Fatalf("expected 1 membership, got %d", len(memberships.Data))
	}

	authResp, err := umClient.AuthenticateWithPassword(ctx, usermanagement.AuthenticateWithPasswordOpts{
		ClientID: "client_123",
		Email:    "flow@example.com",
		Password: "flowpass",
	})
	if err != nil {
		t.Fatalf("AuthenticateWithPassword: %v", err)
	}

	claims, err := issuer.Verify(authResp.AccessToken)
	if err != nil {
		t.Fatalf("verify JWT: %v", err)
	}
	if claims.Sub != user.ID {
		t.Errorf("JWT sub = %q, want %q", claims.Sub, user.ID)
	}
	if claims.OrgID != org.ID {
		t.Errorf("JWT org_id = %q, want %q", claims.OrgID, org.ID)
	}
	if claims.Sid == "" {
		t.Error("expected non-empty JWT sid")
	}
}

func TestSeedLoading(t *testing.T) {
	s := store.New()
	issuer := mockjwt.NewIssuer("test-key")

	err := seed.Apply(seed.Config{
		Users: []seed.SeedUser{
			{ID: "user_seeded", Email: "seeded@example.com", FirstName: "Seeded", LastName: "User", Password: "seedpass"},
		},
		Organizations: []seed.SeedOrganization{
			{ID: "org_seeded", Name: "Seeded Org"},
		},
		Memberships: []seed.SeedMembership{
			{UserID: "user_seeded", OrganizationID: "org_seeded"},
		},
	}, s)
	if err != nil {
		t.Fatalf("seed.Apply: %v", err)
	}

	srv := httptest.NewServer(handler.New(s, issuer))
	t.Cleanup(srv.Close)

	umClient := &usermanagement.Client{
		APIKey:     "test_api_key",
		Endpoint:   srv.URL,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		JSONEncode: json.Marshal,
	}
	ctx := context.Background()

	user, err := umClient.GetUser(ctx, usermanagement.GetUserOpts{User: "user_seeded"})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if user.Email != "seeded@example.com" {
		t.Errorf("email = %q, want %q", user.Email, "seeded@example.com")
	}

	authResp, err := umClient.AuthenticateWithPassword(ctx, usermanagement.AuthenticateWithPasswordOpts{
		ClientID: "client_123",
		Email:    "seeded@example.com",
		Password: "seedpass",
	})
	if err != nil {
		t.Fatalf("AuthenticateWithPassword: %v", err)
	}

	claims, err := issuer.Verify(authResp.AccessToken)
	if err != nil {
		t.Fatalf("verify JWT: %v", err)
	}
	if claims.OrgID != "org_seeded" {
		t.Errorf("JWT org_id = %q, want %q", claims.OrgID, "org_seeded")
	}
}
