package seed

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"

	"github.com/tower/mock-workos-user-management/internal/store"
)

type Config struct {
	Users         []SeedUser         `json:"users"`
	Organizations []SeedOrganization `json:"organizations"`
	Memberships   []SeedMembership   `json:"memberships"`
}

type SeedUser struct {
	ID            string `json:"id,omitempty"`
	Email         string `json:"email"`
	FirstName     string `json:"first_name,omitempty"`
	LastName      string `json:"last_name,omitempty"`
	Password      string `json:"password,omitempty"`
	PasswordHash  string `json:"password_hash,omitempty"`
	ExternalID    string `json:"external_id,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

type SeedOrganization struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

type SeedMembership struct {
	UserID         string `json:"user_id"`
	OrganizationID string `json:"organization_id"`
	RoleSlug       string `json:"role_slug,omitempty"`
}

func Load(path string, s *store.Store) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading seed file: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing seed file: %w", err)
	}
	return Apply(cfg, s)
}

func Apply(cfg Config, s *store.Store) error {
	for _, su := range cfg.Users {
		hash := su.PasswordHash
		if hash == "" && su.Password != "" {
			b, err := bcrypt.GenerateFromPassword([]byte(su.Password), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("hashing password for %s: %w", su.Email, err)
			}
			hash = string(b)
		}
		u := store.User{
			ID:            su.ID,
			Email:         su.Email,
			FirstName:     su.FirstName,
			LastName:      su.LastName,
			EmailVerified: su.EmailVerified,
			ExternalID:    su.ExternalID,
			PasswordHash:  hash,
		}
		if _, err := s.CreateUser(u); err != nil {
			return fmt.Errorf("seeding user %s: %w", su.Email, err)
		}
	}

	for _, so := range cfg.Organizations {
		o := store.Organization{
			ID:   so.ID,
			Name: so.Name,
		}
		if _, err := s.CreateOrganization(o); err != nil {
			return fmt.Errorf("seeding org %s: %w", so.Name, err)
		}
	}

	for _, sm := range cfg.Memberships {
		if _, err := s.CreateOrganizationMembership(sm.UserID, sm.OrganizationID, sm.RoleSlug); err != nil {
			return fmt.Errorf("seeding membership: %w", err)
		}
	}

	return nil
}
