package store

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                string            `json:"id"`
	FirstName         string            `json:"first_name"`
	LastName          string            `json:"last_name"`
	Email             string            `json:"email"`
	CreatedAt         string            `json:"created_at"`
	UpdatedAt         string            `json:"updated_at"`
	EmailVerified     bool              `json:"email_verified"`
	ProfilePictureURL string            `json:"profile_picture_url"`
	LastSignInAt      string            `json:"last_sign_in_at"`
	ExternalID        string            `json:"external_id"`
	Metadata          map[string]string `json:"metadata"`
	PasswordHash      string            `json:"-"`
}

type Organization struct {
	ID                               string            `json:"id"`
	Name                             string            `json:"name"`
	AllowProfilesOutsideOrganization bool              `json:"allow_profiles_outside_organization"`
	Domains                          []any             `json:"domains"`
	CreatedAt                        string            `json:"created_at"`
	UpdatedAt                        string            `json:"updated_at"`
	ExternalID                       string            `json:"external_id"`
	Metadata                         map[string]string `json:"metadata"`
}

type OrganizationMembership struct {
	ID               string       `json:"id"`
	UserID           string       `json:"user_id"`
	OrganizationID   string       `json:"organization_id"`
	OrganizationName string       `json:"organization_name"`
	Role             RoleResponse `json:"role"`
	Roles            []RoleResponse `json:"roles"`
	Status           string       `json:"status"`
	CreatedAt        string       `json:"created_at"`
	UpdatedAt        string       `json:"updated_at"`
}

type RoleResponse struct {
	Slug string `json:"slug"`
}

type Store struct {
	mu          sync.RWMutex
	users        map[string]*User
	usersByEmail map[string]string
	usersByExtID map[string]string
	orgs        map[string]*Organization
	memberships map[string]*OrganizationMembership
	authCodes   map[string]string // code → userID
}

func New() *Store {
	return &Store{
		users:        make(map[string]*User),
		usersByEmail: make(map[string]string),
		usersByExtID: make(map[string]string),
		orgs:         make(map[string]*Organization),
		memberships:  make(map[string]*OrganizationMembership),
		authCodes:    make(map[string]string),
	}
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func newID(prefix string) string {
	return fmt.Sprintf("%s_%s", prefix, uuid.New().String()[:24])
}

func (s *Store) CreateUser(u User) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.usersByEmail[u.Email]; exists {
		return nil, fmt.Errorf("user with email %q already exists", u.Email)
	}

	if u.ID == "" {
		u.ID = newID("user")
	}
	ts := now()
	u.CreatedAt = ts
	u.UpdatedAt = ts

	s.users[u.ID] = &u
	s.usersByEmail[u.Email] = u.ID
	if u.ExternalID != "" {
		s.usersByExtID[u.ExternalID] = u.ID
	}
	return &u, nil
}

func (s *Store) GetUser(id string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
}

func (s *Store) GetUserByEmail(email string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.usersByEmail[email]
	if !ok {
		return nil, false
	}
	return s.users[id], true
}

func (s *Store) GetUserByExternalID(extID string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.usersByExtID[extID]
	if !ok {
		return nil, false
	}
	return s.users[id], true
}

func (s *Store) CreateOrganization(o Organization) (*Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if o.ID == "" {
		o.ID = newID("org")
	}
	ts := now()
	o.CreatedAt = ts
	o.UpdatedAt = ts

	s.orgs[o.ID] = &o
	return &o, nil
}

func (s *Store) CreateOrganizationMembership(userID, orgID, roleSlug string) (*OrganizationMembership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[userID]; !ok {
		return nil, fmt.Errorf("user %q not found", userID)
	}
	org, ok := s.orgs[orgID]
	if !ok {
		return nil, fmt.Errorf("organization %q not found", orgID)
	}

	if roleSlug == "" {
		roleSlug = "member"
	}

	ts := now()
	m := &OrganizationMembership{
		ID:               newID("om"),
		UserID:           userID,
		OrganizationID:   orgID,
		OrganizationName: org.Name,
		Role:             RoleResponse{Slug: roleSlug},
		Roles:            []RoleResponse{{Slug: roleSlug}},
		Status:           "active",
		CreatedAt:        ts,
		UpdatedAt:        ts,
	}
	s.memberships[m.ID] = m
	return m, nil
}

func (s *Store) ListOrganizationMemberships(userID, orgID string) []*OrganizationMembership {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := []*OrganizationMembership{}
	for _, m := range s.memberships {
		if userID != "" && m.UserID != userID {
			continue
		}
		if orgID != "" && m.OrganizationID != orgID {
			continue
		}
		result = append(result, m)
	}
	return result
}

func (s *Store) UpdateUserLastSignIn(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[id]; ok {
		u.LastSignInAt = now()
	}
}

func (s *Store) StoreAuthCode(code, userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[code] = userID
}

func (s *Store) ConsumeAuthCode(code string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID, ok := s.authCodes[code]
	if ok {
		delete(s.authCodes, code)
	}
	return userID, ok
}

func (s *Store) GetFirstUser() (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		return u, true
	}
	return nil, false
}

func (s *Store) GetFirstMembershipOrgID(userID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.memberships {
		if m.UserID == userID {
			return m.OrganizationID
		}
	}
	return ""
}
