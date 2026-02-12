package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	mockjwt "github.com/tower/mock-workos-user-management/internal/jwt"
	"github.com/tower/mock-workos-user-management/internal/store"
)

type handler struct {
	store  *store.Store
	issuer *mockjwt.Issuer
}

func New(s *store.Store, iss *mockjwt.Issuer) http.Handler {
	h := &handler{store: s, issuer: iss}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /user_management/users", h.createUser)
	mux.HandleFunc("GET /user_management/users/external_id/{externalID}", h.getUserByExternalID)
	mux.HandleFunc("GET /user_management/users/{id}", h.getUser)
	mux.HandleFunc("POST /user_management/authenticate", h.authenticate)
	mux.HandleFunc("POST /user_management/organization_memberships", h.createOrganizationMembership)
	mux.HandleFunc("GET /user_management/organization_memberships", h.listOrganizationMemberships)
	mux.HandleFunc("POST /organizations", h.createOrganization)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return logRequests(mux)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type apiError struct {
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Message: msg, Code: code})
}

func (h *handler) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email            string `json:"email"`
		Password         string `json:"password,omitempty"`
		PasswordHash     string `json:"password_hash,omitempty"`
		PasswordHashType string `json:"password_hash_type,omitempty"`
		FirstName        string `json:"first_name,omitempty"`
		LastName         string `json:"last_name,omitempty"`
		EmailVerified    bool   `json:"email_verified,omitempty"`
		ExternalID       string `json:"external_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid request body")
		return
	}
	if req.Email == "" {
		writeError(w, http.StatusUnprocessableEntity, "validation_error", "email is required")
		return
	}

	var hash string
	switch {
	case req.PasswordHash != "" && req.PasswordHashType == "bcrypt":
		hash = req.PasswordHash
	case req.Password != "":
		b, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "failed to hash password")
			return
		}
		hash = string(b)
	}

	u, err := h.store.CreateUser(store.User{
		Email:         req.Email,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		EmailVerified: req.EmailVerified,
		ExternalID:    req.ExternalID,
		PasswordHash:  hash,
	})
	if err != nil {
		writeError(w, http.StatusConflict, "user_already_exists", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (h *handler) getUser(w http.ResponseWriter, r *http.Request) {
	u, ok := h.store.GetUser(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "user_not_found", "User not found.")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *handler) getUserByExternalID(w http.ResponseWriter, r *http.Request) {
	u, ok := h.store.GetUserByExternalID(r.PathValue("externalID"))
	if !ok {
		writeError(w, http.StatusNotFound, "user_not_found", "User not found.")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *handler) authenticate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Email        string `json:"email"`
		Password     string `json:"password"`
		GrantType    string `json:"grant_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid request body")
		return
	}
	if req.GrantType != "password" {
		writeError(w, http.StatusBadRequest, "bad_request", "unsupported grant_type")
		return
	}

	u, ok := h.store.GetUserByEmail(req.Email)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password.")
		return
	}
	if u.PasswordHash != "" {
		if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password.")
			return
		}
	}

	orgID := h.store.GetFirstMembershipOrgID(u.ID)
	accessToken, err := h.issuer.Mint(u.ID, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to mint token")
		return
	}

	h.store.UpdateUserLastSignIn(u.ID)

	writeJSON(w, http.StatusOK, struct {
		User                 *store.User `json:"user"`
		OrganizationID       string      `json:"organization_id"`
		AccessToken          string      `json:"access_token"`
		RefreshToken         string      `json:"refresh_token"`
		AuthenticationMethod string      `json:"authentication_method"`
	}{
		User:                 u,
		OrganizationID:       orgID,
		AccessToken:          accessToken,
		RefreshToken:         "mock_refresh_" + u.ID,
		AuthenticationMethod: "Password",
	})
}

func (h *handler) createOrganization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		ExternalID string `json:"external_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "validation_error", "name is required")
		return
	}

	o, err := h.store.CreateOrganization(store.Organization{
		Name:       req.Name,
		ExternalID: req.ExternalID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, o)
}

func (h *handler) createOrganizationMembership(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID         string `json:"user_id"`
		OrganizationID string `json:"organization_id"`
		RoleSlug       string `json:"role_slug,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid request body")
		return
	}

	m, err := h.store.CreateOrganizationMembership(req.UserID, req.OrganizationID, req.RoleSlug)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

func (h *handler) listOrganizationMemberships(w http.ResponseWriter, r *http.Request) {
	memberships := h.store.ListOrganizationMemberships(
		r.URL.Query().Get("user_id"),
		r.URL.Query().Get("organization_id"),
	)
	writeJSON(w, http.StatusOK, struct {
		Data         []*store.OrganizationMembership `json:"data"`
		ListMetadata struct {
			Before string `json:"before"`
			After  string `json:"after"`
		} `json:"list_metadata"`
	}{Data: memberships})
}
