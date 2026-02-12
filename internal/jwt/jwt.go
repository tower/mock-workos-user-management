package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Issuer struct {
	SigningKey []byte
}

func NewIssuer(key string) *Issuer {
	if key == "" {
		key = "mock-workos-dev-signing-key"
	}
	return &Issuer{SigningKey: []byte(key)}
}

var jwtHeaderB64 = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

type Claims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Sid   string `json:"sid"`
	OrgID string `json:"org_id,omitempty"`
}

func (iss *Issuer) Mint(userID, orgID string) (string, error) {
	now := time.Now().Unix()
	claims := Claims{
		Iss:   "mock-workos",
		Sub:   userID,
		Exp:   now + 3600,
		Iat:   now,
		Sid:   fmt.Sprintf("session_%s", uuid.New().String()[:24]),
		OrgID: orgID,
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := jwtHeaderB64 + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)

	mac := hmac.New(sha256.New, iss.SigningKey)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

func (iss *Issuer) Verify(token string) (*Claims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, iss.SigningKey)
	mac.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid signature")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid claims encoding: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
	}

	if claims.Exp < time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}
