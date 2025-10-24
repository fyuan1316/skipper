package k8sauditlog

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"strings"
)

const (
	saIssuer      = "kubernetes/serviceaccount"
	saGroup       = "system:serviceaccounts"
	saGroupPrefix = "system:serviceaccounts:"
)

// NewOIDCTokenParser create a new OIDC token parser
func NewOIDCTokenParser() authenticator.Token {
	return &oidcTokenParser{}
}

func getUserMetadataName(userID string) string {
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(strings.TrimSpace(userID)))
	cipherStr := md5Ctx.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

type oidcTokenParser struct {
}

func (t *oidcTokenParser) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	jwtToken, err := parseJWT(token)
	if err != nil {
		return nil, false, err
	}
	userInfo := jwtToken.toUserInfo()

	resp := authenticator.Response{
		User: userInfo,
	}

	return &resp, true, nil
}

func parseJWT(rawToken string) (*jwtToken, error) {
	var (
		token jwtToken
	)

	if rawToken == "" {
		return nil, errors.New("authentication head is invalid")
	}
	parts := strings.Split(rawToken, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	if err := json.Unmarshal(payload, &token); err != nil {
		fmt.Println(err)
		return nil, err
	}
	token.MetadataName = getUserMetadataName(token.Email)
	return &token, nil
}

type jwtToken struct {
	// Issuer can be `kubernetes/serviceaccount` or others
	Issuer        string      `json:"iss"`
	Subject       string      `json:"sub"`
	Audience      string      `json:"aud"`
	Expiry        int         `json:"exp"`
	IssuedAt      int         `json:"iat"`
	Nonce         string      `json:"nonce"`
	Email         string      `json:"email"`
	EmailVerified bool        `json:"email_verified"`
	Name          string      `json:"name"`
	Groups        []string    `json:"groups"`
	Ext           jwtTokenExt `json:"ext"`
	MetadataName  string

	// ServiceAccountUID is the uid of the ServiceAccount this token bind to
	// This is a bit of ugly of course, we have to support both ServiceAccount token and OIDC token,
	// since they are both JWT tokens, there is no need to add another struct to impl this interface,
	// so we need to add the fields from both types to a single one, fortunately there are not so many.
	ServiceAccountUID string `json:"kubernetes.io/serviceaccount/service-account.uid"`

	// ServiceAccountNamespace is the namespace which the ServiceAccount lives in.
	ServiceAccountNamespace string `json:"kubernetes.io/serviceaccount/namespace"`
}

type jwtTokenExt struct {
	IsAdmin bool   `json:"is_admin"`
	ConnID  string `json:"conn_id"`
}

func (t *jwtToken) toUserInfo() user.Info {
	var info user.DefaultInfo
	if t.Issuer == saIssuer {
		info.Name = t.Subject
		info.UID = t.ServiceAccountUID
		info.Groups = []string{
			saGroup,
			saGroupPrefix + t.ServiceAccountNamespace,
		}
	} else {
		// If this a normal user, user email as unique name.
		info.Name = t.Email
		info.Groups = t.Groups
	}
	return &info
}
