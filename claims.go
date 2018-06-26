package jwt

import (
	"encoding/json"
)

// RegisteredClaims has all claims as defined in the RFC 7519
// section 4.1
// type RegisteredClaims struct {
// 	Issuer         string      `json:"iss,omitempty"`
// 	Subject        string      `json:"sub,omitempty"`
// 	Audience       string      `json:"aud,omitempty"`
// 	ExpirationTime NumericDate `json:"exp,omitempty"`
// 	NotBefore      NumericDate `json:"nbf,omitempty"`
// 	IssuedAt       NumericDate `json:"iat,omitempty"`
// 	JWTID          string      `json:"jti,omitempty"`
// }

// lets use a map. the struct is complicated

// Claims defines the structure for claims as defined in the RFC
type Claims map[string]interface{}

// VerifyExpirationTime checks if the expiration time is after the given compTime
// The parametr required is used if it is expexted to get exp from the claims
// This functio is used after receiving the token from the client
func (c Claims) VerifyExpirationTime(compTime int64, required bool) bool {
	var value int64
	switch exp := m["exp"].(type) {
	case float64: // probably the most common occurance
		value = int64(exp)
	case json.Number:
		value, _ = exp.Int64()
	default:
		value = 0
	}
	return (compTime <= value) | required
}

// AddClaim adds a claim to the given map c. The value of the claim is v
func (c Claims) AddClaim(claim string, v interface{}) Claims {
	c[claim] = v
	return c
}
