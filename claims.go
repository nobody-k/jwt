package jwt

import (
	"encoding/json"
)

// lets use a map. the struct is complicated

// Claims defines the structure for claims as defined in the RFC
type Claims map[string]interface{}

// MergeClaims merges to claims into one
func MergeClaims(c1 Claims, c2 Claims) Claims {
	c := make(Claims)
	var k string
	var v interface{}
	for k, v = range c1 {
		c[k] = v
	}
	for k, v = range c2 {
		c[k] = v
	}

	return c
}

// VerifyExpirationTime checks if the expiration time is after the given compTime
// The parametr required is used if it is expexted to get exp from the claims
// This functio is used after receiving the token from the client
func (c Claims) VerifyExpirationTime(compTime int64, required bool) bool {
	exp, ok := c["exp"] // I am assuming the DecodeClaims function was called before
	value := exp.(int64)

	return (compTime <= value) || required
}

// AddClaim adds a claim to the given map c. The value of the claim is v
func (c Claims) AddClaim(claim string, v interface{}) Claims {
	c[claim] = v
	return c
}

// EncodeClaims converts the claims to json and then encode as defined in the rfp.
// I.e. using URLEncoding
func (c Claims) EncodeClaims() (string, error) {
	// convert to JSON
	js, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	// and lets encode it
	s := EncodeSegment(js)
	return s, nil
}

// standard claims which should be int64
var int64Claims = [...]string{"exp", "iat", "nbf"}

// DecodeClaims decodes the passed jwt substring a converts it to a Claims type
// also it converts values which are "standard" and are in float (i.e. not in int64) to int64
func DecodeClaims(jwt string) (Claims, error) {

	// make emoty Claims
	claims := make(Claims)

	// decode the jwt string
	segment, err := DecodeSegment(jwt)
	if err != nil {
		return claims, err
	}

	// Convert from JSON to Claims
	err = json.Unmarshal(segment, &claims)
	if err != nil {
		return claims, err
	}
	// convert all standard values to int64
	var claimValue interface{}
	var value int64
	var ok bool
	for i, v := range int64Claims {
		claimValue, ok = claims[v] // get the value and check if the claim exists
		if ok {
			value, _ = claimValue.(int64)
			claims[v] = value
		}
	}
	return claims, nil
}
