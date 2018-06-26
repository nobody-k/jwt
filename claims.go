package jwt

import (
	"encoding/json"
)

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

// EncodeClaims converts the claims to json and then encode as defined in the rfp.
// I.e. using URLEncoding
func (c Claim) EncodeClaims() (string, error) {
	// convert to JSON
	js, err := json.Marshal(c)
	if err != nil {
		return js, err
	}
	// and lets encode it
	s := EncodeSegment(js)
	return s, nil
}

// standard claims which should be int64
var int64Claims = [...]string{"exp", "iat", "nbf"}

// DecodeClaim decodes the passed jwt substring a converts it to a Claims type
// also it converts values which are "standard" and are in float (i.e. not in int64) to int64
func DecodeClaim(jwt string) (Claims, error) {
	// decode the jwt string
	segment, err := DecodeSegment(jwt)
	if err {
		return _, err
	}
	// make emoty Claims
	claims := make(Claims)
	// Convert from JSON to Claims
	err = json.Unmarshal(segment, &claims)
	if err {
		return _, err
	}
	// convert all standard values to int64
	var v interface{}
	var value int64
	var ok bool
	for i := range int64Claims {
		v, ok := claims[i]
		if ok {
			switch v.(type) {
			case float64:
				value = int64(v)
			case json.Number:
				value, _ = v.Int64()
			}
			claims[i] = value
		}
	}

}
