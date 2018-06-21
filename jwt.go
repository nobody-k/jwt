package jwt

import (
	"time"
)

// The approach

// Creating the header

// creating the payload

// creating the signature

// add all three part together

// Claims is the structure of claims
type Claims map[string]interface{}

// SetClaim sets a claim in appropriate field
func (c Claims) SetClaim(claim string, v interface{}) Claims {
	c[claim] = v
	return c
}

// Sign for the defined claims, takes the secretkey for hasing,
// and expiration in seconds for the exp Claim as defined in the RFC
// if experation == 0 no exp Claim will be created
func (c Claims) Sign(alg func(), secretKey string, expiration int) string {
	/*
	* the CLAIMS
	 */
	// 4.1.1.  "iss" (Issuer) Claim - NOT using for NOW
	// 4.1.2.  "sub" (Subject) Claim - NOT using for NOW
	// 4.1.3.  "aud" (Audience) Claim - NOT using for NOW
	// 4.1.4.  "exp" (Expiration Time) Claim
	currentTime := time.Now()
	exp := currentTime.Add(time.Second * time.Duration(expiration))
	if expiration > 0 {
		c.SetClaim("exp", exp)
	}
	// 4.1.5.  "nbf" (Not Before) Claim - NOT Using for now
	// 4.1.6.  "iat" (Issued At) Claim
	// get the current time in Unix format as requested by the RFC
	c.SetClaim("iat", currentTime.Unix())
	//4.1.7.  "jti" (JWT ID) Claim - NOT using now

}
