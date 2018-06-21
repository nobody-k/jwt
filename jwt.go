package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

// ComputeHmac256 creates a hash based on the provided secret
func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Claims is the structure of claims
type Claims map[string]interface{}

// SetClaim sets a claim in appropriate field
func (c Claims) SetClaim(claim string, v interface{}) Claims {
	c[claim] = v
	return c
}

// Sign produces the token for the defined claims, takes the secretkey for hasing,
// and expiration in seconds for the exp Claim as defined in the RFC
// if experation == 0 no exp Claim will be created
// at this moment assuming only one method for hashing
func (c Claims) Sign(secretKey string, expiration int) string {
	/*
	**************** the HEADER ********************
	 */
	// using fized header for now
	header := base64.StdEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	/*
	**************** the CLAIMS ********************
	 */
	// 4.1.1.  "iss" (Issuer) Claim - NOT using for NOW
	// 4.1.2.  "sub" (Subject) Claim - NOT using for NOW
	// 4.1.3.  "aud" (Audience) Claim - NOT using for NOW
	// 4.1.4.  "exp" (Expiration Time) Claim
	currentTime := time.Now()

	if expiration > 0 {
		exp := currentTime.Add(time.Second * time.Duration(expiration)).Unix()
		c.SetClaim("exp", exp)
	}
	// 4.1.5.  "nbf" (Not Before) Claim - NOT Using for now
	// 4.1.6.  "iat" (Issued At) Claim
	// get the current time in Unix format as requested by the RFC
	c.SetClaim("iat", currentTime.Unix())
	//4.1.7.  "jti" (JWT ID) Claim - NOT using now

	// assuming other public claims has been set
	// convert to json
	j, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	// and encode the payload
	payload := base64.StdEncoding.EncodeToString(j)
	/*
	**************** the Signature ********************
	 */
	signature := ComputeHmac256(header+"."+payload, secretKey)

	/*
	**************** the JWT ********************
	 */
	return header + "." + payload + "." + signature
}
