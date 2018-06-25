package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Encode JWT specific base64url encoding with padding stripped
func Encode(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), " ")
}

func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

// ComputeHmac256 creates a hash based on the provided secret
func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return Encode(h.Sum(nil))
}

// Claims is the structure of claims
type Claims map[string]interface{}

// SetClaim sets a claim in appropriate field
func (c Claims) SetClaim(claim string, v interface{}) Claims {
	c[claim] = v
	return c
}

// Verify checks if the token is valid, the siniture is valid and it is not expired
// it will override the Claims
// returning true if validate or an error
func (c Claims) Verify(token string, secretKey string) (bool, error) {
	var err error

	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		err = errors.New("Incorrect format of the token")
		return false, err
	}

	// compute the hash of the first two parts. Header and the payload
	hash := ComputeHmac256(parts[0]+"."+parts[1], secretKey)
	// lets compare it with the received one. parts[2]
	if hash != parts[2] {
		err = errors.New("Wrong signature")
		return false, err
	}

	headerJSON, _ := base64.URLEncoding.DecodeString(parts[0])
	payloadJSON, _ := base64.URLEncoding.DecodeString(parts[1])
	fmt.Println(string(headerJSON), string(payloadJSON))

	// decode header
	header := make(Claims)
	if err = json.Unmarshal(headerJSON, &header); err != nil {
		return false, err
	}

	// decode payload
	if err = json.Unmarshal(payloadJSON, &c); err != nil {
		return false, err
	}

	fmt.Println(c)
	// get the time from the payload and get the currengt time
	expirationTime := time.Unix(c["exp"].(int64), 0)
	currentTime := time.Now()

	// expirationTime should be after the currentTime
	if currentTime.After(expirationTime) {
		err = errors.New("Expired JWT")
		return false, err
	}

	return true, nil
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
	header := Encode([]byte(`{"alg":"HS256","typ":"JWT"}`))
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
	payload := Encode(j)

	/*
	**************** the Signature ********************
	 */
	signature := ComputeHmac256(header+"."+payload, secretKey)

	/*
	**************** the JWT ********************
	 */
	return header + "." + payload + "." + signature
}
