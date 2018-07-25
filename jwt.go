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

// ComputeHmac256 creates a hash based on the provided secret
func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return EncodeSegment(h.Sum(nil))
}

// Verify checks if the token is valid, the signiture is valid and it is not expired
// it will return the Claims
// returning true if validate or an error
func Verify(token string, secretKey string) (bool, error) {
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
func Sign(payload Claims, secretKey string, expiration int) (string, error) {

	// the Header
	header := make(Claims)
	header.AddClaim("alg", "HS256").AddClaim("typ", "JWT")

	headerString, err := header.EncodeClaims()

	// the payload
	// set the time
	currentTime := time.Now()
	// 4.1.1.  "iss" (Issuer) Claim - NOT using for NOW
	// 4.1.2.  "sub" (Subject) Claim - NOT using for NOW
	// 4.1.3.  "aud" (Audience) Claim - NOT using for NOW
	// 4.1.4.  "exp" (Expiration Time) Claim
	if expiration > 0 {
		exp := currentTime.Add(time.Second * time.Duration(expiration)).Unix()
		payload.AddClaim("exp", exp)
	}

	// 4.1.5.  "nbf" (Not Before) Claim - NOT Using for now
	// 4.1.6.  "iat" (Issued At) Claim
	// get the current time in Unix format as requested by the RFC
	payload.AddClaim("iat", currentTime.Unix())
	//4.1.7.  "jti" (JWT ID) Claim - NOT using now

	// encoding the string
	// TODO: need better error handling
	payloadString, err := payload.EncodeClaims()
	if err != nil {
		return "", err
	}

	signature := ComputeHmac256(headerString+"."+payloadString, secretKey)

	return headerString + "." + payloadString + ".", nil
}
