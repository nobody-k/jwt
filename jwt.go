package jwt

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
