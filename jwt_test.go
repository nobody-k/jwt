package jwt_test

import (
	"testing"

	"github.com/nobody-k/jwt"
)

func TestSign(t *testing.T) {
	c := make(jwt.Claims)
	c.SetClaim("name", "john")
	token := c.Sign("secret", 10000)
	t.Log(token)
}
