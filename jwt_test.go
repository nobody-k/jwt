package jwt_test

import (
	"fmt"
	"testing"

	"github.com/nobody-k/jwt"
)

func TestSign(t *testing.T) {
	c := jwt.Claims{"pay": 51}
	key := "secretkey"
	var expiration int64 = 10

	jwt, err := jwt.Sign(c, key, expiration)

	fmt.Println(jwt)
	fmt.Println(err)

}

func TestVerify(t *testing.T) {
	s := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	c, ok, err := jwt.Verify(s, "your-256-bit-secret")
	t.Log(ok)
	fmt.Println(ok, err)
	fmt.Println(c)
}
