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

/*
func TestVerify(t *testing.T) {
	s := "eyJhbGciOsiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1Mjk4ODY0NDksImlhdCI6MTUyOTg3NjQ0OSwibmFtZSI6ImpvaG4ifQ==.QUoLtHeoJHec2t8LpmWal4ZTdZg5FhUInQjz7PDXQtk="

	t.Log(s)

	c, ok, err := jwt.Verify(s, "secret")

	fmt.Println(ok, err)
	fmt.Println(c)

}*/
