package jwt

// Token consist of all neede data to represent the token
type Token struct {
	header  Claims
	payload Claims
}
