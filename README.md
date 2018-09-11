# jwt

> A jwt library written in Go. The RFC7519 document was used as reference.

This JSON Web Token library is not to be used for production. I wrote it to practice in Go language, which is fun to do. :smile:

It is still in draft and need thourought testing which is the next step.

## Usage

This simplified library consist of mainly Sign and Verify functions.

### Sign

Sign takes user defined claims, some secret key and expiratin in seconds).
The function returns the JSON Web Token.
The header of the JWT is populatated with


# TODO
- Complete the testing
- Complete the README.md file


