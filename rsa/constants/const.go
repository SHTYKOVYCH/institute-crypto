package constants

import "math/big"

const OPEN_KEY_MSG string = "RSA OPEN KEY"

const PRIVATE_KEY_MSG string = "RSA PRIVATE KEY"

var E *big.Int = new(big.Int).SetInt64(65537)
