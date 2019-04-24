package models

import ( jwt "github.com/dgrijalva/jwt-go")

type Claim struct {
	User `json:"User"`
	jwt.StandardClaims

}