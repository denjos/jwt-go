package main

import (
	"github.com/denjos/jwt/authentication"
	"log"
	"net/http"
)

func main()  {
	mux:=http.NewServeMux()
	mux.HandleFunc("/login",authentication.Login)
	mux.HandleFunc("/validate",authentication.ValidateToken)
	log.Println("escuchando en http://localhost:8080")
	http.ListenAndServe(":8080",mux)
}
