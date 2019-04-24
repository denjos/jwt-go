package authentication

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/denjos/jwt/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

//se firman los token con una llave privada
//se verifican con una llave publica
//openssl genrsa -out private.rsa 1024
//openssl rsa -in private.rsa -pubout > public.rsa.pub

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func init() {
	privateBytes, err := ioutil.ReadFile("./private.rsa")
	if err != nil {
		log.Fatal("error en la lectura del archivo private")
	}
	publicBytes, err := ioutil.ReadFile("./public.rsa.pub")
	if err != nil {
		log.Fatal("error en la lectura del archivo publico")
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateBytes)
	if err != nil {
		log.Fatal("error en parse privateKey")
	}
	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicBytes)
	if err != nil {
		log.Fatal("error en parse privateKey")
	}
}

func GenerateJWT(user models.User) string {
	claims := models.Claim{
		User: user,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
			Issuer:    "taller",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	result, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal("no se firmo el token")
	}
	return result
}
func Login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		fmt.Fprintln(w, "error al leer el usuario %s", err)
		return
	}
	if user.Name == "oscar" && user.Password == "javier" {
		user.Password = ""
		user.Role = "admin"
		token := GenerateJWT(user)
		result := models.ResponseToken{token}
		jsonResult, err := json.Marshal(result)
		if err != nil {
			fmt.Fprintln(w, "error en la generacion del json")
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResult)
	} else {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Usuario o clave no validos")
	}
}

func ValidateToken(w http.ResponseWriter, r *http.Request) {
	token, err := request.ParseFromRequestWithClaims(r, request.OAuth2Extractor, &models.Claim{}, func(token *jwt.Token) (i interface{}, e error) {
		return publicKey, nil
	})

	if err != nil {
		switch err.(type) {
		case *jwt.ValidationError:
			vErr := err.(*jwt.ValidationError)
			switch vErr.Errors {
			case jwt.ValidationErrorExpired:
					fmt.Fprintln(w,"Token expirado")
					return
			case jwt.ValidationErrorSignatureInvalid:
				fmt.Fprintln(w,"Token expirado")
				return
			default:
				fmt.Fprintln(w,"Token invalido")
				return
			}
		default:
			fmt.Fprintln(w,"Token no es valido")
			return
		}

	}
	if token.Valid {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w,"aceptado")
	}else{
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w,"no autorizado")

	}
}
