package snauth

// Some misc jwt realted functions used in the auth package.

import (
	"encoding/json"
	"fmt"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

func jtiClaimFromJWTStr(jwtStr string) string {
	return GetStrClaimFromJWTStr("jti", jwtStr)
}

func jwtPayload(ss string) (map[string]interface{}, error) {
	parts := strings.Split(ss, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT, expected three parts")
	}
	js, err := jwt.DecodeSegment(parts[1])
	if err != nil {
		return nil, err
	}

	jwtClaims := make(map[string]interface{})
	if err = json.Unmarshal(js, &jwtClaims); err != nil {
		return nil, err
	}
	return jwtClaims, nil
}

func NewJTI() string {
	return uuid.New().String()
}

func GetStrClaimFromJWTStr(claim string, jwtStr string) string {
	if jwtStr == "" {
		return ""
	}
	claims, err := jwtPayload(jwtStr)
	if err != nil {
		return ""
	}
	if id, ok := claims[claim]; ok {
		if ids, ok := id.(string); ok {
			return ids
		}
	}
	return ""
}

func GetInt64ClaimFromJWTStr(claim string, jwtStr string) int64 {
	if jwtStr == "" {
		return 0
	}
	claims, err := jwtPayload(jwtStr)
	if err != nil {
		return 0
	}
	if id, ok := claims[claim]; ok {
		switch idv := id.(type) {
		case int:
			return int64(idv)
		case int64:
			return idv
		case float64:
			return int64(idv)
		default:
			//fmt.Printf("XXX unknown type: %T\n", idv)
			return 0
		}
	}
	return 0
}
