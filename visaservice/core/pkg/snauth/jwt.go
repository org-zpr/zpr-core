package snauth

// Some misc jwt realted functions used in the auth package.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func jwtPayload(ss string) (map[string]interface{}, error) {
	parts := strings.Split(ss, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT, expected three parts")
	}
	parser := jwt.NewParser()
	js, err := parser.DecodeSegment(parts[1])
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

func GetAllClaimsAsStrings(jwtStr string) (map[string]string, error) {
	claims, err := jwtPayload(jwtStr)
	if err != nil {
		return nil, err
	}
	strClaims := make(map[string]string)
	for k, v := range claims {
		switch v.(type) {
		case string:
			strClaims[k] = v.(string)
		case int:
			strClaims[k] = fmt.Sprintf("%d", v.(int))
		case int64:
			strClaims[k] = fmt.Sprintf("%d", v.(int64))
		case float64:
			strClaims[k] = fmt.Sprintf("%f", v.(float64))
		default:
			strClaims[k] = fmt.Sprintf("%v", v)
		}
	}
	return strClaims, nil
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
