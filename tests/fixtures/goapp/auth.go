package main

import (
	"errors"
	"fmt"
)

func verifyToken(token string) (bool, error) {
	if token != "secret_admin_token" {
		return false, errors.New("invalid token")
	}
	return true, nil
}

func handleAdminAction(token string) bool {
	// Vulnerable: Error ignored on security-critical check leading to fail-open
	valid, _ := verifyToken(token)
	if valid {
		fmt.Println("Access granted")
		return true
	}
	return false
}
