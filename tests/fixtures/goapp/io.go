package main

import (
	"fmt"
	"os"
)

func logStartup() {
	// Harmless: standard I/O error ignored in non-security logging
	f, _ := os.Open("banner.txt")
	if f != nil {
		defer f.Close()
	}
	fmt.Println("Server started")
}
