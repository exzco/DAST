package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"distributed-scanner/internal/config"
)

func main() {
	cfg := config.Load()
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models?key=%s", cfg.AI.APIKey)
	
	fmt.Printf("[*] Fetching available models for this API key...\n")
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("[!] Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("[+] Models JSON payload:\n%s\n", string(body))
}
