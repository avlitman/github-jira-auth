package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// verifySignature computes the expected signature using the hex-encoded secret,
// normalizes both signatures to lower case, and compares them.
func verifySignature(secretHex, signature string, body []byte) (bool, error) {
	// Decode the hex-encoded secret.
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode secret: %v", err)
	}

	mac := hmac.New(sha256.New, secret)
	if _, err := mac.Write(body); err != nil {
		return false, fmt.Errorf("failed to compute HMAC: %v", err)
	}
	expectedMAC := mac.Sum(nil)
	expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC)

	// Normalize both signatures to lower case.
	normalizedExpected := strings.ToLower(expectedSignature)
	normalizedReceived := strings.ToLower(signature)

	// Debug logs.
	log.Printf("DEBUG: Computed signature (normalized): %s", normalizedExpected)
	log.Printf("DEBUG: Received signature (normalized): %s", normalizedReceived)

	if !hmac.Equal([]byte(normalizedExpected), []byte(normalizedReceived)) {
		return false, fmt.Errorf("signature mismatch: expected '%s', got '%s'", normalizedExpected, normalizedReceived)
	}
	return true, nil
}

func forwardToJira(url string, payload []byte, w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		log.Printf("Error creating request to JIRA: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Forward select headers from the original request.
	for _, h := range []string{
		"Accept", "Content-Type", "User-Agent",
		"X-GitHub-Delivery", "X-GitHub-Event",
		"X-GitHub-Hook-ID", "X-GitHub-Hook-Installation-Target-ID",
		"X-GitHub-Hook-Installation-Target-Type",
	} {
		req.Header.Set(h, r.Header.Get(h))
	}

	client := &http.Client{}
	log.Printf("Forwarding webhook to Jira: %s", url)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error forwarding request to JIRA: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response from JIRA: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("JIRA response status: %d", resp.StatusCode)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBody)
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		log.Printf("Missing X-Hub-Signature-256 header")
		http.Error(w, "Missing signature", http.StatusUnauthorized)
		return
	}

	// Log the signature and body (base64 encoded) to help with debugging.
	log.Printf("DEBUG: Signature (base64): %s", base64.StdEncoding.EncodeToString([]byte(signature)))
	log.Printf("DEBUG: Body (base64): %s", base64.StdEncoding.EncodeToString(body))

	githubSecret := os.Getenv("GITHUB_SECRET")
	jiraURL := os.Getenv("JIRA_URL")
	if githubSecret == "" || jiraURL == "" {
		log.Println("Missing GITHUB_SECRET or JIRA_URL environment variables")
		http.Error(w, "Server misconfiguration", http.StatusInternalServerError)
		return
	}

	valid, err := verifySignature(githubSecret, signature, body)
	if !valid {
		log.Printf("Signature verification failed: %v", err)
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	log.Printf("Received valid webhook: %s", string(body))
	forwardToJira(jiraURL, body, w, r)
}

func main() {
	http.HandleFunc("/", handler)
	log.Println("Server listening on port 9900...")
	log.Fatal(http.ListenAndServe(":9900", nil))
}
