package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
)

func verifySignature(secret, signature string, body []byte) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

func forwardToJira(url string, payload []byte, w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		log.Printf("Error creating request to JIRA: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	for _, h := range []string{
		"Accept", "Content-Type", "User-Agent",
		"X-GitHub-Delivery", "X-GitHub-Event",
		"X-GitHub-Hook-ID", "X-GitHub-Hook-Installation-Target-ID",
		"X-GitHub-Hook-Installation-Target-Type"} {
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response from JIRA: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("JIRA response status: %d", resp.StatusCode)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		http.Error(w, "Missing signature", http.StatusUnauthorized)
		return
	}

	log.Printf(b64.StdEncoding.EncodeToString([]byte(signature)))
	log.Printf(b64.StdEncoding.EncodeToString(body))

	githubSecret := os.Getenv("GITHUB_SECRET")
	jiraURL := os.Getenv("JIRA_URL")
	if githubSecret == "" || jiraURL == "" {
		log.Println("Missing GITHUB_SECRET or JIRA_URL environment variables")
		http.Error(w, "Server misconfiguration", http.StatusInternalServerError)
		return
	}

	if !verifySignature(githubSecret, signature, body) {
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
