package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	githubSecretPath := flag.String("github-webhook-secret-path", "", "Path to the GitHub secret")
	jiraWebhookURLPath := flag.String("jira-webhook-secret-path", "", "Path to the JIRA webhook URL")
	flag.Parse()

	githubSecret, err := ioutil.ReadFile(*githubSecretPath)
	if err != nil {
		log.Fatalf("Failed to read GitHub secret: %v", err)
	}

	jiraWebhookURL, err := ioutil.ReadFile(*jiraWebhookURLPath)
	if err != nil {
		log.Fatalf("Failed to read JIRA webhook URL: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		signature := r.Header.Get("X-Hub-Signature-256")
		payload, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading request body: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if verifySignature(githubSecret, signature, payload) {
			forwardToJira(string(jiraWebhookURL), payload, w, r)
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})

	log.Println("Listening on port 9900...")
	log.Fatal(http.ListenAndServe(":9900", nil))
}

func verifySignature(secret []byte, signature string, payload []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)
	expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC)
	log.Printf("Expected Signature: %s", expectedSignature)
	log.Printf("Received Signature: %s", signature)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

func forwardToJira(url string, payload []byte, w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		log.Printf("Error creating request to JIRA: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Copy selected headers
	for _, h := range []string{"Accept", "Content-Type", "User-Agent", "X-GitHub-Delivery", "X-GitHub-Event", "X-GitHub-Hook-ID", "X-GitHub-Hook-Installation-Target-ID", "X-GitHub-Hook-Installation-Target-Type"} {
		req.Header.Set(h, r.Header.Get(h))
	}

	// Remove signature headers
	req.Header.Del("X-Hub-Signature")
	req.Header.Del("X-Hub-Signature-256")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error forwarding request to JIRA: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response from JIRA: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func copyHeaders(source http.Header, destination http.Header) {
	for key, values := range source {
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}
