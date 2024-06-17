package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/quic-go/quic-go/http3"
)

func main() {
		keyLog, err := os.Create("key.log")
	if err != nil {
		log.Fatal("keylog: %v", err)
	}

	r := http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
			KeyLogWriter: keyLog,
		},
	}
	req, _ := http.NewRequest("GET", "https://localhost:18443", nil)

	resp, err := r.RoundTrip(req)
	if err != nil {
		log.Fatal(err)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Print(string(body))

}
