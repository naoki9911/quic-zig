package main

import (
	"crypto/tls"
	"fmt"
	"github.com/quic-go/quic-go/http3"
	"log"
	"net/http"
	"os"
)

func HelloHTTP3Server(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("client from : %s\n", req.RemoteAddr)
	fmt.Fprintf(w, "hello\n")
}

func main() {

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(HelloHTTP3Server))

	w := os.Stdout
	
	server := http3.Server{
		Addr: ":18443",
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			KeyLogWriter: w,
		},
		Handler: mux,
	}

	err := server.ListenAndServeTLS("./cert.pem", "./key.pem")
	if err != nil {
		log.Fatal(err)
	}
}
