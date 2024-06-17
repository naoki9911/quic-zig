package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/quic-go/quic-go"
)

func main() {
	tlsCert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal("tls.LoadX509KeyPair: ", err)
	}
	keyLog, err := os.Create("key.log")
	if err != nil {
		log.Fatal("keylog: %v", err)
	}
	defer keyLog.Close()
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"test"},
		KeyLogWriter: keyLog,
	}

	listener, err := quic.ListenAddr(":4242", tlsConfig, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

	conn, err := listener.Accept(context.Background())
	if err != nil {
		log.Fatal("Accept: ", err)
	}
	fmt.Println("Connection accepted")

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Fatal("AcceptStream: ", err)
	}
	defer stream.Close()
	fmt.Println("Stream accepted")

	buf := make([]byte, 100)
	readSize, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}
	fmt.Printf("recv=%s\n", string(buf[0:readSize]))
}
