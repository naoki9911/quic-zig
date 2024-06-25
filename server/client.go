package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	keyLogFile := flag.String("keylog", "", "key log file")
	flag.Parse()

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: true,
		NextProtos:         []string{"test"},
		KeyLogWriter:       keyLog,
	}

	con, err := quic.DialAddr(context.TODO(), "127.0.0.1:4242", tlsConfig, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Success to open connection")

	stream, err := con.OpenStreamSync(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	defer stream.Close()
	fmt.Println("Success to open stream")

	writeSize, err := stream.Write([]byte("hello"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Written %d bytes\n", writeSize)

	err = stream.Close()
	if err != nil {
		log.Fatal(err)
	}

	time.Sleep(1 * time.Second)
}
