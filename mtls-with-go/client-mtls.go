package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {

	urlPath := flag.String("url", "", "URL to make request to")
	clientCert := flag.String("cert", "", "Client certificate file")
	clientKey := flag.String("key", "", "Client key file")
	flag.Parse()
	if *urlPath == "" {
		log.Fatalf("URL to make request to is required")
	}

	var certificate tls.Certificate
	if *clientCert != "" && *clientKey != "" {
		var err error
		certificate, err = tls.LoadX509KeyPair(*clientCert, *clientKey)
		if err != nil {
			log.Fatalf("error loading client certificate: %v", err)
		}
	}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{certificate},
			},
		},
	}

	// Make a GET request to the URL
	rsp, err := client.Get(*urlPath)
	if err != nil {
		log.Fatalf("error making get request: %v", err)
	}
	defer func() { _ = rsp.Body.Close() }()

	// Read the response body
	rspBytes, err := io.ReadAll(rsp.Body)
	if err != nil {
		log.Fatalf("error reading response: %v", err)
	}

	// Print the response body
	fmt.Printf("%s\n", string(rspBytes))
}
