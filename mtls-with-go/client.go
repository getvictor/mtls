package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {

	urlPath := flag.String("url", "", "URL to make request to")
	flag.Parse()
	if *urlPath == "" {
		log.Fatalf("URL to make request to is required")
	}

	client := http.Client{}

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
