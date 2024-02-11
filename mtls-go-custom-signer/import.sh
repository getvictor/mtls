#!/bin/bash

# This script imports mTLS certificates and keys into the Apple Keychain.

# Import the server CA
security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/server-ca.crt

# Import the client CA so that client TLS certificates can be verified
security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/client-ca.crt
# Import the client TLS certificate and key
security import certs/client.crt -k /Library/Keychains/System.keychain
security import certs/client.key -k /Library/Keychains/System.keychain -x -T /usr/bin/curl -T /Applications/Safari.app -T '/Applications/Google Chrome.app'
