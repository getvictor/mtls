#!/bin/bash

security verify-cert -c certs/server.crt -p ssl -s localhost -k /Library/Keychains/System.keychain
security find-identity -p ssl-client /Library/Keychains/System.keychain
