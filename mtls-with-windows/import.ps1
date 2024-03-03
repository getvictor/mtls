# This script imports mTLS certificates and keys into the certificate store.

# Import the server CA
Import-Certificate -FilePath "certs\server-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
# Import the client CA so that client TLS certificates can be verified
Import-Certificate -FilePath "certs\client-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
# Import the client TLS certificate and key
Import-PfxCertificate -FilePath "certs\client.pfx" -CertStoreLocation Cert:\CurrentUser\My
