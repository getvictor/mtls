Full article: Coming soon to https://victoronsoftware.com/

```
   PSParentPath: Microsoft.PowerShell.Security\Certificate::LocalMachine\Root

Thumbprint                                Subject
----------                                -------
0A31BF3C48A3D98A91A2F63B5BD286818311A707  CN=testServerCA, OU=Your Unit, O=Your Organization, L=Austin, S=Texas, C=US
7F7E5612F3A90B9EB246762358251F98911A9D1A  CN=testClientCA, OU=Your Unit, O=Your Organization, L=Austin, S=Texas, C=US


   PSParentPath: Microsoft.PowerShell.Security\Certificate::CurrentUser\My

Thumbprint                                Subject
----------                                -------
E2EBB991E3849E32E934D8465FAE42787D34C9ED  CN=testClientTLS, OU=Your Unit, O=Your Organization, L=Austin, S=Texas, C=US
```

```
StatusCode        : 200
StatusDescription : OK
Content           : TLS Hello World!

RawContent        : HTTP/1.1 200 OK
                    Connection: keep-alive
                    Accept-Ranges: bytes
                    Content-Length: 17
                    Content-Type: text/plain
                    Date: Sun, 03 Mar 2024 17:28:29 GMT
                    ETag: "65b29c19-11"
                    Last-Modified: Thu, 25 Jan 2024 1...
Forms             : {}
Headers           : {[Connection, keep-alive], [Accept-Ranges, bytes], [Content-Length, 17], [Content-Type, text/plain]...}
Images            : {}
InputFields       : {}
Links             : {}
ParsedHtml        : System.__ComObject
RawContentLength  : 17
```

```plaintext
Invoke-WebRequest : 400 Bad Request
No required SSL certificate was sent
nginx/1.25.3
At line:1 char:1
+ Invoke-WebRequest -Uri https://myhost:8889/hello-world.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:HttpWebRequest) [Invoke-WebRequest], WebException
    + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand
```

```plaintext
StatusCode        : 200
StatusDescription : OK
Content           : mTLS Hello World!

RawContent        : HTTP/1.1 200 OK
                    Connection: keep-alive
                    Accept-Ranges: bytes
                    Content-Length: 18
                    Content-Type: text/plain
                    Date: Sun, 03 Mar 2024 17:31:55 GMT
                    ETag: "65b29c19-12"
                    Last-Modified: Thu, 25 Jan 2024 1...
Forms             : {}
Headers           : {[Connection, keep-alive], [Accept-Ranges, bytes], [Content-Length, 18], [Content-Type, text/plain]...}
Images            : {}
InputFields       : {}
Links             : {}
ParsedHtml        : System.__ComObject
RawContentLength  : 18
```