Full article: [Mutual TLS intro and hands-on example](https://victoronsoftware.com/posts/mtls-hello-world/)

`curl` can use `--insecure` to ignore the server certificate:
```shell
curl --insecure https://localhost:8888/hello-world.txt
TLS Hello World!
```

Connect to the TLS server:
```shell
curl https://localhost:8888/hello-world.txt --cacert ./certs/server-ca.crt
TLS Hello World!
```

Connect to the mTLS server:
```shell
curl https://localhost:8889/hello-world.txt --cacert ./certs/server-ca.crt --cert ./certs/client.crt --key ./certs/client.key
mTLS Hello World!
```
