# ktls-bpf_redirect-example

## How to test

In the first terminal, launch the program
```bash
sudo go run .
```

In the second terminal, launch a listening `nc`
```bash
nc -lp 8080
```

In the last terminal, launch an openssl client
```bash
openssl s_client -connect 127.0.0.1:8081
```


You should see decrypted data on the `nc` terminal.