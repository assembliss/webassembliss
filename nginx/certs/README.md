Add ssl certificates here for https connections.
If developing, you can generate self-signed certs with the following command:
```
openssl req -x509 -newkey rsa:4096 -keyout assembliss_cert.key -out assembliss_cert.pem -sha256 -days 7 -nodes -subj "/C=US/ST=North Carolina/L=Raleigh/O=DEV CERT - DO NOT TRUST/OU=DEV CERT - DO NOT TRUST/CN=DEV CERT - DO NOT TRUST"
```

If deploying, add appropriate `assembliss_cert.pem` and `assembliss_cert.key` files in this folder.
