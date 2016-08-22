# nativedtls
Golang DTLS library using OpenSSL 1.1.0-pre7-dev.

Look at the example_server and example_client directories for usage.

Based on https://github.com/shanemhansen/gossl BIO glue between cgo and go.

Build with OpenSSL 1.1 or master.

## Compiling
Before building, go in the openssl sub-directory, do "./config && make"
