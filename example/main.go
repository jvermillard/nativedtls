package main

/*
#cgo LDFLAGS: /home/jvermillar/sandbox/openssl/libssl.a /home/jvermillar/sandbox/openssl/libcrypto.a
#cgo CFLAGS: -g -Wno-deprecated -I/home/jvermillar/sandbox/openssl/include
*/
import "C"

import (
	"fmt"
	"net"

	"github.com/jvermillard/nativedtls"
)

func main() {
	nativedtls.Init()
	ctx := nativedtls.NewDTLSContext()
	if !ctx.SetCipherList("PSK-AES256-CCM8:PSK-AES128-CCM8") {
		panic("impossible to set cipherlist")
	}
	conn, err := net.Dial("udp", "localhost:5684")
	if err != nil {
		panic(err)
	}
	c := nativedtls.NewDTLSClient(ctx, conn)
	c.SetPSK("Client_identity", []byte("secretPSK"))
	if _, err = c.Write([]byte("Yeah!\n")); err != nil {
		panic(err)
	}

	buff := make([]byte, 1500)
	c.Read(buff)

	fmt.Println("Rcvd:", string(buff))

	c.Close()
}
