package main

import "C"

import (
	"fmt"
	"net"
	"strings"

	"github.com/jvermillard/nativedtls"
)

func main() {
	ctx := nativedtls.NewServerDTLSContext()
	if !ctx.SetCipherList("PSK-AES256-CCM8:PSK-AES128-CCM8") {
		panic("impossible to set cipherlist")
	}

	svrAddr, err := net.ResolveUDPAddr("udp", ":5684")

	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", svrAddr)

	server := nativedtls.NewDTLSServer(ctx, conn)

	server.SetPskCallback(func(pskId string) []byte {
		fmt.Println("PSK ID:", pskId)
		return []byte("secretPSK")
	})
	fmt.Println("Accept")
	session, err := server.Accept()

	if err != nil {
		panic(err)
	}
	fmt.Println("session ", session)

	for {
		buff := make([]byte, 1500)
		count, err := session.Read(buff)

		if err != nil {
			panic(err)
		}
		fmt.Println("Rcvd:", string(buff))

		if strings.HasPrefix(string(buff), "quit") {
			break
		}
		fmt.Println(count, err)

		fmt.Println("Send echo")

		session.Write([]byte("echo :D\n"))
	}

	session.Close()

	fmt.Println("bye")
}
