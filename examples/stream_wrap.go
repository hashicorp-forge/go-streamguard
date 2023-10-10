package main

import (
	"fmt"
	"net"
	"time"

	streamguard "github.com/hashicorp/go-streamguard"
)

func server(incomingKey chan streamguard.NoisePublicKey, outgoingKey chan streamguard.NoisePublicKey, port int) {
	tcpListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		panic(err)
	}
	defer tcpListener.Close()
	fmt.Printf("Server waiting on port %d\n", port)

	sock, err := tcpListener.Accept()
	if err != nil {
		panic(err)
	}
	defer sock.Close()
	fmt.Printf("Server accepted connection on %+v", sock)

	stream, err := streamguard.WrapStream(sock)
	if err != nil {
		panic(err)
	}
	defer stream.Close()

	// cross the streams
	outgoingKey <- *stream.PublicKey()
	clientKey := <-incomingKey

	err = stream.SetPeer(clientKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Server has wrapped and set the key\n")

	msg := []byte{1, 2, 3, 4}
	fmt.Printf("Server sending message: %+v\n", msg)
	n, err := stream.Write(msg)
	if n != 4 || err != nil {
		panic(err)
	}

	buff := make([]byte, 128)

	n, err = stream.Read(buff)
	if err != nil {
		panic(fmt.Errorf("error reading from server packetStream. Read %d bytes, err %+v", n, err))
	}
	fmt.Printf("Server received message: %+v\n", msg[:n])

	time.Sleep(1 * time.Second)
}

func client(incomingKey chan streamguard.NoisePublicKey, outgoingKey chan streamguard.NoisePublicKey, port int) {
	fmt.Printf("Client connecting to port %d\n", port)
	sock, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		panic(err)
	}
	defer sock.Close()
	fmt.Printf("Client connected\n")

	clientStream, err := streamguard.WrapStream(sock)
	if err != nil {
		panic(err)
	}
	defer clientStream.Close()

	// cross the streams
	serverKey := <-incomingKey
	outgoingKey <- *clientStream.PublicKey()

	err = clientStream.SetPeer(serverKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Client has wrapped the stream and set the key\n")

	buff := make([]byte, 128)
	n, err := clientStream.Read(buff)
	if n != 4 || err != nil {
		panic(fmt.Errorf("error reading from client packetStream. Read %d bytes, err %+v", n, err))
	}
	fmt.Printf("Client received message: %+v\n", buff[:n])

	msg := []byte{104, 105, 106, 107}
	fmt.Printf("Client sending message: %+v\n", msg)
	_, err = clientStream.Write(msg)
	if err != nil {
		panic(err)
	}

	time.Sleep(1 * time.Second)
}

func main() {
	keyCh1 := make(chan streamguard.NoisePublicKey)
	keyCh2 := make(chan streamguard.NoisePublicKey)
	port := 9999
	go server(keyCh1, keyCh2, port)
	time.Sleep(1 * time.Second)
	client(keyCh2, keyCh1, port)
}
