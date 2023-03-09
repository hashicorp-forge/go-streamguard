/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2023 HashiCorp Inc.
 */

package lite

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

func TestStreamWrap(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()

	var sideB net.Conn
	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		sideB, err = tcpListener.Accept()
		if err != nil {
			panic(err)
		}
		wg.Done()
	}()

	sideA, err := net.Dial("tcp", "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}

	// make sure we have the other side too
	wg.Wait()

	defer sideB.Close()
	defer sideA.Close()

	serverStream, err := WrapStream(sideA)
	if err != nil {
		t.Fatal(err)
	}
	defer serverStream.Close()

	clientStream, err := WrapStream(sideB)
	if err != nil {
		t.Fatal(err)
	}
	defer clientStream.Close()

	// cross the streams
	err = serverStream.SetPeer(clientStream.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	err = clientStream.SetPeer(serverStream.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	err = serverStream.up()
	if err != nil {
		t.Fatal(err)
	}
	err = clientStream.up()
	if err != nil {
		t.Fatal(err)
	}
	n, err := serverStream.Write([]byte{1, 2, 3, 4})
	if n != 4 || err != nil {
		t.Error(err)
	}
	time.Sleep(1 * time.Second)
	buff := make([]byte, 128, 128)
	n, err = clientStream.Read(buff)
	if n != 4 || err != nil {
		t.Errorf("Error reading from client packetStream. Read %d bytes, err %+v", n, err)
	}
	_, err = clientStream.Write([]byte{104, 105, 106, 107})
	if err != nil {
		t.Error(err)
	}
	time.Sleep(1 * time.Second)
	n, err = serverStream.Read(buff)
	if n != 4 || err != nil {
		t.Errorf("Error reading from server packetStream. Read %d bytes, err %+v", n, err)
	}

	// send a bunch of times server -> client
	for i := 0; i < 100; i++ {
		l := rand.Intn(1000) + 1
		buff := make([]byte, l, l)
		rand.Read(buff)

		n, err = serverStream.Write(buff)
		if err != nil {
			t.Fatal(err)
		}
		if n != l {
			t.Fatalf("Wrong length, got %d expected %d", n, l)
		}

		newBuff := make([]byte, 65536, 65536)
		n, err = clientStream.Read(newBuff)
		if err != nil {
			t.Fatal(err)
		}
		if n != l {
			t.Fatalf("Wrong length, got %d expected %d", n, l)
		}
		if !bytes.Equal(buff, newBuff[:n]) {
			t.Fatalf("Got unequal: %s != %s", hex.EncodeToString(buff), hex.EncodeToString(newBuff[:n]))
		}
	}
	// send a bunch of times client -> server
	for i := 0; i < 100; i++ {
		l := rand.Intn(1000) + 1
		buff := make([]byte, l, l)
		rand.Read(buff)

		n, err = clientStream.Write(buff)
		if err != nil {
			t.Fatal(err)
		}
		if n != l {
			t.Fatalf("Wrong length, got %d expected %d", n, l)
		}

		newBuff := make([]byte, 65536, 65536)
		n, err = serverStream.Read(newBuff)
		if err != nil {
			t.Fatal(err)
		}
		if n != l {
			t.Fatalf("Wrong length, got %d expected %d", n, l)
		}
		if !bytes.Equal(buff, newBuff[:n]) {
			t.Fatalf("Got unequal: %s != %s", hex.EncodeToString(buff), hex.EncodeToString(newBuff[:n]))
		}
	}
}

func TestListenerWrap(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()

	listener, err := WrapListener(tcpListener)
	if err != nil {
		t.Fatal(err)
	}

	var sideB net.Conn
	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		sideB, err = listener.Accept()
		if err != nil {
			panic(err)
		}
		wg.Done()
	}()

	sideA, err := net.Dial("tcp", "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}

	// make sure we have the other side too
	wg.Wait()

	defer sideB.Close()
	defer sideA.Close()

	sideAKey, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	clientStream := sideB
	fmt.Printf("Setting peer key for client\n")
	err = clientStream.(*StreamGuard).SetPeer(sideAKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	listener.SetPeer(sideAKey.PublicKey())

	serverStream, err := WrapStreamWithKey(sideA, sideAKey)
	if err != nil {
		t.Fatal(err)
	}
	defer serverStream.Close()

	// cross the streams
	err = serverStream.SetPeer(clientStream.(*StreamGuard).publicKey)
	if err != nil {
		t.Fatal(err)
	}
	err = clientStream.(*StreamGuard).up()
	err = serverStream.up()
	if err != nil {
		t.Fatal(err)
	}
	n, err := serverStream.Write([]byte{1, 2, 3, 4})
	if n != 4 || err != nil {
		t.Error(err)
	}
	time.Sleep(1 * time.Second)
	buff := make([]byte, 128, 128)
	n, err = clientStream.Read(buff)
	if n != 4 || err != nil {
		t.Errorf("Error reading from client packetStream. Read %d bytes, err %+v", n, err)
	}
	_, err = clientStream.Write([]byte{104, 105, 106, 107})
	if err != nil {
		t.Error(err)
	}
	time.Sleep(1 * time.Second)
	n, err = serverStream.Read(buff)
	if n != 4 || err != nil {
		t.Errorf("Error reading from server packetStream. Read %d bytes, err %+v", n, err)
	}
}
