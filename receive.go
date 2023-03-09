/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2023 HashiCorp Inc.
 */

package lite

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type queueHandshakeElement struct {
	msgType uint32
	packet  []byte
	buffer  *[maxMessageSize]byte
}

type queueInboundElement struct {
	sync.Mutex
	buffer  *[maxMessageSize]byte
	packet  []byte
	counter uint64
	keypair *keypair
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *queueInboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Load() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair != nil && keypair.isInitiator && time.Since(keypair.created) > (rejectAfterTime-keepaliveTimeout-rekeyTimeout) {
		peer.timers.sentLastMinuteHandshake.Store(true)
		peer.sendHandshakeInitiation(false)
	}
}

/* Receives incoming datagrams for the device
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */
func (s *StreamGuard) routineReceiveIncoming(recv receiveFunc) {
	defer func() {
		log.Printf("Routine: receive incoming - stopped")
		s.queue.decryption.wg.Done()
		s.queue.handshake.wg.Done()
		s.packetStream.stopping.Done()
		go s.Close()
	}()

	log.Printf("Routine: receive incoming - started")

	// receive datagrams until conn is closed
	buffer := s.getMessageBuffer()
	var (
		err         error
		size        int
		deathSpiral int
	)

	for {
		size, err = recv(buffer[:])

		if err != nil {
			s.putMessageBuffer(buffer)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if neterr, ok := err.(net.Error); ok && !neterr.Temporary() {
				return
			}
			if deathSpiral < 10 {
				deathSpiral++
				time.Sleep(time.Second / 3)
				buffer = s.getMessageBuffer()
				continue
			}
			return
		}
		deathSpiral = 0

		if size < minMessageSize {
			continue
		}

		// check size of packet

		packet := buffer[:size]
		msgType := binary.LittleEndian.Uint32(packet[:4])

		var okay bool

		switch msgType {

		// check if transport

		case messageTransportType:

			// check size
			if len(packet) < messageTransportSize {
				log.Printf("Ignoring message transport because size is too small %d < %d", len(packet), messageTransportSize)
				continue
			}

			// lookup key pair
			value := s.handshakeKeypair
			if value == nil || value.keypair == nil {
				continue
			}
			keypair := value.keypair

			// check keypair expiry

			if keypair.created.Add(rejectAfterTime).Before(time.Now()) {
				continue
			}

			// create work element
			peer := s.peer
			elem := s.getInboundElement()
			elem.packet = packet
			elem.buffer = buffer
			elem.keypair = keypair
			elem.counter = 0
			elem.Mutex = sync.Mutex{}
			elem.Lock()

			// add to decryption queues
			if peer.isRunning.Load() {
				peer.queue.inbound.c <- elem
				s.queue.decryption.c <- elem
				buffer = s.getMessageBuffer()
			} else {
				s.putInboundElement(elem)
			}
			continue

		// otherwise it is a fixed size & handshake related packet

		case messageInitiationType:
			okay = len(packet) == messageInitiationSize

		case messageResponseType:
			okay = len(packet) == messageResponseSize

		case messageCookieReplyType:
			okay = len(packet) == messageCookieReplySize

		default:
			log.Printf("Received message with unknown type")
		}

		if okay {
			select {
			case s.queue.handshake.c <- queueHandshakeElement{
				msgType: msgType,
				buffer:  buffer,
				packet:  packet,
			}:
				buffer = s.getMessageBuffer()
			default:
			}
		}
	}
}

func (s *StreamGuard) routineDecryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer log.Printf("Routine: decryption worker %d - stopped", id)
	log.Printf("Routine: decryption worker %d - started", id)

	for elem := range s.queue.decryption.c {
		// split message into fields
		counter := elem.packet[messageTransportOffsetCounter:messageTransportOffsetContent]
		content := elem.packet[messageTransportOffsetContent:]

		// decrypt and release to consumer
		var err error
		elem.counter = binary.LittleEndian.Uint64(counter)
		// copy counter to nonce
		binary.LittleEndian.PutUint64(nonce[0x4:0xc], elem.counter)
		elem.packet, err = elem.keypair.receive.Open(
			content[:0],
			nonce[:],
			content,
			nil,
		)
		if err != nil {
			elem.packet = nil
		}
		elem.Unlock()
	}
}

/* Handles incoming packets related to handshake
 */
func (s *StreamGuard) routineHandshake(id int) {
	defer func() {
		log.Printf("Routine: handshake worker %d - stopped", id)
		s.queue.encryption.wg.Done()
	}()
	log.Printf("Routine: handshake worker %d - started", id)

	for elem := range s.queue.handshake.c {

		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case messageCookieReplyType:

			// unmarshal packet
			var reply messageCookieReply
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &reply)
			if err != nil {
				goto skip
			}
			if s.peer == nil {
				goto skip
			}
			// consume reply
			if peer := s.peer; peer.isRunning.Load() {
				if !peer.cookieGenerator.consumeReply(&reply) {
					log.Printf("Could not decrypt invalid cookie response")
				}
			}

			goto skip

		case messageInitiationType, messageResponseType:

			// check 1st mac field
			if !s.cookieChecker.checkMAC1(elem.packet) {
				goto skip
			}

		default:
			log.Printf("Invalid packet ended up in the handshake queue")
			goto skip
		}

		// handle handshake initiation/response content
		switch elem.msgType {
		case messageInitiationType:

			// unmarshal
			var msg messageInitiation
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				goto skip
			}

			// consume initiation
			peer := s.consumeMessageInitiation(&msg)
			if peer == nil {
				goto skip
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			peer.rxBytes.Add(uint64(len(elem.packet)))

			peer.sendHandshakeResponse()

		case messageResponseType:

			// unmarshal

			var msg messageResponse
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				goto skip
			}

			// consume response

			peer := s.consumeMessageResponse(&msg)
			if peer == nil {
				goto skip
			}

			peer.rxBytes.Add(uint64(len(elem.packet)))

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair

			err = peer.beginSymmetricSession()

			if err != nil {
				goto skip
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.sendKeepalive()
		}
	skip:
		s.putMessageBuffer(elem.buffer)
	}
}

func (peer *peer) routineSequentialReceiver() {
	device := peer.device
	defer func() {
		log.Printf("%v - Routine: sequential receiver - stopped", peer)
		peer.stopping.Done()
		go device.Close()
	}()
	log.Printf("%v - Routine: sequential receiver - started", peer)

	for elem := range peer.queue.inbound.c {
		if elem == nil {
			return
		}
		var length uint16
		var err error

		elem.Lock()
		if elem.packet == nil {
			// decryption failed
			goto skip
		}

		if !elem.keypair.replayFilter.ValidateCounter(elem.counter, rejectAfterMessages) {
			goto skip
		}

		if peer.receivedWithKeypair(elem.keypair) {
			peer.timersHandshakeComplete()
			peer.sendStagedPackets()
		}

		peer.keepKeyFreshReceiving()
		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketReceived()
		peer.rxBytes.Add(uint64(len(elem.packet) + minMessageSize))

		if len(elem.packet) == 0 {
			goto skip
		}
		peer.timersDataReceived()
		if len(elem.packet) < 2 {
			goto skip
		}
		length = binary.BigEndian.Uint16(elem.packet[:2])
		if int(length) > len(elem.packet)-2 {
			goto skip
		}
		elem.packet = elem.packet[2 : 2+int(length)]
		_, err = device.stagedReadWriter.incomingWrite(elem.packet)

		if err != nil && !device.isClosed() {
			log.Printf("Failed to write packet to TUN device: %v", err)
		}
	skip:
		device.putMessageBuffer(elem.buffer)
		device.putInboundElement(elem)
	}
}
