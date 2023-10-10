/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2023 HashiCorp Inc.
 */

package streamguard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */

type queueOutboundElement struct {
	sync.Mutex
	buffer  *[maxMessageSize]byte // slice holding the packet data
	packet  []byte                // slice of "buffer" (always!)
	nonce   uint64                // nonce for encryption
	keypair *keypair              // keypair for encryption
	peer    *peer                 // related peer
}

func (s *StreamGuard) newOutboundElement() *queueOutboundElement {
	elem := s.getOutboundElement()
	elem.buffer = s.getMessageBuffer()
	elem.Mutex = sync.Mutex{}
	elem.nonce = 0
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *queueOutboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
}

/* Queues a keepalive if no packets are queued for peer
 */
func (peer *peer) sendKeepalive() {
	if len(peer.queue.staged) == 0 && peer.isRunning.Load() {
		elem := peer.device.newOutboundElement()
		select {
		case peer.queue.staged <- elem:
			log.Printf("%v - Sending keepalive packet", peer)
		default:
			peer.device.putMessageBuffer(elem.buffer)
			peer.device.putOutboundElement(elem)
		}
	}
	peer.sendStagedPackets()
}

func (peer *peer) sendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		peer.timers.handshakeAttempts.Store(0)
	}

	peer.handshake.mutex.RLock()
	if time.Since(peer.handshake.lastSentHandshake) < rekeyTimeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	peer.handshake.mutex.Lock()
	if time.Since(peer.handshake.lastSentHandshake) < rekeyTimeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	msg, err := peer.device.createMessageInitiation(peer)
	if err != nil {
		return err
	}

	var buff [messageInitiationSize]byte
	writer := bytes.NewBuffer(buff[:0])
	binary.Write(writer, binary.LittleEndian, msg)
	packet := writer.Bytes()
	peer.cookieGenerator.addMacs(packet)

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	//log.Printf("sendBuffer: %s", hex.EncodeToString(packet))
	err = peer.sendBuffer(packet)
	if err != nil {
		log.Printf("%v - Failed to send handshake initiation: %v", peer, err)
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *peer) sendHandshakeResponse() error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	response, err := peer.device.createMessageResponse(peer)
	if err != nil {
		return err
	}

	var buff [messageResponseSize]byte
	writer := bytes.NewBuffer(buff[:0])
	binary.Write(writer, binary.LittleEndian, response)
	packet := writer.Bytes()
	peer.cookieGenerator.addMacs(packet)

	err = peer.beginSymmetricSession()
	if err != nil {
		return err
	}

	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	return peer.sendBuffer(packet)
}

func (peer *peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	nonce := keypair.sendNonce.Load()
	if nonce > rekeyAfterMessages || (keypair.isInitiator && time.Since(keypair.created) > rekeyAfterTime) {
		peer.sendHandshakeInitiation(false)
	}
}

// Reads packets from the stagedReadWriter and inserts
// into staged queue for peer
func (s *StreamGuard) routineReadFromStagedReadWriter() {
	defer func() {
		log.Printf("Routine: stagedReadWriter reader - stopped")
		s.state.stopping.Done()
		s.queue.encryption.wg.Done()
	}()

	log.Printf("Routine: stagedReadWriter reader - started")

	var elem *queueOutboundElement

	for {
		if elem != nil {
			s.putMessageBuffer(elem.buffer)
			s.putOutboundElement(elem)
		}
		elem = s.newOutboundElement()

		// read packet

		offset := messageTransportHeaderSize
		size, err := s.stagedReadWriter.outgoingRead(elem.buffer[:][offset:])
		if err != nil {
			if !s.isClosed() {
				if !errors.Is(err, os.ErrClosed) {
					log.Printf("Failed to read packet from packetStream: %v", err)
				} else {
					log.Printf("Closing device because outer packetStream closed: %v", err)
				}
				go s.Close()
			}
			s.putMessageBuffer(elem.buffer)
			s.putOutboundElement(elem)
			return
		}

		if size == 0 || size > maxContentSize {
			continue
		}

		elem.packet = elem.buffer[offset : offset+size]

		peer := s.peer
		if peer == nil {
			continue
		}
		if peer.isRunning.Load() {
			peer.stagePacket(elem)
			elem = nil
			peer.sendStagedPackets()
		}
	}
}

func (peer *peer) stagePacket(elem *queueOutboundElement) {
	for {
		select {
		case peer.queue.staged <- elem:
			return
		default:
		}
		select {
		case tooOld := <-peer.queue.staged:
			peer.device.putMessageBuffer(tooOld.buffer)
			peer.device.putOutboundElement(tooOld)
		default:
		}
	}
}

func (peer *peer) sendStagedPackets() {
top:
	if len(peer.queue.staged) == 0 || !peer.device.isUp() {
		return
	}

	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= rejectAfterMessages || time.Since(keypair.created) >= rejectAfterTime {
		peer.sendHandshakeInitiation(false)
		return
	}

	for {
		select {
		case elem := <-peer.queue.staged:
			elem.peer = peer
			elem.nonce = keypair.sendNonce.Add(1) - 1
			if elem.nonce >= rejectAfterMessages {
				keypair.sendNonce.Store(rejectAfterMessages)
				peer.stagePacket(elem) // XXX: Out of order, but we can't front-load go chans
				goto top
			}

			elem.keypair = keypair
			elem.Lock()

			// add to parallel and sequential queue
			if peer.isRunning.Load() {
				peer.queue.outbound.c <- elem
				peer.device.queue.encryption.c <- elem
			} else {
				peer.device.putMessageBuffer(elem.buffer)
				peer.device.putOutboundElement(elem)
			}
		default:
			return
		}
	}
}

func (peer *peer) flushStagedPackets() {
	for {
		select {
		case elem := <-peer.queue.staged:
			peer.device.putMessageBuffer(elem.buffer)
			peer.device.putOutboundElement(elem)
		default:
			return
		}
	}
}

func calculatePaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + paddingMultiple - 1) & ^(paddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := (lastUnit + paddingMultiple - 1) & ^(paddingMultiple - 1)
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (s *StreamGuard) routineEncryption(id int) {
	var paddingZeros [paddingMultiple]byte
	var nonce [chacha20poly1305.NonceSize]byte

	defer log.Printf("Routine: encryption worker %d - stopped", id)
	log.Printf("Routine: encryption worker %d - started", id)

	for elem := range s.queue.encryption.c {
		// populate header fields
		header := elem.buffer[:messageTransportHeaderSize]

		fieldType := header[0:4]
		fieldReceiver := header[4:8]
		fieldNonce := header[8:16]

		binary.LittleEndian.PutUint32(fieldType, messageTransportType)
		binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
		binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

		// pad content to multiple of 16
		paddingSize := calculatePaddingSize(len(elem.packet), defaultMTU)
		elem.packet = append(elem.packet, paddingZeros[:paddingSize]...)

		// encrypt content and release to consumer

		binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
		elem.packet = elem.keypair.send.Seal(
			header,
			nonce[:],
			elem.packet,
			nil,
		)
		elem.Unlock()
	}
}

/* Sequentially reads packets from queue and sends to endpoint
 *
 * Obs. Single instance per peer.
 * The routine terminates then the outbound queue is closed.
 */
func (peer *peer) routineSequentialSender() {
	device := peer.device
	defer func() {
		defer log.Printf("%v - Routine: sequential sender - stopped", peer)
		peer.stopping.Done()
		go device.Close()
	}()
	log.Printf("%v - Routine: sequential sender - started", peer)

	for elem := range peer.queue.outbound.c {
		if elem == nil {
			return
		}
		elem.Lock()
		if !peer.isRunning.Load() {
			// peer has been stopped; return re-usable elems to the shared pool.
			// This is an optimization only. It is possible for the peer to be stopped
			// immediately after this check, in which case, elem will get processed.
			// The timers and sendBuffer code are resilient to a few stragglers.
			// TODO: rework peer shutdown order to ensure
			// that we never accidentally keep timers alive longer than necessary.
			device.putMessageBuffer(elem.buffer)
			device.putOutboundElement(elem)
			continue
		}

		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()

		// send message and return buffer to pool

		err := peer.sendBuffer(elem.packet)
		if len(elem.packet) != messageKeepaliveSize {
			peer.timersDataSent()
		}
		device.putMessageBuffer(elem.buffer)
		device.putOutboundElement(elem)
		if err != nil {
			log.Printf("%v - Failed to send data packet: %v", peer, err)
			continue
		}

		peer.keepKeyFreshSending()
	}
}
