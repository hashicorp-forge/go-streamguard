/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2023 HashiCorp Inc.
 */

package streamguard

import (
	"container/list"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

type peer struct {
	isRunning         atomic.Bool
	sync.RWMutex      // Is generally taken whenever we modify peer
	keypairs          keypairs
	handshake         handshake
	device            *StreamGuard
	stopping          sync.WaitGroup // routines pending stop
	txBytes           atomic.Uint64  // bytes send to peer (endpoint)
	rxBytes           atomic.Uint64  // bytes received from peer
	lastHandshakeNano atomic.Int64   // nano seconds since epoch

	disableRoaming bool

	timers struct {
		retransmitHandshake     *wgTimer
		sendKeepalive           *wgTimer
		newHandshake            *wgTimer
		zeroKeyMaterial         *wgTimer
		persistentKeepalive     *wgTimer
		handshakeAttempts       atomic.Uint32
		needAnotherKeepalive    atomic.Bool
		sentLastMinuteHandshake atomic.Bool
	}

	state struct {
		sync.Mutex // protects against concurrent start/stop
	}

	queue struct {
		staged   chan *queueOutboundElement // staged packets before a handshake is available
		outbound *autodrainingOutboundQueue // sequential ordering of udp transmission
		inbound  *autodrainingInboundQueue  // sequential ordering of tun writing
	}

	cookieGenerator             cookieGenerator
	trieEntries                 list.List
	persistentKeepaliveInterval atomic.Uint32
}

func (s *StreamGuard) newPeer(pk NoisePublicKey) (*peer, error) {
	if s.isClosed() {
		return nil, errors.New("device closed")
	}

	// lock resources
	s.staticIdentity.RLock()
	defer s.staticIdentity.RUnlock()

	// create peer
	peer := new(peer)
	peer.Lock()
	defer peer.Unlock()

	peer.cookieGenerator.init(pk)
	peer.device = s
	peer.queue.outbound = newAutodrainingOutboundQueue(s)
	peer.queue.inbound = newAutodrainingInboundQueue(s)
	peer.queue.staged = make(chan *queueOutboundElement, queueStagedSize)

	// pre-compute DH
	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.precomputedStaticStatic = s.staticIdentity.privateKey.sharedSecret(pk)
	handshake.remoteStatic = pk
	handshake.mutex.Unlock()

	// init timers
	peer.timersInit()

	// add
	s.peer = peer
	return peer, nil
}

func (peer *peer) sendBuffer(buffer []byte) error {
	if peer.device.isClosed() {
		return nil
	}

	err := peer.device.packetStream.Send(buffer)
	if err == nil {
		peer.txBytes.Add(uint64(len(buffer)))
	}
	return err
}

func (peer *peer) String() string {
	// The awful goo that follows is identical to:
	//
	//   base64Key := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	//   abbreviatedKey := base64Key[0:4] + "…" + base64Key[39:43]
	//   return fmt.Sprintf("peer(%s)", abbreviatedKey)
	//
	// except that it is considerably more efficient.
	src := peer.handshake.remoteStatic
	b64 := func(input byte) byte {
		return input + 'A' + byte(((25-int(input))>>8)&6) - byte(((51-int(input))>>8)&75) - byte(((61-int(input))>>8)&15) + byte(((62-int(input))>>8)&3)
	}
	b := []byte("peer(____…____)")
	const first = len("peer(")
	const second = len("peer(____…")
	b[first+0] = b64((src[0] >> 2) & 63)
	b[first+1] = b64(((src[0] << 4) | (src[1] >> 4)) & 63)
	b[first+2] = b64(((src[1] << 2) | (src[2] >> 6)) & 63)
	b[first+3] = b64(src[2] & 63)
	b[second+0] = b64(src[29] & 63)
	b[second+1] = b64((src[30] >> 2) & 63)
	b[second+2] = b64(((src[30] << 4) | (src[31] >> 4)) & 63)
	b[second+3] = b64((src[31] << 2) & 63)
	return string(b)
}

func (peer *peer) start() {
	// should never start a peer on a closed device
	if peer.device.isClosed() {
		return
	}

	// prevent simultaneous start/stop operations
	peer.state.Lock()
	defer peer.state.Unlock()

	if peer.isRunning.Load() {
		return
	}

	device := peer.device
	log.Printf("%v - Starting", peer)

	// reset routine state
	peer.stopping.Wait()
	peer.stopping.Add(2)

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(rekeyTimeout + time.Second))
	peer.handshake.mutex.Unlock()

	peer.device.queue.encryption.wg.Add(1) // keep encryption queue open for our writes

	peer.timersStart()

	device.flushInboundQueue(peer.queue.inbound)
	device.flushOutboundQueue(peer.queue.outbound)
	go peer.routineSequentialSender()
	go peer.routineSequentialReceiver()

	peer.isRunning.Store(true)
}

func (peer *peer) zeroAndFlushAll() {
	// clear key pairs
	keypairs := &peer.keypairs
	keypairs.Lock()
	keypairs.previous = nil
	keypairs.current = nil
	keypairs.next.Store(nil)
	keypairs.Unlock()

	// clear handshake state

	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.Clear()
	handshake.mutex.Unlock()

	peer.flushStagedPackets()
}

func (peer *peer) stop() {
	peer.state.Lock()
	defer peer.state.Unlock()

	if !peer.isRunning.Swap(false) {
		return
	}

	log.Printf("%v - Stopping", peer)

	peer.timersStop()
	// Signal that routineSequentialSender and routineSequentialReceiver should exit.
	peer.queue.inbound.c <- nil
	peer.queue.outbound.c <- nil
	peer.stopping.Wait()
	peer.device.queue.encryption.wg.Done() // no more writes to encryption queue from us

	peer.zeroAndFlushAll()
}
