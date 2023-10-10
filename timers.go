/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2023 HashiCorp Inc.
 *
 * This is based heavily on timers.c from the kernel implementation.
 */

package streamguard

import (
	"log"
	"sync"
	"time"
	_ "unsafe"
)

//go:linkname fastrandn runtime.fastrandn
func fastrandn(n uint32) uint32

// A wgTimer manages time-based aspects of the WireGuard protocol.
// wgTimer roughly copies the interface of the Linux kernel's struct timer_list.
type wgTimer struct {
	*time.Timer
	modifyingLock sync.RWMutex
	runningLock   sync.Mutex
	isPending     bool
}

func (peer *peer) NewTimer(expirationFunction func(*peer)) *wgTimer {
	timer := &wgTimer{}
	timer.Timer = time.AfterFunc(time.Hour, func() {
		timer.runningLock.Lock()
		defer timer.runningLock.Unlock()

		timer.modifyingLock.Lock()
		if !timer.isPending {
			timer.modifyingLock.Unlock()
			return
		}
		timer.isPending = false
		timer.modifyingLock.Unlock()

		expirationFunction(peer)
	})
	timer.Stop()
	return timer
}

func (timer *wgTimer) Mod(d time.Duration) {
	timer.modifyingLock.Lock()
	timer.isPending = true
	timer.Reset(d)
	timer.modifyingLock.Unlock()
}

func (timer *wgTimer) Del() {
	timer.modifyingLock.Lock()
	timer.isPending = false
	timer.Stop()
	timer.modifyingLock.Unlock()
}

func (timer *wgTimer) DelSync() {
	timer.Del()
	timer.runningLock.Lock()
	timer.Del()
	timer.runningLock.Unlock()
}

func (timer *wgTimer) IsPending() bool {
	timer.modifyingLock.RLock()
	defer timer.modifyingLock.RUnlock()
	return timer.isPending
}

func (peer *peer) timersActive() bool {
	return peer.isRunning.Load() && peer.device != nil && peer.device.isUp()
}

func expiredRetransmitHandshake(peer *peer) {
	if peer.timers.handshakeAttempts.Load() > maxTimerHandshakes {
		log.Printf("%s - handshake did not complete after %d attempts, giving up", peer, maxTimerHandshakes+2)

		if peer.timersActive() {
			peer.timers.sendKeepalive.Del()
		}

		/* We drop all packets without a keypair and don't try again,
		 * if we try unsuccessfully for too long to make a handshake.
		 */
		peer.flushStagedPackets()

		/* We set a timer for destroying any residue that might be left
		 * of a partial exchange.
		 */
		if peer.timersActive() && !peer.timers.zeroKeyMaterial.IsPending() {
			peer.timers.zeroKeyMaterial.Mod(rejectAfterTime * 3)
		}
	} else {
		peer.timers.handshakeAttempts.Add(1)
		log.Printf("%s - handshake did not complete after %d seconds, retrying (try %d)", peer, int(rekeyTimeout.Seconds()), peer.timers.handshakeAttempts.Load()+1)
		peer.sendHandshakeInitiation(true)
	}
}

func expiredSendKeepalive(peer *peer) {
	peer.sendKeepalive()
	if peer.timers.needAnotherKeepalive.Load() {
		peer.timers.needAnotherKeepalive.Store(false)
		if peer.timersActive() {
			peer.timers.sendKeepalive.Mod(keepaliveTimeout)
		}
	}
}

func expiredNewHandshake(peer *peer) {
	log.Printf("%s - Retrying handshake because we stopped hearing back after %d seconds", peer, int((keepaliveTimeout + rekeyTimeout).Seconds()))
	peer.sendHandshakeInitiation(false)
}

func expiredZeroKeyMaterial(peer *peer) {
	log.Printf("%s - Removing all keys, since we haven't received a new one in %d seconds", peer, int((rejectAfterTime * 3).Seconds()))
	peer.zeroAndFlushAll()
}

func expiredPersistentKeepalive(peer *peer) {
	if peer.persistentKeepaliveInterval.Load() > 0 {
		peer.sendKeepalive()
	}
}

/* Should be called after an authenticated data packet is sent. */
func (peer *peer) timersDataSent() {
	if peer.timersActive() && !peer.timers.newHandshake.IsPending() {
		peer.timers.newHandshake.Mod(keepaliveTimeout + rekeyTimeout + time.Millisecond*time.Duration(fastrandn(rekeyTimeoutJitterMaxMs)))
	}
}

/* Should be called after an authenticated data packet is received. */
func (peer *peer) timersDataReceived() {
	if peer.timersActive() {
		if !peer.timers.sendKeepalive.IsPending() {
			peer.timers.sendKeepalive.Mod(keepaliveTimeout)
		} else {
			peer.timers.needAnotherKeepalive.Store(true)
		}
	}
}

/* Should be called after any type of authenticated packet is sent -- keepalive, data, or handshake. */
func (peer *peer) timersAnyAuthenticatedPacketSent() {
	if peer.timersActive() {
		peer.timers.sendKeepalive.Del()
	}
}

/* Should be called after any type of authenticated packet is received -- keepalive, data, or handshake. */
func (peer *peer) timersAnyAuthenticatedPacketReceived() {
	if peer.timersActive() {
		peer.timers.newHandshake.Del()
	}
}

/* Should be called after a handshake initiation message is sent. */
func (peer *peer) timersHandshakeInitiated() {
	if peer.timersActive() {
		peer.timers.retransmitHandshake.Mod(rekeyTimeout + time.Millisecond*time.Duration(fastrandn(rekeyTimeoutJitterMaxMs)))
	}
}

/* Should be called after a handshake response message is received and processed or when getting key confirmation via the first data message. */
func (peer *peer) timersHandshakeComplete() {
	if peer.timersActive() {
		peer.timers.retransmitHandshake.Del()
	}
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.lastHandshakeNano.Store(time.Now().UnixNano())
}

/* Should be called after an ephemeral key is created, which is before sending a handshake response or after receiving a handshake response. */
func (peer *peer) timersSessionDerived() {
	if peer.timersActive() {
		peer.timers.zeroKeyMaterial.Mod(rejectAfterTime * 3)
	}
}

/* Should be called before a packet with authentication -- keepalive, data, or handshake -- is sent, or after one is received. */
func (peer *peer) timersAnyAuthenticatedPacketTraversal() {
	keepalive := peer.persistentKeepaliveInterval.Load()
	if keepalive > 0 && peer.timersActive() {
		peer.timers.persistentKeepalive.Mod(time.Duration(keepalive) * time.Second)
	}
}

func (peer *peer) timersInit() {
	peer.timers.retransmitHandshake = peer.NewTimer(expiredRetransmitHandshake)
	peer.timers.sendKeepalive = peer.NewTimer(expiredSendKeepalive)
	peer.timers.newHandshake = peer.NewTimer(expiredNewHandshake)
	peer.timers.zeroKeyMaterial = peer.NewTimer(expiredZeroKeyMaterial)
	peer.timers.persistentKeepalive = peer.NewTimer(expiredPersistentKeepalive)
}

func (peer *peer) timersStart() {
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.timers.needAnotherKeepalive.Store(false)
}

func (peer *peer) timersStop() {
	peer.timers.retransmitHandshake.DelSync()
	peer.timers.sendKeepalive.DelSync()
	peer.timers.newHandshake.DelSync()
	peer.timers.zeroKeyMaterial.DelSync()
	peer.timers.persistentKeepalive.DelSync()
}
