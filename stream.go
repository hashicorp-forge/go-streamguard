/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2023 HashiCorp Inc.
 */

package lite

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
)

type receiveFunc func([]byte) (int, error)

type ioFlusher interface {
	Flush() error
}

type StreamGuard struct {
	innerStream net.Conn // this is only used to help satisfy the net.Conn interface
	publicKey   NoisePublicKey
	peer        *peer

	state struct {
		// state holds the device's state. It is accessed atomically.
		// Use the device.deviceState method to read it.
		// device.deviceState does not acquire the mutex, so it captures only a snapshot.
		// During state transitions, the state variable is updated before the device itself.
		// The state is thus either the current state of the device or
		// the intended future state of the device.
		// For example, while executing a call to up, state will be deviceStateUp.
		// There is no guarantee that that intended future state of the device
		// will become the actual state; up can fail.
		// The device can also change state multiple times between time of check and time of use.
		// Unsynchronized uses of state must therefore be advisory/best-effort only.
		state atomic.Uint32 // actually a deviceState, but typed uint32 for convenience
		// stopping blocks until all inputs to guardDevice have been closed.
		stopping sync.WaitGroup
		// mu protects state changes.
		sync.Mutex
	}

	packetStream *packetStream

	staticIdentity struct {
		sync.RWMutex
		privateKey NoisePrivateKey
		publicKey  NoisePublicKey
	}

	handshakeKeypair *handshakeKeypair

	cookieChecker cookieChecker

	pool struct {
		messageBuffers   *waitPool
		inboundElements  *waitPool
		outboundElements *waitPool
	}

	queue struct {
		encryption *outboundQueue
		decryption *inboundQueue
		handshake  *handshakeQueue
	}

	ipcMutex sync.RWMutex
	closed   chan struct{}
	log      hclog.Logger

	// stagedReadWriter is used to implement io.Reader / io.Writer by staging packets for both
	stagedReadWriter *stagedReadWriter
}

// deviceState represents the state of a guardDevice.
// There are three states: down, up, closed.
// Transitions:
//
//	down -----+
//	  ↑↓      ↓
//	  up -> closed
type deviceState uint32

//go:generate go run golang.org/x/tools/cmd/stringer -type deviceState -trimprefix=deviceState
const (
	deviceStateDown deviceState = iota
	deviceStateUp
	deviceStateClosed
)

// deviceState returns device.state.state as a deviceState
// See those docs for how to interpret this value.
func (s *StreamGuard) deviceState() deviceState {
	return deviceState(s.state.state.Load())
}

// isClosed reports whether the device is closed (or is closing).
// See device.state.state comments for how to interpret this value.
func (s *StreamGuard) isClosed() bool {
	return s.deviceState() == deviceStateClosed
}

// isUp reports whether the device is up (or is attempting to come up).
// See device.state.state comments for how to interpret this value.
func (s *StreamGuard) isUp() bool {
	return s.deviceState() == deviceStateUp
}

// changeState attempts to change the device state to match want.
func (s *StreamGuard) changeState(want deviceState) (err error) {
	s.state.Lock()
	defer s.state.Unlock()
	old := s.deviceState()
	if old == deviceStateClosed {
		// once closed, always closed
		log.Printf("Interface closed, ignored requested state %s", want)
		return nil
	}
	switch want {
	case old:
		return nil
	case deviceStateUp:
		s.state.state.Store(uint32(deviceStateUp))
		err = s.upLocked()
		if err == nil {
			break
		}
		fallthrough // up failed; bring the device all the way back down
	case deviceStateDown:
		s.state.state.Store(uint32(deviceStateDown))
		errDown := s.downLocked()
		if err == nil {
			err = errDown
		}
	}
	log.Printf("Interface state was %s, requested %s, now %s", old, want, s.deviceState())
	return
}

// upLocked attempts to bring the device up and reports whether it succeeded.
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (s *StreamGuard) upLocked() error {
	if err := s.packetStreamUpdate(); err != nil {
		log.Printf("Unable to update packet stream: %v", err)
		return err
	}

	// The IPC set operation waits for peers to be created before calling start() on them,
	// so if there's a concurrent IPC set request happening, we should wait for it to complete.
	s.ipcMutex.Lock()
	defer s.ipcMutex.Unlock()

	if s.peer != nil {
		s.peer.start()
		if s.peer.persistentKeepaliveInterval.Load() > 0 {
			s.peer.sendKeepalive()
		}
	}
	return nil
}

// downLocked attempts to bring the device down.
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (s *StreamGuard) downLocked() error {
	err := s.packetStreamClose()
	if err != nil {
		log.Printf("Packet stream close failed: %v", err)
	}

	if s.peer != nil {
		s.peer.stop()
	}
	return err
}

func (s *StreamGuard) up() error {
	return s.changeState(deviceStateUp)
}

func (s *StreamGuard) down() error {
	return s.changeState(deviceStateDown)
}

func (s *StreamGuard) SetPrivateKey(sk NoisePrivateKey) error {
	// lock required resources

	s.staticIdentity.Lock()
	defer s.staticIdentity.Unlock()

	if sk.Equals(s.staticIdentity.privateKey) {
		return nil
	}

	// update key material
	publicKey := sk.PublicKey()
	s.staticIdentity.privateKey = sk
	s.staticIdentity.publicKey = publicKey
	s.cookieChecker.init(publicKey)

	peer := s.peer
	if peer != nil {
		peer.handshake.mutex.RLock()
		defer peer.handshake.mutex.RUnlock()
		// do static-static DH pre-computations
		handshake := &peer.handshake
		handshake.precomputedStaticStatic = s.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic)
	}

	return nil
}

func newDevice(innerStream net.Conn, publicKey NoisePublicKey, packetStream *packetStream, logger hclog.Logger) *StreamGuard {
	device := new(StreamGuard)
	device.innerStream = innerStream
	device.publicKey = publicKey
	device.state.state.Store(uint32(deviceStateDown))
	device.closed = make(chan struct{})
	device.log = logger
	device.packetStream = packetStream
	device.populatePools()
	device.stagedReadWriter = newStagedReadWriter()

	// create queues

	device.queue.handshake = newHandshakeQueue()
	device.queue.encryption = newOutboundQueue()
	device.queue.decryption = newInboundQueue()

	// start workers

	cpus := runtime.NumCPU()
	device.state.stopping.Wait()
	device.queue.encryption.wg.Add(cpus) // One for each routineHandshake
	for i := 0; i < cpus; i++ {
		go device.routineEncryption(i + 1)
		go device.routineDecryption(i + 1)
		go device.routineHandshake(i + 1)
	}

	device.state.stopping.Add(1)      // routineReadFromStagedReadWriter
	device.queue.encryption.wg.Add(1) // routineReadFromStagedReadWriter
	go device.routineReadFromStagedReadWriter()

	return device
}

func (s *StreamGuard) lookupPeer() *peer {
	return s.peer
}

func (s *StreamGuard) removePeer() {
	s.peer = nil
}

func (s *StreamGuard) Close() error {
	s.state.Lock()
	defer s.state.Unlock()
	if s.isClosed() {
		return nil
	}
	s.state.state.Store(uint32(deviceStateClosed))
	s.innerStream.Close()
	s.stagedReadWriter.Close()

	s.downLocked()

	// Remove peers before closing queues,
	// because peers assume that queues are active.
	s.removePeer()

	// We kept a reference to the encryption and decryption queues,
	// in case we started any new peers that might write to them.
	// No new peers are coming; we are done with these queues.
	s.queue.encryption.wg.Done()
	s.queue.decryption.wg.Done()
	s.queue.handshake.wg.Done()

	s.state.stopping.Wait()

	close(s.closed)
	return nil
}

func (s *StreamGuard) packetStreamUpdate() error {
	if !s.isUp() {
		return nil
	}
	recvFns := []receiveFunc{s.packetStream.Receive}
	// start receiving routines
	s.packetStream.stopping.Add(len(recvFns))
	s.queue.decryption.wg.Add(len(recvFns)) // each routineReceiveIncoming goroutine writes to device.queue.decryption
	s.queue.handshake.wg.Add(len(recvFns))  // each routineReceiveIncoming goroutine writes to device.queue.handshake
	for _, fn := range recvFns {
		go s.routineReceiveIncoming(fn)
	}
	return nil
}

func (s *StreamGuard) packetStreamClose() error {
	err := s.packetStream.Close()
	s.packetStream.stopping.Wait()
	return err
}

func genConfig() (cfg string, publicKey NoisePublicKey, err error) {
	var privateKey NoisePrivateKey
	_, err = rand.Read(privateKey[:])
	if err != nil {
		return
	}
	return genConfigWithKey(privateKey), privateKey.PublicKey(), nil
}

func genConfigWithKey(privateKey NoisePrivateKey) string {
	pubKey := privateKey.PublicKey()
	return uapiCfg(
		"private_key", hex.EncodeToString(privateKey[:]),
		"public_key", hex.EncodeToString(pubKey[:]),
		"protocol_version", "1",
	)
}

func (s *StreamGuard) LocalAddr() net.Addr {
	return s.innerStream.LocalAddr()
}

func (s *StreamGuard) RemoteAddr() net.Addr {
	return s.innerStream.RemoteAddr()
}

func (s *StreamGuard) SetDeadline(t time.Time) error {
	return s.innerStream.SetDeadline(t)
}

func (s *StreamGuard) SetReadDeadline(t time.Time) error {
	return s.innerStream.SetReadDeadline(t)
}

func (s *StreamGuard) SetWriteDeadline(t time.Time) error {
	return s.innerStream.SetWriteDeadline(t)
}

var _ net.Conn = (*StreamGuard)(nil)

func (s *StreamGuard) PublicKey() *NoisePublicKey {
	return &s.publicKey
}

func (s *StreamGuard) SetPeer(publicKey NoisePublicKey) error {
	err := s.ipcSet(uapiCfg(
		"public_key", hex.EncodeToString(publicKey[:])))
	if err != nil {
		return err
	}
	s.peer = s.lookupPeer()
	if s.peer == nil {
		return fmt.Errorf("could not find peer for %s", hex.EncodeToString(publicKey[:]))
	}
	return nil
}

func (s *StreamGuard) Read(p []byte) (int, error) {
	n, err := s.stagedReadWriter.Read(p)
	return n, err
}

func (s *StreamGuard) Write(p []byte) (int, error) {
	newP := make([]byte, len(p)+2, len(p)+2)
	copy(newP[2:], p)
	binary.LittleEndian.PutUint16(newP, uint16(len(p)))
	n, err := s.stagedReadWriter.Write(newP)
	return n - 2, err
}

var _ io.ReadWriteCloser = (*StreamGuard)(nil)

type packetStream struct {
	receiveLock   sync.Mutex
	sendLock      sync.Mutex
	innerStream   io.ReadWriteCloser
	readLeftovers []byte
	stopping      sync.WaitGroup
}

func (s *packetStream) Receive(b []byte) (int, error) {
	s.receiveLock.Lock()
	defer s.receiveLock.Unlock()

	// check if we have leftovers to read
	if len(s.readLeftovers) > 0 {
		buff := bytes.NewBuffer(s.readLeftovers)
		n, err := buff.Read(b)
		s.readLeftovers = s.readLeftovers[n:]
		return n, err
	}

	length := []byte{0, 0, 0, 0}
	n, err := io.ReadFull(s.innerStream, length)
	if err != nil {
		return 0, err
	}
	fullLength := int(binary.LittleEndian.Uint32(length))
	n, err = io.ReadFull(s.innerStream, b[:fullLength])
	if n < fullLength {
		s.readLeftovers = make([]byte, fullLength-n, fullLength-n)
		_, err = io.ReadFull(s.innerStream, s.readLeftovers)
	} else {
		s.readLeftovers = s.readLeftovers[:0]
	}
	return n, err
}

func (s *packetStream) Close() error {
	return s.innerStream.Close()
}

func (s *packetStream) Send(b []byte) error {
	s.sendLock.Lock()
	defer s.sendLock.Unlock()

	// wrap with length
	buff := make([]byte, len(b)+4, len(b)+4)
	//length := []byte{0, 0, 0, 0}
	binary.LittleEndian.PutUint32(buff, uint32(len(b)))
	copy(buff[4:], b)
	_, err := s.innerStream.Write(buff)
	if err != nil {
		return err
	}
	//_, err = s.innerStream.Write(b)
	//if err != nil {
	//	return err
	//}
	if flusher, ok := s.innerStream.(ioFlusher); ok {
		err = flusher.Flush()
	}
	return err
}

func WrapStream(stream net.Conn) (*StreamGuard, error) {
	cfg, publicKey, err := genConfig()
	if err != nil {
		return nil, err
	}

	packetStream := &packetStream{
		innerStream: stream,
	}

	guard := newDevice(stream, publicKey, packetStream, hclog.New(&hclog.LoggerOptions{
		Name:  "streamguard",
		Level: hclog.LevelFromString("DEBUG"),
	}))
	err = guard.ipcSet(cfg)
	if err != nil {
		return nil, err
	}
	err = guard.up()
	if err != nil {
		return nil, err
	}
	return guard, nil
}

func WrapStreamWithKey(stream net.Conn, privateKey NoisePrivateKey) (*StreamGuard, error) {
	cfg := genConfigWithKey(privateKey)
	publicKey := privateKey.PublicKey()
	packetStream := &packetStream{innerStream: stream}
	dev := newDevice(stream, publicKey, packetStream, hclog.New(&hclog.LoggerOptions{
		Name:  "streamguard",
		Level: hclog.LevelFromString("DEBUG"),
	}))
	err := dev.ipcSet(cfg)
	if err != nil {
		return nil, err
	}
	err = dev.up()
	if err != nil {
		return nil, err
	}
	return dev, nil
}

func WrapStreamWithKeyAndPeer(stream net.Conn, privateKey NoisePrivateKey, peer NoisePublicKey) (*StreamGuard, error) {
	cfg := genConfigWithKey(privateKey)
	publicKey := privateKey.PublicKey()
	packetStream := &packetStream{innerStream: stream}
	dev := newDevice(stream, publicKey, packetStream, hclog.New(&hclog.LoggerOptions{
		Name:  "streamguard",
		Level: hclog.LevelFromString("DEBUG"),
	}))
	err := dev.ipcSet(cfg)
	if err != nil {
		return nil, err
	}
	_, err = dev.newPeer(peer)
	if err != nil {
		return nil, err
	}
	return dev, dev.up()
}

type StreamGuardListener struct {
	inner         net.Listener
	peerPublicKey NoisePublicKey
	privateKey    NoisePrivateKey
}

func (s *StreamGuardListener) PublicKey() *NoisePublicKey {
	pk := s.privateKey.PublicKey()
	pkPtr := (*[NoisePublicKeySize]byte)(&pk)
	return (*NoisePublicKey)(pkPtr)
}

func (s *StreamGuardListener) Accept() (net.Conn, error) {
	log.Printf("StreamGuard listener waiting on connection")
	connection, err := s.inner.Accept()
	if err != nil {
		return nil, err
	}
	log.Printf("Got new connection to %v", connection.RemoteAddr())
	var c *StreamGuard
	if s.peerPublicKey.IsZero() {
		c, err = WrapStreamWithKey(connection, s.privateKey)
	} else {
		c, err = WrapStreamWithKeyAndPeer(connection, s.privateKey, s.peerPublicKey)
	}
	if err != nil {
		return nil, err
	}
	err = c.up()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *StreamGuardListener) Close() error {
	return s.inner.Close()
}

func (s *StreamGuardListener) Addr() net.Addr {
	return s.inner.Addr()
}

func (s *StreamGuardListener) SetPeer(publicKey NoisePublicKey) {
	s.peerPublicKey = publicKey
}

var _ net.Listener = (*StreamGuardListener)(nil)

func WrapListener(listener net.Listener) (*StreamGuardListener, error) {
	privateKey, err := NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return &StreamGuardListener{
		inner:      listener,
		privateKey: privateKey,
	}, nil
}
