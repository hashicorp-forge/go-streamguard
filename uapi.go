/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2023 HashiCorp Inc.
 */

package lite

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"

	"golang.zx2c4.com/wireguard/ipc"
)

type ipcError struct {
	code int64 // error code
	err  error // underlying/wrapped error
}

func (s ipcError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

func (s ipcError) Unwrap() error {
	return s.err
}

func (s ipcError) ErrorCode() int64 {
	return s.code
}

func ipcErrorf(code int64, msg string, args ...any) *ipcError {
	return &ipcError{code: code, err: fmt.Errorf(msg, args...)}
}

// uapiCfg returns a string that contains cfg formatted use with ipcSet.
// cfg is a series of alternating key/value strings.
// uapiCfg exists because editors and humans like to insert
// whitespace into configs, which can cause failures, some of which are silent.
// For example, a leading blank newline causes the remainder
// of the config to be silently ignored.
func uapiCfg(cfg ...string) string {
	if len(cfg)%2 != 0 {
		panic("odd number of args to uapiReader")
	}
	buf := new(bytes.Buffer)
	for i, s := range cfg {
		buf.WriteString(s)
		sep := byte('\n')
		if i%2 == 0 {
			sep = '='
		}
		buf.WriteByte(sep)
	}
	return buf.String()
}

// ipcSetOperation implements the WireGuard configuration protocol "set" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (s *StreamGuard) ipcSetOperation(r io.Reader) (err error) {
	s.ipcMutex.Lock()
	defer s.ipcMutex.Unlock()

	defer func() {
		if err != nil {
			log.Printf("%v", err)
		}
	}()

	peer := new(ipcSetPeer)
	deviceConfig := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			peer.handlePostConfig()
			return nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ipcErrorf(ipc.IpcErrorProtocol, "failed to parse line %q", line)
		}

		if key == "public_key" {
			if deviceConfig {
				deviceConfig = false
			}
			peer.handlePostConfig()
			// Load/create the peer we are now configuring.
			err := s.handlePublicKeyLine(peer, value)
			if err != nil {
				return err
			}
			continue
		}

		var err error
		if deviceConfig {
			err = s.handleDeviceLine(key, value)
		} else {
			err = s.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return err
		}
	}
	peer.handlePostConfig()

	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil
}

func (s *StreamGuard) handleDeviceLine(key, value string) error {
	switch key {
	case "private_key":
		var sk NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
		}
		log.Printf("UAPI: Updating private key")
		s.SetPrivateKey(sk)

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}

	return nil
}

// An ipcSetPeer is the current state of an IPC set operation on a peer.
type ipcSetPeer struct {
	*peer        // peer is the current peer being operated on
	dummy   bool // dummy reports whether this peer is a temporary, placeholder peer
	created bool // new reports whether this is a newly created peer
	pkaOn   bool // pkaOn reports whether the peer had the persistent keepalive turn on
}

func (peer *ipcSetPeer) handlePostConfig() {
	if peer.peer == nil || peer.dummy {
		return
	}
	if peer.device.isUp() {
		peer.start()
		if peer.pkaOn {
			peer.sendKeepalive()
		}
		peer.sendStagedPackets()
	}
}

func (s *StreamGuard) handlePublicKeyLine(setPeer *ipcSetPeer, value string) error {
	// Load/create the setPeer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get setPeer by public key: %w", err)
	}

	// Ignore setPeer with the same public key as this device.
	s.staticIdentity.RLock()
	setPeer.dummy = s.staticIdentity.publicKey.Equals(publicKey)
	s.staticIdentity.RUnlock()

	if setPeer.dummy {
		setPeer.peer = &peer{}
		return nil
	} else {
		setPeer.peer = s.lookupPeer()
	}

	setPeer.created = setPeer.peer == nil
	if setPeer.created {
		setPeer.peer, err = s.newPeer(publicKey)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to create new setPeer: %w", err)
		}
		log.Printf("%v - UAPI: Created", setPeer.peer)
	}
	return nil
}

func (s *StreamGuard) handlePeerLine(setPeer *ipcSetPeer, key, value string) error {
	switch key {
	case "update_only":
		// allow disabling of creation
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set update only, invalid value: %v", value)
		}
		if setPeer.created && !setPeer.dummy {
			s.removePeer()
			setPeer.peer = &peer{}
			setPeer.dummy = true
		}

	case "remove":
		// remove currently selected setPeer from device
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
		}
		if !setPeer.dummy {
			log.Printf("%v - UAPI: Removing", setPeer.peer)
			s.removePeer()
		}
		setPeer.peer = &peer{}
		setPeer.dummy = true

	case "preshared_key":
		log.Printf("%v - UAPI: Updating preshared key", setPeer.peer)

		setPeer.handshake.mutex.Lock()
		err := setPeer.handshake.presharedKey.FromHex(value)
		setPeer.handshake.mutex.Unlock()

		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set preshared key: %w", err)
		}

	case "protocol_version":
		if value != "1" {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid protocol version: %v", value)
		}

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI setPeer key: %v", key)
	}

	return nil
}

func (s *StreamGuard) ipcSet(uapiConf string) error {
	return s.ipcSetOperation(strings.NewReader(uapiConf))
}
