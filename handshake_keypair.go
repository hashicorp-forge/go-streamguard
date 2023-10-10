/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2023 HashiCorp Inc.
 */

package streamguard

type handshakeKeypair struct {
	handshake *handshake
	keypair   *keypair
}

func (s *StreamGuard) swapKeypair(keypair *keypair) {
	if s.handshakeKeypair == nil {
		return
	}
	s.handshakeKeypair.keypair = keypair
	s.handshakeKeypair.handshake = nil
}

func (s *StreamGuard) newHandshake(handshake *handshake) {
	s.handshakeKeypair = &handshakeKeypair{
		handshake: handshake,
		keypair:   nil,
	}
}
