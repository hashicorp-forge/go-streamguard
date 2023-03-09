/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2023 HashiCorp Inc.
 */

package lite

import (
	"crypto/cipher"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/replay"
)

/* Due to limitations in Go and /x/crypto there is currently
 * no way to ensure that key material is securely ereased in memory.
 *
 * Since this may harm the forward secrecy property,
 * we plan to resolve this issue; whenever Go allows us to do so.
 */

type keypair struct {
	sendNonce    atomic.Uint64
	send         cipher.AEAD
	receive      cipher.AEAD
	replayFilter replay.Filter
	isInitiator  bool
	created      time.Time
	localIndex   uint32
	remoteIndex  uint32
}

type keypairs struct {
	sync.RWMutex
	current  *keypair
	previous *keypair
	next     atomic.Pointer[keypair]
}

func (kp *keypairs) Current() *keypair {
	kp.RLock()
	defer kp.RUnlock()
	return kp.current
}
