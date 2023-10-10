/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2023 HashiCorp Inc.
 */

package streamguard

import (
	"net/netip"
	"time"
)

/* Specification constants */

const (
	rekeyAfterMessages      = (1 << 60)
	rejectAfterMessages     = (1 << 64) - (1 << 13) - 1
	rekeyAfterTime          = time.Second * 120
	rekeyTimeout            = time.Second * 5
	maxTimerHandshakes      = 90 / 5 /* RekeyAttemptTime / rekeyTimeout */
	rekeyTimeoutJitterMaxMs = 334
	rejectAfterTime         = time.Second * 180
	keepaliveTimeout        = time.Second * 10
	cookieRefreshTime       = time.Second * 120
	handshakeInitationRate  = time.Second / 50
	paddingMultiple         = 16
	defaultMTU              = 1420
)

const (
	minMessageSize = messageKeepaliveSize                  // minimum size of transport message (keepalive)
	maxMessageSize = maxSegmentSize                        // maximum size of transport message
	maxContentSize = maxSegmentSize - messageTransportSize // maximum size of transport message content
)

var fixedIp = netip.AddrFrom4([4]byte{10, 0, 0, 1}) // used for the rate limiter. We can only have one peer.
