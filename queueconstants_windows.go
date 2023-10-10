/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2023 HashiCorp Inc.
 */

package streamguard

const (
	queueStagedSize            = 128
	queueOutboundSize          = 1024
	queueInboundSize           = 1024
	queueHandshakeSize         = 1024
	maxSegmentSize             = 2048 - 32 // largest possible UDP datagram
	preallocatedBuffersPerPool = 0         // Disable and allow for infinite memory growth
)
