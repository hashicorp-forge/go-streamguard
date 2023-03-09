/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2023 HashiCorp Inc.
 */

package lite

import (
	"sync"
	"sync/atomic"
)

type waitPool struct {
	pool  sync.Pool
	cond  sync.Cond
	lock  sync.Mutex
	count atomic.Uint32
	max   uint32
}

func newWaitPool(max uint32, new func() any) *waitPool {
	p := &waitPool{pool: sync.Pool{New: new}, max: max}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

func (p *waitPool) get() any {
	if p.max != 0 {
		p.lock.Lock()
		for p.count.Load() >= p.max {
			p.cond.Wait()
		}
		p.count.Add(1)
		p.lock.Unlock()
	}
	return p.pool.Get()
}

func (p *waitPool) put(x any) {
	p.pool.Put(x)
	if p.max == 0 {
		return
	}
	p.count.Add(^uint32(0))
	p.cond.Signal()
}

func (s *StreamGuard) populatePools() {
	s.pool.messageBuffers = newWaitPool(preallocatedBuffersPerPool, func() any {
		return new([maxMessageSize]byte)
	})
	s.pool.inboundElements = newWaitPool(preallocatedBuffersPerPool, func() any {
		return new(queueInboundElement)
	})
	s.pool.outboundElements = newWaitPool(preallocatedBuffersPerPool, func() any {
		return new(queueOutboundElement)
	})
}

func (s *StreamGuard) getMessageBuffer() *[maxMessageSize]byte {
	return s.pool.messageBuffers.get().(*[maxMessageSize]byte)
}

func (s *StreamGuard) putMessageBuffer(msg *[maxMessageSize]byte) {
	s.pool.messageBuffers.put(msg)
}

func (s *StreamGuard) getInboundElement() *queueInboundElement {
	return s.pool.inboundElements.get().(*queueInboundElement)
}

func (s *StreamGuard) putInboundElement(elem *queueInboundElement) {
	elem.clearPointers()
	s.pool.inboundElements.put(elem)
}

func (s *StreamGuard) getOutboundElement() *queueOutboundElement {
	return s.pool.outboundElements.get().(*queueOutboundElement)
}

func (s *StreamGuard) putOutboundElement(elem *queueOutboundElement) {
	elem.clearPointers()
	s.pool.outboundElements.put(elem)
}
