package reuse

import (
	"net"
	"sync/atomic"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type Conn struct {
	net.Conn
	watch *watch
}

type watch struct {
	done chan struct{}
	data [1]byte
	n    int
	err  error
}

func (c *Conn) Ready(state *atomic.Uint32, from State) bool {
	if from != StateActive && !state.CompareAndSwap(uint32(from), uint32(StateActive)) {
		return false
	}
	idle := &watch{done: make(chan struct{})}
	c.watch = idle
	if !state.CompareAndSwap(uint32(StateActive), uint32(StateReady)) {
		c.watch = nil
		return false
	}
	go func() {
		idle.n, idle.err = c.Conn.Read(idle.data[:])
		close(idle.done)
		if state.CompareAndSwap(uint32(StateReady), uint32(StateClosed)) {
			c.Conn.Close()
		}
	}()
	return true
}

func (c *Conn) Read(p []byte) (int, error) {
	idle := c.watch
	if idle == nil {
		return c.Conn.Read(p)
	}
	c.watch = nil
	<-idle.done
	if idle.n == 0 && E.IsTimeout(idle.err) {
		return c.Conn.Read(p)
	}
	return copy(p, idle.data[:idle.n]), idle.err
}

func (c *Conn) Upstream() any {
	return c.Conn
}

func (c *Conn) WriterReplaceable() bool {
	return true
}

var (
	_ common.WithUpstream  = (*Conn)(nil)
	_ N.WriterWithUpstream = (*Conn)(nil)
)
