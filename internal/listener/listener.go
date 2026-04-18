package listener

import (
	"errors"
	"net"
	"sync"
)

type QueueListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func NewQueueListener(addr net.Addr, size int) *QueueListener {
	if size <= 0 {
		size = 128
	}
	return &QueueListener{
		addr:   addr,
		conns:  make(chan net.Conn, size),
		closed: make(chan struct{}),
	}
}

func (l *QueueListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.conns:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *QueueListener) Inject(conn net.Conn) error {
	select {
	case <-l.closed:
		if conn != nil {
			_ = conn.Close()
		}
		return net.ErrClosed
	default:
	}

	select {
	case l.conns <- conn:
		return nil
	case <-l.closed:
		if conn != nil {
			_ = conn.Close()
		}
		return net.ErrClosed
	}
}

func (l *QueueListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		close(l.conns)
	})
	return nil
}

func (l *QueueListener) Addr() net.Addr {
	return l.addr
}

type connWithAddrs struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func WrapConn(conn net.Conn, localAddr, remoteAddr net.Addr) net.Conn {
	return &connWithAddrs{
		Conn:       conn,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

func (c *connWithAddrs) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return c.Conn.LocalAddr()
}

func (c *connWithAddrs) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.Conn.RemoteAddr()
}

var ErrListenerClosed = errors.New("listener closed")
