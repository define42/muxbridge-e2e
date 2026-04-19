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

	mu            sync.Mutex
	activeInjects int
	injectCond    *sync.Cond
}

func NewQueueListener(addr net.Addr, size int) *QueueListener {
	if size <= 0 {
		size = 128
	}
	l := &QueueListener{
		addr:   addr,
		conns:  make(chan net.Conn, size),
		closed: make(chan struct{}),
	}
	l.injectCond = sync.NewCond(&l.mu)
	return l
}

func (l *QueueListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		select {
		case <-l.closed:
			if conn != nil {
				_ = conn.Close()
			}
			return nil, net.ErrClosed
		default:
		}
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *QueueListener) Inject(conn net.Conn) error {
	l.mu.Lock()
	l.activeInjects++
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.activeInjects--
		if l.activeInjects == 0 {
			l.injectCond.Broadcast()
		}
		l.mu.Unlock()
	}()

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
		select {
		case <-l.closed:
			if conn != nil {
				_ = conn.Close()
			}
			return net.ErrClosed
		default:
		}
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

		l.mu.Lock()
		for l.activeInjects > 0 {
			l.injectCond.Wait()
		}
		l.mu.Unlock()

		for {
			select {
			case conn := <-l.conns:
				if conn != nil {
					_ = conn.Close()
				}
			default:
				return
			}
		}
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
