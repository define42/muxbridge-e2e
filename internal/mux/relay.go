package mux

import (
	"io"
	"net"
	"sync"
)

type RelayResult struct {
	ClientToUpstream int64
	UpstreamToClient int64
}

type closeWriter interface {
	CloseWrite() error
}

func Relay(a, b net.Conn) RelayResult {
	var result RelayResult
	var closeOnce sync.Once
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		result.ClientToUpstream, _ = copyAndClose(b, a)
		closeOnce.Do(closeBoth)
	}()

	go func() {
		defer wg.Done()
		result.UpstreamToClient, _ = copyAndClose(a, b)
		closeOnce.Do(closeBoth)
	}()

	wg.Wait()
	closeOnce.Do(closeBoth)
	return result
}

func copyAndClose(dst, src net.Conn) (int64, error) {
	n, err := io.Copy(dst, src)
	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	if err == io.EOF {
		err = nil
	}
	return n, err
}
