package edge

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/define42/muxbridge-e2e/internal/control"
	controlpb "github.com/define42/muxbridge-e2e/proto"
)

type clientSession struct {
	id            string
	token         string
	hostnames     []string
	mux           *yamux.Session
	controlStream ioCloser
	controlWriter *control.LockedWriter
	registry      *sessionRegistry
	metrics       *Metrics
	activeStreams atomic.Int64
	draining      atomic.Bool
	closed        chan struct{}
	closeOnce     sync.Once
}

type ioCloser interface {
	Close() error
}

func (s *clientSession) Send(env *controlpb.Envelope) error {
	return s.controlWriter.WriteEnvelope(env)
}

func (s *clientSession) OpenStream() (*yamux.Stream, error) {
	stream, err := s.mux.OpenStream()
	if err != nil {
		return nil, err
	}
	s.activeStreams.Add(1)
	return stream, nil
}

func (s *clientSession) FinishStream() {
	if remaining := s.activeStreams.Add(-1); remaining == 0 && s.draining.Load() {
		s.Close()
	}
}

func (s *clientSession) BeginDrain(reason controlpb.DrainReason, message string, grace time.Duration) {
	if s.draining.Swap(true) {
		return
	}
	_ = s.Send(&controlpb.Envelope{
		Message: &controlpb.Envelope_DrainNotice{
			DrainNotice: &controlpb.DrainNotice{
				Reason:  reason,
				Message: message,
			},
		},
	})
	if s.activeStreams.Load() == 0 || grace <= 0 {
		s.Close()
		return
	}
	go func() {
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-timer.C:
			s.Close()
		case <-s.closed:
		}
	}()
}

func (s *clientSession) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.controlStream.Close()
		_ = s.mux.Close()
		s.registry.remove(s)
	})
}

type sessionRegistry struct {
	mu      sync.RWMutex
	byHost  map[string]*clientSession
	byToken map[string]*clientSession
	metrics *Metrics
}

func newSessionRegistry(metrics *Metrics) *sessionRegistry {
	return &sessionRegistry{
		byHost:  make(map[string]*clientSession),
		byToken: make(map[string]*clientSession),
		metrics: metrics,
	}
}

func (r *sessionRegistry) activate(session *clientSession) (*clientSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, host := range session.hostnames {
		if current, ok := r.byHost[host]; ok && current != nil && current != r.byToken[session.token] {
			return nil, errHostnameAlreadyActive(host)
		}
	}

	replaced := r.byToken[session.token]
	r.byToken[session.token] = session
	for _, host := range session.hostnames {
		r.byHost[host] = session
	}
	r.updateMetricsLocked()
	return replaced, nil
}

func (r *sessionRegistry) lookup(host string) *clientSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byHost[host]
}

func (r *sessionRegistry) remove(session *clientSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current := r.byToken[session.token]; current == session {
		delete(r.byToken, session.token)
	}
	for _, host := range session.hostnames {
		if current := r.byHost[host]; current == session {
			delete(r.byHost, host)
		}
	}
	r.updateMetricsLocked()
}

func (r *sessionRegistry) shutdown(grace time.Duration) {
	r.mu.RLock()
	sessions := make([]*clientSession, 0, len(r.byToken))
	for _, session := range r.byToken {
		sessions = append(sessions, session)
	}
	r.mu.RUnlock()

	for _, session := range sessions {
		session.BeginDrain(controlpb.DrainReason_DRAIN_REASON_SERVER_SHUTDOWN, "edge shutting down", grace)
	}
}

func (r *sessionRegistry) snapshot() registrySnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := registrySnapshot{
		ActiveSessions: len(r.byToken),
		Hostnames:      make([]string, 0, len(r.byHost)),
	}
	for host := range r.byHost {
		out.Hostnames = append(out.Hostnames, host)
	}
	return out
}

func (r *sessionRegistry) updateMetricsLocked() {
	if r.metrics == nil {
		return
	}
	r.metrics.ActiveSessions.Set(float64(len(r.byToken)))
	r.metrics.RegisteredHostnames.Set(float64(len(r.byHost)))
}

type registrySnapshot struct {
	ActiveSessions int
	Hostnames      []string
}

type hostnameConflictError struct {
	hostname string
}

func errHostnameAlreadyActive(host string) error {
	return hostnameConflictError{hostname: host}
}

func (e hostnameConflictError) Error() string {
	return "hostname already active: " + e.hostname
}
