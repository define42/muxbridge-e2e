package edge

import (
	"errors"
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
	streamMu      sync.Mutex
}

var errSessionDraining = errors.New("session draining")
var errSessionInflightLimitReached = errors.New("session inflight limit reached")
var errTotalInflightLimitReached = errors.New("total inflight limit reached")

type ioCloser interface {
	Close() error
}

func (s *clientSession) Send(env *controlpb.Envelope) error {
	return s.controlWriter.WriteEnvelope(env)
}

func (s *clientSession) OpenStream() (*yamux.Stream, error) {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()

	if s.draining.Load() {
		return nil, errSessionDraining
	}
	if limit := s.registry.maxInflightPerSession; limit > 0 && s.activeStreams.Load() >= int64(limit) {
		return nil, errSessionInflightLimitReached
	}
	if err := s.registry.reserveInflight(); err != nil {
		return nil, err
	}
	s.activeStreams.Add(1)

	stream, err := s.mux.OpenStream()
	if err != nil {
		s.activeStreams.Add(-1)
		s.registry.releaseInflight()
		return nil, err
	}
	return stream, nil
}

func (s *clientSession) FinishStream() {
	s.registry.releaseInflight()
	if remaining := s.activeStreams.Add(-1); remaining == 0 && s.draining.Load() {
		s.Close()
	}
}

func (s *clientSession) BeginDrain(reason controlpb.DrainReason, message string, grace time.Duration) {
	s.streamMu.Lock()
	if s.draining.Load() {
		s.streamMu.Unlock()
		return
	}
	s.draining.Store(true)
	activeStreams := s.activeStreams.Load()
	s.streamMu.Unlock()

	_ = s.Send(&controlpb.Envelope{
		Message: &controlpb.Envelope_DrainNotice{
			DrainNotice: &controlpb.DrainNotice{
				Reason:  reason,
				Message: message,
			},
		},
	})
	if activeStreams == 0 || grace <= 0 {
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
	mu                    sync.RWMutex
	byHost                map[string]*clientSession
	byToken               map[string]*clientSession
	metrics               *Metrics
	maxInflightPerSession int
	maxTotalInflight      int
	inflightTotal         atomic.Int64
}

func newSessionRegistry(metrics *Metrics, maxInflightPerSession, maxTotalInflight int) *sessionRegistry {
	return &sessionRegistry{
		byHost:                make(map[string]*clientSession),
		byToken:               make(map[string]*clientSession),
		metrics:               metrics,
		maxInflightPerSession: maxInflightPerSession,
		maxTotalInflight:      maxTotalInflight,
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
	session := r.byHost[host]
	if session != nil && session.draining.Load() {
		return nil
	}
	return session
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

func (r *sessionRegistry) reserveInflight() error {
	if r.maxTotalInflight <= 0 {
		total := r.inflightTotal.Add(1)
		r.setInflightMetric(total)
		return nil
	}

	for {
		current := r.inflightTotal.Load()
		if current >= int64(r.maxTotalInflight) {
			return errTotalInflightLimitReached
		}
		if r.inflightTotal.CompareAndSwap(current, current+1) {
			r.setInflightMetric(current + 1)
			return nil
		}
	}
}

func (r *sessionRegistry) releaseInflight() {
	total := r.inflightTotal.Add(-1)
	if total < 0 {
		total = 0
		r.inflightTotal.Store(0)
	}
	r.setInflightMetric(total)
}

func (r *sessionRegistry) setInflightMetric(total int64) {
	if r.metrics == nil {
		return
	}
	r.metrics.InflightStreams.Set(float64(total))
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
