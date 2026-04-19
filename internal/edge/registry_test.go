package edge

import (
	"bytes"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/define42/muxbridge-e2e/internal/control"
	controlpb "github.com/define42/muxbridge-e2e/proto"
)

func TestSessionRegistryActivateLookupRemoveAndSnapshot(t *testing.T) {
	t.Parallel()

	registry := newSessionRegistry(NewMetrics(prometheus.NewRegistry()), 0, 0)
	first := &clientSession{
		token:     "demo-token",
		hostnames: []string{"demo.example.test"},
		registry:  registry,
		closed:    make(chan struct{}),
	}

	replaced, err := registry.activate(first)
	if err != nil {
		t.Fatalf("activate(first) error = %v", err)
	}
	if replaced != nil {
		t.Fatalf("activate(first) replaced = %v, want nil", replaced)
	}
	if got := registry.lookup("demo.example.test"); got != first {
		t.Fatal("lookup() returned unexpected session")
	}

	snapshot := registry.snapshot()
	if snapshot.ActiveSessions != 1 {
		t.Fatalf("snapshot.ActiveSessions = %d, want %d", snapshot.ActiveSessions, 1)
	}
	if !slices.Equal(snapshot.Hostnames, []string{"demo.example.test"}) {
		t.Fatalf("snapshot.Hostnames = %v, want %v", snapshot.Hostnames, []string{"demo.example.test"})
	}
	if got := gaugeValue(t, registry.metrics.ActiveSessions); got != 1 {
		t.Fatalf("ActiveSessions gauge = %v, want %d", got, 1)
	}
	if got := gaugeValue(t, registry.metrics.RegisteredHostnames); got != 1 {
		t.Fatalf("RegisteredHostnames gauge = %v, want %d", got, 1)
	}

	replacement := &clientSession{
		token:     "demo-token",
		hostnames: []string{"demo.example.test"},
		registry:  registry,
		closed:    make(chan struct{}),
	}
	replaced, err = registry.activate(replacement)
	if err != nil {
		t.Fatalf("activate(replacement) error = %v", err)
	}
	if replaced != first {
		t.Fatalf("activate(replacement) replaced = %v, want %v", replaced, first)
	}

	conflict := &clientSession{
		token:     "other-token",
		hostnames: []string{"demo.example.test"},
		registry:  registry,
		closed:    make(chan struct{}),
	}
	_, err = registry.activate(conflict)
	if err == nil || err.Error() != "hostname already active: demo.example.test" {
		t.Fatalf("activate(conflict) error = %v, want hostname conflict", err)
	}

	registry.remove(first)
	if got := registry.lookup("demo.example.test"); got != replacement {
		t.Fatal("remove(first) removed the replacement session")
	}

	registry.remove(replacement)
	if got := registry.lookup("demo.example.test"); got != nil {
		t.Fatalf("lookup() after remove = %v, want nil", got)
	}
	if got := gaugeValue(t, registry.metrics.ActiveSessions); got != 0 {
		t.Fatalf("ActiveSessions gauge = %v, want %d", got, 0)
	}
	if got := gaugeValue(t, registry.metrics.RegisteredHostnames); got != 0 {
		t.Fatalf("RegisteredHostnames gauge = %v, want %d", got, 0)
	}
}

func TestClientSessionOpenStreamBeginDrainAndFinishStream(t *testing.T) {
	t.Parallel()

	registry := newSessionRegistry(NewMetrics(prometheus.NewRegistry()), 0, 0)
	peer, sessionMux := newYamuxPair(t)
	controlStream := &bufferCloser{}
	session := &clientSession{
		id:            "session-1",
		token:         "demo-token",
		hostnames:     []string{"demo.example.test"},
		mux:           sessionMux,
		controlStream: controlStream,
		controlWriter: control.NewLockedWriter(controlStream),
		registry:      registry,
		closed:        make(chan struct{}),
	}
	if _, err := registry.activate(session); err != nil {
		t.Fatalf("activate() error = %v", err)
	}

	accepted := make(chan *yamux.Stream, 1)
	go func() {
		stream, err := peer.AcceptStream()
		if err == nil {
			accepted <- stream
		}
	}()

	stream, err := session.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	defer func() { _ = stream.Close() }()

	peerStream := <-accepted
	defer func() { _ = peerStream.Close() }()
	if got := session.activeStreams.Load(); got != 1 {
		t.Fatalf("activeStreams = %d, want %d", got, 1)
	}
	if got := registry.inflightTotal.Load(); got != 1 {
		t.Fatalf("inflightTotal = %d, want %d", got, 1)
	}
	if got := gaugeValue(t, registry.metrics.InflightStreams); got != 1 {
		t.Fatalf("InflightStreams gauge = %v, want %d", got, 1)
	}

	session.BeginDrain(controlpb.DrainReason_DRAIN_REASON_SESSION_REPLACED, "newer session", time.Second)
	if !session.draining.Load() {
		t.Fatal("BeginDrain() did not mark session as draining")
	}
	if got := registry.lookup("demo.example.test"); got != nil {
		t.Fatalf("lookup() during drain = %v, want nil", got)
	}
	if _, err := session.OpenStream(); !errors.Is(err, errSessionDraining) {
		t.Fatalf("OpenStream() during drain error = %v, want %v", err, errSessionDraining)
	}
	session.FinishStream()
	if got := registry.inflightTotal.Load(); got != 0 {
		t.Fatalf("inflightTotal after FinishStream = %d, want %d", got, 0)
	}
	if got := gaugeValue(t, registry.metrics.InflightStreams); got != 0 {
		t.Fatalf("InflightStreams gauge after FinishStream = %v, want %d", got, 0)
	}

	select {
	case <-session.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("session did not close after FinishStream()")
	}

	if got := registry.lookup("demo.example.test"); got != nil {
		t.Fatalf("lookup() after drain = %v, want nil", got)
	}

	env, err := control.ReadEnvelope(bytes.NewReader(controlStream.Bytes()))
	if err != nil {
		t.Fatalf("ReadEnvelope() error = %v", err)
	}
	notice := env.GetDrainNotice()
	if notice == nil || notice.GetReason() != controlpb.DrainReason_DRAIN_REASON_SESSION_REPLACED {
		t.Fatalf("DrainNotice = %#v, want session replaced notice", notice)
	}
}

func TestSessionRegistryShutdownBeginsDrain(t *testing.T) {
	t.Parallel()

	registry := newSessionRegistry(nil, 0, 0)

	sessionOne := newDrainableSession(t, registry, "demo-token", "demo.example.test")
	sessionTwo := newDrainableSession(t, registry, "api-token", "api.example.test")
	if _, err := registry.activate(sessionOne); err != nil {
		t.Fatalf("activate(sessionOne) error = %v", err)
	}
	if _, err := registry.activate(sessionTwo); err != nil {
		t.Fatalf("activate(sessionTwo) error = %v", err)
	}

	registry.shutdown(0)

	waitClosed(t, sessionOne.closed)
	waitClosed(t, sessionTwo.closed)

	envOne, err := control.ReadEnvelope(bytes.NewReader(sessionOne.controlStream.(*bufferCloser).Bytes()))
	if err != nil {
		t.Fatalf("ReadEnvelope(sessionOne) error = %v", err)
	}
	if envOne.GetDrainNotice().GetReason() != controlpb.DrainReason_DRAIN_REASON_SERVER_SHUTDOWN {
		t.Fatalf("sessionOne drain reason = %v, want server shutdown", envOne.GetDrainNotice().GetReason())
	}
}

func TestClientSessionOpenStreamRejectsPerSessionInflightLimit(t *testing.T) {
	t.Parallel()

	registry := newSessionRegistry(NewMetrics(prometheus.NewRegistry()), 1, 0)
	peer, sessionMux := newYamuxPair(t)
	controlStream := &bufferCloser{}
	session := &clientSession{
		id:            "session-limit",
		token:         "demo-token",
		hostnames:     []string{"demo.example.test"},
		mux:           sessionMux,
		controlStream: controlStream,
		controlWriter: control.NewLockedWriter(controlStream),
		registry:      registry,
		closed:        make(chan struct{}),
	}
	if _, err := registry.activate(session); err != nil {
		t.Fatalf("activate() error = %v", err)
	}

	accepted := make(chan *yamux.Stream, 1)
	go func() {
		stream, err := peer.AcceptStream()
		if err == nil {
			accepted <- stream
		}
	}()

	stream, err := session.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream(first) error = %v", err)
	}
	defer func() { _ = stream.Close() }()
	defer session.FinishStream()

	peerStream := <-accepted
	defer func() { _ = peerStream.Close() }()

	if _, err := session.OpenStream(); !errors.Is(err, errSessionInflightLimitReached) {
		t.Fatalf("OpenStream(second) error = %v, want %v", err, errSessionInflightLimitReached)
	}
	if got := session.activeStreams.Load(); got != 1 {
		t.Fatalf("activeStreams = %d, want %d", got, 1)
	}
	if got := registry.inflightTotal.Load(); got != 1 {
		t.Fatalf("inflightTotal = %d, want %d", got, 1)
	}
}

func TestClientSessionOpenStreamRejectsTotalInflightLimitAcrossSessions(t *testing.T) {
	t.Parallel()

	registry := newSessionRegistry(NewMetrics(prometheus.NewRegistry()), 0, 1)
	sessionOne := newDrainableSession(t, registry, "demo-token", "demo.example.test")
	sessionTwo := newDrainableSession(t, registry, "api-token", "api.example.test")
	if _, err := registry.activate(sessionOne); err != nil {
		t.Fatalf("activate(sessionOne) error = %v", err)
	}
	if _, err := registry.activate(sessionTwo); err != nil {
		t.Fatalf("activate(sessionTwo) error = %v", err)
	}

	streamOne, err := sessionOne.OpenStream()
	if err != nil {
		t.Fatalf("sessionOne.OpenStream() error = %v", err)
	}
	defer func() { _ = streamOne.Close() }()
	defer sessionOne.FinishStream()

	if _, err := sessionTwo.OpenStream(); !errors.Is(err, errTotalInflightLimitReached) {
		t.Fatalf("sessionTwo.OpenStream() error = %v, want %v", err, errTotalInflightLimitReached)
	}
	if got := registry.inflightTotal.Load(); got != 1 {
		t.Fatalf("inflightTotal = %d, want %d", got, 1)
	}
}

func TestClientSessionOpenStreamRollsBackReservationsWhenMuxOpenFails(t *testing.T) {
	t.Parallel()

	registry := newSessionRegistry(NewMetrics(prometheus.NewRegistry()), 1, 1)
	_, sessionMux := newYamuxPair(t)
	_ = sessionMux.Close()
	controlStream := &bufferCloser{}
	session := &clientSession{
		id:            "session-rollback",
		token:         "demo-token",
		hostnames:     []string{"demo.example.test"},
		mux:           sessionMux,
		controlStream: controlStream,
		controlWriter: control.NewLockedWriter(controlStream),
		registry:      registry,
		closed:        make(chan struct{}),
	}

	if _, err := session.OpenStream(); err == nil {
		t.Fatal("OpenStream() error = nil, want mux open failure")
	}
	if got := session.activeStreams.Load(); got != 0 {
		t.Fatalf("activeStreams = %d, want %d", got, 0)
	}
	if got := registry.inflightTotal.Load(); got != 0 {
		t.Fatalf("inflightTotal = %d, want %d", got, 0)
	}
	if got := gaugeValue(t, registry.metrics.InflightStreams); got != 0 {
		t.Fatalf("InflightStreams gauge = %v, want %d", got, 0)
	}
}

func newDrainableSession(t *testing.T, registry *sessionRegistry, token, hostname string) *clientSession {
	t.Helper()

	_, muxSession := newYamuxPair(t)
	controlStream := &bufferCloser{}
	return &clientSession{
		id:            hostname,
		token:         token,
		hostnames:     []string{hostname},
		mux:           muxSession,
		controlStream: controlStream,
		controlWriter: control.NewLockedWriter(controlStream),
		registry:      registry,
		closed:        make(chan struct{}),
	}
}

func newYamuxPair(t *testing.T) (*yamux.Session, *yamux.Session) {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	server, err := yamux.Server(serverConn, nil)
	if err != nil {
		t.Fatalf("yamux.Server() error = %v", err)
	}
	client, err := yamux.Client(clientConn, nil)
	if err != nil {
		t.Fatalf("yamux.Client() error = %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	return server, client
}

func waitClosed(t *testing.T, ch <-chan struct{}) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for session to close")
	}
}

type bufferCloser struct {
	bytes.Buffer
}

func (b *bufferCloser) Close() error { return nil }

func gaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()

	metric := &dto.Metric{}
	if err := gauge.Write(metric); err != nil {
		t.Fatalf("gauge.Write() error = %v", err)
	}
	return metric.GetGauge().GetValue()
}
