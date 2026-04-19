package edge

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	ActiveSessions         prometheus.Gauge
	RegisteredHostnames    prometheus.Gauge
	InflightStreams        prometheus.Gauge
	HeartbeatsMissed       prometheus.Counter
	StreamsOpened          prometheus.Counter
	StreamsClosed          prometheus.Counter
	BytesRelayed           prometheus.Counter
	UnknownHostCloses      prometheus.Counter
	MissingSNICloses       prometheus.Counter
	ClientHelloParseErrors prometheus.Counter
	PerSessionLimitRejects prometheus.Counter
	TotalLimitRejects      prometheus.Counter
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	m := &Metrics{
		ActiveSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "muxbridge_edge_active_sessions",
			Help: "Number of currently active client sessions.",
		}),
		RegisteredHostnames: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "muxbridge_edge_registered_hostnames",
			Help: "Number of hostnames mapped to active sessions.",
		}),
		InflightStreams: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "muxbridge_edge_inflight_streams",
			Help: "Number of currently active tunneled public connections/yamux data streams.",
		}),
		HeartbeatsMissed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "muxbridge_edge_heartbeats_missed_total",
			Help: "Number of sessions closed due to heartbeat timeout.",
		}),
		StreamsOpened: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "muxbridge_edge_streams_opened_total",
			Help: "Number of yamux data streams opened.",
		}),
		StreamsClosed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "muxbridge_edge_streams_closed_total",
			Help: "Number of yamux data streams closed.",
		}),
		BytesRelayed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "muxbridge_edge_bytes_relayed_total",
			Help: "Total bytes relayed across tunneled streams.",
		}),
		UnknownHostCloses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "muxbridge_edge_unknown_host_closes_total",
			Help: "Connections closed because no active session owned the requested hostname.",
		}),
		MissingSNICloses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "muxbridge_edge_missing_sni_closes_total",
			Help: "Connections closed because SNI was missing.",
		}),
		ClientHelloParseErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "muxbridge_edge_clienthello_parse_errors_total",
			Help: "Connections closed because the TLS ClientHello could not be parsed.",
		}),
		PerSessionLimitRejects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "muxbridge_edge_inflight_per_session_rejects_total",
			Help: "Connections rejected because a client session hit its inflight stream limit.",
		}),
		TotalLimitRejects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "muxbridge_edge_inflight_total_rejects_total",
			Help: "Connections rejected because the edge hit its total inflight stream limit.",
		}),
	}
	reg.MustRegister(
		m.ActiveSessions,
		m.RegisteredHostnames,
		m.InflightStreams,
		m.HeartbeatsMissed,
		m.StreamsOpened,
		m.StreamsClosed,
		m.BytesRelayed,
		m.UnknownHostCloses,
		m.MissingSNICloses,
		m.ClientHelloParseErrors,
		m.PerSessionLimitRejects,
		m.TotalLimitRejects,
	)
	return m
}
