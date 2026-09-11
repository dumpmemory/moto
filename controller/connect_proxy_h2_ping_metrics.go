package controller

import (
	"crypto/tls"
	"net"
	"sync"
)

// A CountError callback belongs to a physical ClientConn, not the shared
// endpoint transport. x/net can deliver another lost-PING notification after
// its read loop has terminated; that is neither a new failure nor a failure of
// the replacement connection. This observer changes metrics only.
type http2PingMetricConn struct {
	net.Conn
	mu         sync.Mutex
	terminated bool
	recorded   bool
}

func wrapHTTP2PingMetricConnection(raw net.Conn, countError func(string)) (net.Conn, func(string)) {
	observed := &http2PingMetricConn{Conn: raw}
	var connection net.Conn = observed
	// Preserve x/net's optional crypto/tls state access without claiming that a
	// specialized TLS adapter exposes a state type it does not implement.
	if state, ok := raw.(interface{ ConnectionState() tls.ConnectionState }); ok {
		connection = &http2PingTLSMetricConn{http2PingMetricConn: observed, state: state}
	}
	return connection, func(errorType string) {
		if errorType == "conn_close_lost_ping" {
			observed.mu.Lock()
			if observed.terminated || observed.recorded {
				observed.mu.Unlock()
				return
			}
			observed.recorded = true
			observed.mu.Unlock()
		}
		if countError != nil {
			countError(errorType)
		}
	}
}

func (connection *http2PingMetricConn) markTerminated() {
	connection.mu.Lock()
	connection.terminated = true
	connection.mu.Unlock()
}

func (connection *http2PingMetricConn) Read(buffer []byte) (int, error) {
	n, err := connection.Conn.Read(buffer)
	if err != nil {
		// An EOF/read failure already ended the physical reader. A racing PING
		// on that dead reader must not invent a second cause of connection loss.
		connection.markTerminated()
	}
	return n, err
}

func (connection *http2PingMetricConn) Close() error {
	connection.markTerminated()
	return connection.Conn.Close()
}

type http2PingTLSMetricConn struct {
	*http2PingMetricConn
	state interface{ ConnectionState() tls.ConnectionState }
}

func (connection *http2PingTLSMetricConn) ConnectionState() tls.ConnectionState {
	return connection.state.ConnectionState()
}
