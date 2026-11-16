package chathub

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

type pooledConn struct {
	conn      *websocket.Conn
	created   time.Time
	handshook bool
	ids       PooledIDs
	variant   string
}

// PooledIDs are the identifiers a pre-warmed socket was dialed with. The
// upstream binds a WebSocket to the ConversationId / X-SessionId carried in its
// URL, so the request that consumes the socket must send exactly these IDs in
// its payload (and report them back to the caller). Using different IDs makes
// the next turn of the conversation land in an empty upstream conversation.
type PooledIDs struct {
	SessionID      string
	ConversationID string
	RequestID      string
}

func poolVariant(licenseType, scenario string) string { return licenseType + "|" + scenario }

const maxPoolPerKey = 2

// MaxPoolPerKey is the number of idle connections kept per account. Exported so
// the keep-alive loop refills only to the pool's real capacity.
const MaxPoolPerKey = maxPoolPerKey

type ConnPool struct {
	mu     sync.Mutex
	conns  map[string][]*pooledConn // key = oid|tid, up to maxPoolPerKey connections
	dialer *websocket.Dialer
	header http.Header
	stop   chan struct{}
}

func NewConnPool(dialer *websocket.Dialer, header http.Header) *ConnPool {
	p := &ConnPool{
		conns:  make(map[string][]*pooledConn),
		dialer: dialer,
		header: header,
		stop:   make(chan struct{}),
	}
	go p.gcLoop()
	return p
}

func (p *ConnPool) key(oid, tid string) string { return oid + "|" + tid }

// Take hands out a pre-warmed socket that has never carried a request, or
// reports false when none matches. A socket is only ever used for one request:
// it is never put back, so frames or upstream conversation state from one
// caller can never reach another. The socket must also have been dialed with
// the same licenseType/scenario as the request that wants it.
func (p *ConnPool) Take(oid, tid, licenseType, scenario string) (*websocket.Conn, PooledIDs, bool) {
	if p == nil {
		return nil, PooledIDs{}, false
	}
	want := poolVariant(licenseType, scenario)
	key := p.key(oid, tid)
	p.mu.Lock()
	defer p.mu.Unlock()
	conns := p.conns[key]
	for i := len(conns) - 1; i >= 0; i-- {
		pc := conns[i]
		if time.Since(pc.created) >= 2*time.Minute || !pc.handshook {
			pc.conn.Close()
			conns = append(conns[:i], conns[i+1:]...)
			continue
		}
		if pc.variant != want {
			continue
		}
		conns = append(conns[:i], conns[i+1:]...)
		p.conns[key] = conns
		return pc.conn, pc.ids, true
	}
	p.conns[key] = conns
	return nil, PooledIDs{}, false
}

// Warm dials and handshakes one spare socket for the account. Each socket gets
// its own fresh session/conversation/request IDs, remembered alongside it so
// the consuming request can adopt them.
func (p *ConnPool) Warm(ctx context.Context, acc Account, licenseType, scenario string) bool {
	if p == nil || acc.OID == "" || acc.TID == "" || acc.AccessToken == "" {
		return false
	}
	key := p.key(acc.OID, acc.TID)

	p.mu.Lock()
	if len(p.conns[key]) >= maxPoolPerKey {
		p.mu.Unlock()
		return false
	}
	p.mu.Unlock()

	ids := PooledIDs{SessionID: uuid.NewString(), ConversationID: uuid.NewString(), RequestID: uuid.NewString()}
	wsURL, err := BuildWSURL(acc, ids.SessionID, ids.ConversationID, ids.RequestID, licenseType, scenario)
	if err != nil {
		return false
	}
	conn, resp, err := p.dialer.DialContext(ctx, wsURL, p.header.Clone())
	if err != nil {
		if resp != nil {
			log.Printf("[connpool] warm dial failed oid=%s status=%d err=%v", acc.OID, resp.StatusCode, err)
		} else {
			log.Printf("[connpool] warm dial failed oid=%s err=%v", acc.OID, err)
		}
		return false
	}

	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"protocol":"json","version":1}`+"\x1e")); err != nil {
		log.Printf("[connpool] warm handshake send failed: %v", err)
		conn.Close()
		return false
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _, err = conn.ReadMessage()
	if err != nil {
		log.Printf("[connpool] warm handshake recv failed: %v", err)
		conn.Close()
		return false
	}
	_ = conn.SetReadDeadline(time.Time{})

	p.mu.Lock()
	if len(p.conns[key]) >= maxPoolPerKey {
		conn.Close()
		p.mu.Unlock()
		return false
	}
	p.conns[key] = append(p.conns[key], &pooledConn{conn: conn, created: time.Now(), handshook: true, ids: ids, variant: poolVariant(licenseType, scenario)})
	p.mu.Unlock()

	log.Printf("[connpool] warmed connection oid=%s tid=%s", acc.OID, acc.TID)
	return true
}

// Idle returns how many pooled, still-fresh connections this pool currently
// holds for the account. Used by the keeper to refill only the real gap.
func (p *ConnPool) Idle(oid, tid string) int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	n := 0
	for _, pc := range p.conns[p.key(oid, tid)] {
		if now.Sub(pc.created) < 2*time.Minute && pc.handshook {
			n++
		}
	}
	return n
}

func (p *ConnPool) GC() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for k, conns := range p.conns {
		kept := conns[:0]
		for _, pc := range conns {
			if now.Sub(pc.created) > 2*time.Minute {
				pc.conn.Close()
			} else {
				kept = append(kept, pc)
			}
		}
		if len(kept) == 0 {
			delete(p.conns, k)
		} else {
			p.conns[k] = kept
		}
	}
}

func (p *ConnPool) Close() {
	close(p.stop)
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, conns := range p.conns {
		for _, pc := range conns {
			pc.conn.Close()
		}
		delete(p.conns, k)
	}
}

func (p *ConnPool) Stats() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	details := make([]map[string]any, 0)
	for k, conns := range p.conns {
		for _, pc := range conns {
			total++
			details = append(details, map[string]any{"key": k, "age_ms": time.Since(pc.created).Milliseconds(), "handshook": pc.handshook})
		}
	}
	return map[string]any{"mode": "connpool", "pooled_connections": total, "details": details}
}

func (p *ConnPool) gcLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.GC()
		}
	}
}
