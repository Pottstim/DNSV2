package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
 )

// Configuration
const (
	// Server Ports
	DNS_PORT   = ":5353"
	HTTPS_PORT = ":8444"
	DOT_PORT   = ":8853"
	DOQ_PORT   = ":8854"

	// Upstream DNS Resolver
	UPSTREAM_DNS = "127.0.0.1:53"

	// SSL Certificate Paths
	SSL_CERT_PATH = "/etc/letsencrypt/live/doh.617east.com/fullchain.pem"
	SSL_KEY_PATH  = "/etc/letsencrypt/live/doh.617east.com/privkey.pem"
)

// Stats structure
type Stats struct {
	mu             sync.Mutex
	TotalQueries   int
	HTTPSQueries   int
	DoTQueries     int
	DoQQueries     int
	DNSQueries     int
	BlockedQueries int
}

var stats Stats

// DNS handler
func dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	stats.mu.Lock()
	stats.TotalQueries++
	stats.DNSQueries++
	stats.mu.Unlock()

	client := dns.Client{Net: "udp"}
	resp, _, err := client.Exchange(r, UPSTREAM_DNS)
	if err != nil {
		log.Printf("Failed to forward DNS query: %v", err)
		dns.HandleFailed(w, r)
		return
	}

	for _, a := range resp.Answer {
		if a, ok := a.(*dns.A); ok {
			if a.A.Equal(net.IPv4(0, 0, 0, 0)) {
				stats.mu.Lock()
				stats.BlockedQueries++
				stats.mu.Unlock()
				break
			}
		}
	}
	w.WriteMsg(resp)
}

// DoH handler
func handleDoH(w http.ResponseWriter, r *http.Request ) {
	stats.mu.Lock()
	stats.TotalQueries++
	stats.HTTPSQueries++
	stats.mu.Unlock()

	var query []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		b64query := r.URL.Query( ).Get("dns")
		query, err = base64.RawURLEncoding.DecodeString(b64query)
		if err != nil {
			http.Error(w, "Invalid DNS query", http.StatusBadRequest )
			return
		}
	case http.MethodPost:
		if r.Header.Get("Content-Type" ) != "application/dns-message" {
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType )
			return
		}
		query, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest )
			return
		}
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed )
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(query); err != nil {
		http.Error(w, "Failed to unpack DNS message", http.StatusBadRequest )
		return
	}

	client := &dns.Client{Net: "udp"}
	resp, _, err := client.Exchange(msg, UPSTREAM_DNS)
	if err != nil {
		log.Printf("Failed to resolve DoH query: %v", err)
		http.Error(w, "DNS resolution failed", http.StatusInternalServerError )
		return
	}

	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError )
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packed)
}

// DoT handler
func handleDoTConnection(conn net.Conn, dnsServer string) {
	defer conn.Close()
	stats.mu.Lock()
	stats.TotalQueries++
	stats.DoTQueries++
	stats.mu.Unlock()

	for {
		lenBuf := make([]byte, 2)
		_, err := io.ReadFull(conn, lenBuf)
		if err != nil {
			return
		}
		queryLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		queryBuf := make([]byte, queryLen)
		_, err = io.ReadFull(conn, queryBuf)
		if err != nil {
			return
		}

		client := &dns.Client{Net: "udp"}
		msg := new(dns.Msg)
		msg.Unpack(queryBuf)
		resp, _, err := client.Exchange(msg, dnsServer)
		if err != nil {
			log.Printf("Failed to resolve DoT query: %v", err)
			continue
		}

		packed, err := resp.Pack()
		if err != nil {
			continue
		}

		respLenBuf := make([]byte, 2)
		respLenBuf[0] = byte(len(packed) >> 8)
		respLenBuf[1] = byte(len(packed))
		conn.Write(append(respLenBuf, packed...))
	}
}

// DoQ Listener
func listenAndServeDoQ(addr, certFile, keyFile, dnsServer string) {
	tlsConf, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load DoQ certificate and key: %v", err)
	}
	listener, err := quic.ListenAddr(addr, &tls.Config{Certificates: []tls.Certificate{tlsConf}, NextProtos: []string{"doq"}}, nil)
	if err != nil {
		log.Fatalf("Failed to start DoQ listener: %v", err)
	}
	defer listener.Close()
	log.Printf("DoQ server listening on %s", addr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Failed to accept DoQ connection: %v", err)
			continue
		}
		go handleDoQStream(conn, dnsServer)
	}
}

// DoQ Stream Handler
func handleDoQStream(conn quic.Connection, dnsServer string) {
	defer conn.CloseWithError(0, "")
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Failed to accept DoQ stream: %v", err)
		return
	}

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil {
		return
	}
	query := buf[:n]

	if len(query) < 2 {
		return
	}
	dnsQuery := query[2:]

	dnsConn, err := net.Dial("udp", dnsServer)
	if err != nil {
		log.Printf("Failed to connect to DNS server: %v", err)
		return
	}
	defer dnsConn.Close()

	_, err = dnsConn.Write(dnsQuery)
	if err != nil {
		log.Printf("Failed to send query to DNS server: %v", err)
		return
	}

	respBuf := make([]byte, 4096)
	n, err = dnsConn.Read(respBuf)
	if err != nil {
		log.Printf("Failed to read response from DNS server: %v", err)
		return
	}
	dnsResp := respBuf[:n]

	respLen := uint16(len(dnsResp))
	doqResp := []byte{byte(respLen >> 8), byte(respLen)}
	doqResp = append(doqResp, dnsResp...)

	_, err = stream.Write(doqResp)
	if err != nil {
		log.Printf("Failed to write DoQ response: %v", err)
	}
	stream.Close()
}

// Web interface handler
func handleWebInterface(w http.ResponseWriter, r *http.Request ) {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func main() {
	go func() {
		server := &dns.Server{Addr: DNS_PORT, Net: "udp"}
		dns.HandleFunc(".", dnsHandler)
		log.Printf("Standard DNS server listening on %s", DNS_PORT)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start DNS server: %v", err)
		}
	}()

	go func() {
		cert, err := tls.LoadX509KeyPair(SSL_CERT_PATH, SSL_KEY_PATH)
		if err != nil {
			log.Fatalf("Failed to load DoT certificate: %v", err)
		}
		config := &tls.Config{Certificates: []tls.Certificate{cert}}
		listener, err := tls.Listen("tcp", DOT_PORT, config)
		if err != nil {
			log.Fatalf("Failed to start DoT listener: %v", err)
		}
		defer listener.Close()
		log.Printf("DoT server listening on %s", DOT_PORT)
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("DoT accept error: %v", err)
				continue
			}
			go handleDoTConnection(conn, UPSTREAM_DNS)
		}
	}()

	go listenAndServeDoQ(DOQ_PORT, SSL_CERT_PATH, SSL_KEY_PATH, UPSTREAM_DNS)

	mux := http.NewServeMux( )
	mux.HandleFunc("/dns-query", handleDoH)
	mux.HandleFunc("/stats", handleWebInterface)

	log.Printf("DoH server listening on %s", HTTPS_PORT)
	if err := http.ListenAndServeTLS(HTTPS_PORT, SSL_CERT_PATH, SSL_KEY_PATH, mux ); err != nil {
		log.Fatalf("Failed to start DoH server: %v", err)
	}
}
