// Package route forwards encrypted connections without terminating client TLS.
package route

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const Proxy = "127.0.0.1:53147"
const DNSIP = "127.0.0.54"

var Domains = []string{"cloudcode-pa.googleapis.com", "daily-cloudcode-pa.googleapis.com", "aicode.googleapis.com"}
var DefaultResolvers = []string{"https://dns.dns-ai.ru/dns-query", "tls://dns.dns-ai.ru"}

func Target(host string) bool {
	for _, d := range Domains {
		if host == d {
			return true
		}
	}
	return false
}

type cached struct {
	IPs   []net.IP
	Until time.Time
}
type Router struct {
	Resolvers []string
	Log       func(string)
	mu        sync.Mutex
	cache     map[string]cached
	http      *http.Client
}

func New(resolvers []string, log func(string)) *Router {
	return &Router{Resolvers: resolvers, Log: log, cache: map[string]cached{}, http: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConns: 8, IdleConnTimeout: 60 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func public(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}
func query(ctx context.Context, client *http.Client, server, host string) ([]net.IP, error) {
	if strings.HasPrefix(server, "tls://") {
		name := strings.TrimPrefix(server, "tls://")
		if _, _, e := net.SplitHostPort(name); e != nil {
			name = net.JoinHostPort(name, "853")
		}
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 4 * time.Second}}
			return d.DialContext(ctx, "tcp", name)
		}}
		ips, e := r.LookupIP(ctx, "ip4", host)
		return ips, e
	}
	if net.ParseIP(server) != nil {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		}}
		return r.LookupIP(ctx, "ip4", host)
	}
	if !strings.HasPrefix(server, "https://") {
		return nil, errors.New("DNS: нужен IPv4, https:// или tls://")
	}
	name, e := dnsmessage.NewName(host + ".")
	if e != nil {
		return nil, e
	}
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x5041, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, e := msg.Pack()
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", server, bytes.NewReader(wire))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DNS HTTP %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if e != nil {
		return nil, e
	}
	var result dnsmessage.Message
	if e = result.Unpack(b); e != nil {
		return nil, e
	}
	if !result.Header.Response || result.Header.RCode != dnsmessage.RCodeSuccess || len(result.Questions) != 1 || result.Questions[0].Name != name {
		return nil, errors.New("неверный ответ DNS")
	}
	var ips []net.IP
	for _, a := range result.Answers {
		if ar, ok := a.Body.(*dnsmessage.AResource); ok {
			ip := net.IP(ar.A[:])
			if public(ip) {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("DNS не вернул адрес")
	}
	return ips, nil
}
func (r *Router) candidates(ctx context.Context, host string) []net.IP {
	r.mu.Lock()
	cached := r.cache[host]
	r.mu.Unlock()
	if time.Now().Before(cached.Until) {
		return cached.IPs
	}
	type answer struct {
		IPs []net.IP
		Ref bool
	}
	ch := make(chan answer, len(r.Resolvers)+1)
	for _, server := range r.Resolvers {
		go func(server string) { ips, _ := query(ctx, r.http, server, host); ch <- answer{IPs: ips} }(server)
	}
	go func() {
		ips, _ := query(ctx, r.http, "https://dns.google/dns-query", host)
		ch <- answer{IPs: ips, Ref: true}
	}()
	var providers, reference []net.IP
	refDone := false
collect:
	for i := 0; i < len(r.Resolvers)+1; i++ {
		select {
		case a := <-ch:
			if a.Ref {
				reference = a.IPs
				refDone = true
			} else {
				providers = append(providers, a.IPs...)
			}
		case <-ctx.Done():
			return nil
		}
		if refDone && len(reference) > 0 {
			for _, ip := range providers {
				same := false
				for _, ref := range reference {
					if ip.Equal(ref) {
						same = true
						break
					}
				}
				if !same {
					break collect
				}
			}
		}
	}

	refs := map[string]bool{}
	for _, ip := range reference {
		refs[ip.String()] = true
	}
	// Prefer a relay address over direct Google addresses, even when direct TLS is faster.
	var substituted []net.IP
	seen := map[string]bool{}
	for _, ip := range providers {
		if public(ip) && !refs[ip.String()] && !seen[ip.String()] {
			seen[ip.String()] = true
			substituted = append(substituted, ip)
		}
	}
	if len(substituted) > 0 {
		return substituted
	}
	if len(providers) > 0 {
		return providers
	}
	return reference

}
func (r *Router) Dial(ctx context.Context, host string) (net.Conn, error) {
	if !Target(host) {
		ips, e := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if e != nil {
			return nil, e
		}
		for _, ip := range ips {
			if !public(ip) {
				continue
			}
			c, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
			if e == nil {
				return c, nil
			}
		}
		return nil, errors.New("адрес недоступен")
	}
	r.mu.Lock()
	entry := r.cache[host]
	r.mu.Unlock()
	if time.Now().Before(entry.Until) && len(entry.IPs) > 0 {
		c, e := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(entry.IPs[0].String(), "443"))
		if e == nil {
			return c, nil
		}
		r.mu.Lock()
		delete(r.cache, host)
		r.mu.Unlock()
	}
	ips := r.candidates(ctx, host)
	if len(ips) == 0 {
		return nil, errors.New("не найдены сетевые маршруты")
	}
	// Probe all candidates concurrently, with real hostname certificate verification.
	type tested struct {
		IP  net.IP
		Err error
	}
	done := make(chan tested, len(ips))
	for _, ip := range ips {
		go func(ip net.IP) {
			d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 4 * time.Second}, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
			c, e := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
			if e == nil {
				c.Close()
			}
			done <- tested{ip, e}
		}(ip)
	}
	var errs []string
	for range ips {
		select {
		case t := <-done:
			if t.Err == nil {
				c, e := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(t.IP.String(), "443"))
				if e == nil {
					r.mu.Lock()
					r.cache[host] = cached{[]net.IP{t.IP}, time.Now().Add(45 * time.Second)}
					r.mu.Unlock()
					return c, nil
				}
			} else {
				errs = append(errs, t.Err.Error())
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// A working direct route remains a fallback outside restricted regions.
	reference, _ := query(ctx, r.http, "https://dns.google/dns-query", host)
	for _, ip := range reference {
		already := false
		for _, old := range ips {
			if ip.Equal(old) {
				already = true
				break
			}
		}
		if already {
			continue
		}
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
		probe, e := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
		if e != nil {
			continue
		}
		probe.Close()
		c, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
		if e == nil {
			return c, nil
		}
	}
	r.mu.Lock()
	delete(r.cache, host)
	r.mu.Unlock()
	return nil, fmt.Errorf("маршрут %s недоступен (%d попыток)", host, len(errs))
}
func tunnel(a net.Conn, br io.Reader, b net.Conn) {
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(12 * time.Hour))
	b.SetDeadline(time.Now().Add(12 * time.Hour))
	done := make(chan struct{})
	go func() {
		io.Copy(b, br)
		if t, ok := b.(*net.TCPConn); ok {
			t.CloseWrite()
		}
		close(done)
	}()
	io.Copy(a, b)
	a.Close()
	b.Close()
	<-done
}
func (r *Router) ServeProxy(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); l.Close() }()
	limit := make(chan struct{}, 64)
	for {
		c, e := l.Accept()
		if e != nil {
			return e
		}
		select {
		case limit <- struct{}{}:
			go func() {
				defer func() { <-limit }()
				defer c.Close()
				c.SetDeadline(time.Now().Add(15 * time.Second))
				br := bufio.NewReaderSize(c, 8192)
				req, e := http.ReadRequest(br)
				if e != nil {
					return
				}
				if req.Method != "CONNECT" {
					io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
					return
				}
				host, port, e := net.SplitHostPort(req.Host)
				if e != nil || port != "443" {
					io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n\r\n")
					return
				}
				call, cancel := context.WithTimeout(ctx, 12*time.Second)
				defer cancel()
				up, e := r.Dial(call, strings.ToLower(host))
				if e != nil {
					r.Log(e.Error())
					io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				tunnel(c, br, up)
			}()
		default:
			c.Close()
		}
	}
}
func DNSReply(wire []byte) ([]byte, error) {
	var q dnsmessage.Message
	if e := q.Unpack(wire); e != nil {
		return nil, e
	}
	if q.Header.Response || len(q.Questions) != 1 {
		return nil, errors.New("invalid query")
	}
	question := q.Questions[0]
	host := strings.TrimSuffix(strings.ToLower(question.Name.String()), ".")
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: q.Header.ID, Response: true, Authoritative: true, RecursionAvailable: true, RecursionDesired: q.Header.RecursionDesired}, Questions: q.Questions}
	if !Target(host) {
		response.Header.RCode = dnsmessage.RCodeRefused
	} else if question.Type == dnsmessage.TypeA {
		response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 20}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 54}}}}
	}
	return response.Pack()
}
func ServeDNS(ctx context.Context, udp net.PacketConn, tcp net.Listener) {
	go func() { <-ctx.Done(); udp.Close(); tcp.Close() }()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, a, e := udp.ReadFrom(buf)
			if e != nil {
				return
			}
			out, e := DNSReply(buf[:n])
			if e == nil {
				udp.WriteTo(out, a)
			}
		}
	}()
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				var h [2]byte
				if _, e := io.ReadFull(c, h[:]); e != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(h[:]))
				if n > 4096 {
					return
				}
				b := make([]byte, n)
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				out, e := DNSReply(b)
				if e == nil {
					binary.BigEndian.PutUint16(h[:], uint16(len(out)))
					c.Write(h[:])
					c.Write(out)
				}
			}()
		}
	}()
}

// SNI parses one complete ClientHello, including records split by TCP.
func SNI(b []byte) (string, error) {
	fail := errors.New("неверный TLS ClientHello")
	if len(b) < 4 || b[0] != 1 {
		return "", fail
	}
	p := 4
	if p+35 > len(b) {
		return "", fail
	}
	p += 34
	n := int(b[p])
	p++
	p += n
	if p+2 > len(b) {
		return "", fail
	}
	n = int(binary.BigEndian.Uint16(b[p:]))
	p += 2 + n
	if p >= len(b) {
		return "", fail
	}
	n = int(b[p])
	p += 1 + n
	if p+2 > len(b) {
		return "", fail
	}
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if end > len(b) {
		return "", fail
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(b[p:])
		n = int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if p+n > end {
			return "", fail
		}
		if typ == 0 {
			v := b[p : p+n]
			if len(v) < 5 || v[2] != 0 {
				return "", fail
			}
			size := int(binary.BigEndian.Uint16(v[3:]))
			if size+5 > len(v) {
				return "", fail
			}
			return strings.ToLower(string(v[5 : 5+size])), nil
		}
		p += n
	}
	return "", fail
}
func (r *Router) ServeTLS(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); l.Close() }()
	sem := make(chan struct{}, 64)
	for {
		c, e := l.Accept()
		if e != nil {
			return e
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var raw, hello []byte
				for len(hello) < 4 || len(hello) < 4+(int(hello[1])<<16|int(hello[2])<<8|int(hello[3])) {
					var h [5]byte
					if _, e := io.ReadFull(c, h[:]); e != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(h[3:]))
					if h[0] != 22 || n > 18432 || len(raw)+n > 65536 {
						return
					}
					part := make([]byte, n)
					if _, e := io.ReadFull(c, part); e != nil {
						return
					}
					raw = append(raw, h[:]...)
					raw = append(raw, part...)
					hello = append(hello, part...)
				}
				host, e := SNI(hello)
				if e != nil || !Target(host) {
					return
				}
				call, cancel := context.WithTimeout(ctx, 12*time.Second)
				defer cancel()
				up, e := r.Dial(call, host)
				if e != nil {
					r.Log(e.Error())
					return
				}
				if _, e = up.Write(raw); e != nil {
					up.Close()
					return
				}
				tunnel(c, c, up)
			}()
		default:
			c.Close()
		}
	}
}
