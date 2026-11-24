package route

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"testing"
	"time"
)

func TestDNSExactNames(t *testing.T) {
	for _, host := range []string{Domains[0], "accounts.google.com", "evilcloudcode-pa.googleapis.com"} {
		for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.Type(65)} {
			name, _ := dnsmessage.NewName(host + ".")
			q := dnsmessage.Message{Header: dnsmessage.Header{ID: 37, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: typ, Class: dnsmessage.ClassINET}}}
			wire, _ := q.Pack()
			out, e := DNSReply(wire)
			if e != nil {
				t.Fatal(e)
			}
			var r dnsmessage.Message
			if e = r.Unpack(out); e != nil {
				t.Fatal(e)
			}
			if r.ID != 37 || !r.Response {
				t.Fatal("bad response")
			}
			if !Target(host) && r.RCode != dnsmessage.RCodeRefused {
				t.Fatal("foreign hostname accepted")
			}
			if Target(host) && typ == dnsmessage.TypeA {
				if len(r.Answers) != 1 {
					t.Fatal("missing loopback answer")
				}
			} else if len(r.Answers) != 0 {
				t.Fatal("unexpected answer")
			}
		}
	}
}
func TestClientHello(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		client := tls.Client(a, &tls.Config{ServerName: Domains[0]})
		client.SetDeadline(time.Now().Add(time.Second))
		client.Handshake()
	}()
	var h [5]byte
	if _, e := io.ReadFull(b, h[:]); e != nil {
		t.Fatal(e)
	}
	body := make([]byte, binary.BigEndian.Uint16(h[3:]))
	io.ReadFull(b, body)
	host, e := SNI(body)
	if e != nil || host != Domains[0] {
		t.Fatalf("SNI: %q %v", host, e)
	}
	for n := 0; n < len(body); n++ {
		SNI(body[:n])
	}
}
func TestRejectMalformedDNS(t *testing.T) {
	for _, b := range [][]byte{nil, {}, bytes.Repeat([]byte{255}, 128)} {
		if _, e := DNSReply(b); e == nil {
			t.Fatal("invalid query accepted")
		}
	}
}
func TestProxyRejectsOtherPorts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go New(nil, func(string) {}).ServeProxy(ctx, l)
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(c, "CONNECT 127.0.0.1:22 HTTP/1.1\r\nHost: 127.0.0.1:22\r\n\r\n")
	line, e := bufio.NewReader(c).ReadString('\n')
	if e != nil || line != "HTTP/1.1 403 Forbidden\r\n" {
		t.Fatal(line, e)
	}
}
