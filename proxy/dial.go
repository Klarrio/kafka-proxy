package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

type DialerWithContext interface {
	DialWithContext(network, addr string, ctx *ConnectionContext) (c net.Conn, err error)
}

type directDialer struct {
	dialTimeout time.Duration
	keepAlive   time.Duration
}

func (d directDialer) DialWithContext(network, addr string, _ *ConnectionContext) (net.Conn, error) {
	dialer := net.Dialer{
		Timeout:   d.dialTimeout,
		KeepAlive: d.keepAlive,
	}
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	err = conn.SetDeadline(time.Now().Add(d.dialTimeout))
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, err
}

func (d directDialer) Dial(network, addr string) (net.Conn, error) {
	dialer := net.Dialer{
		Timeout:   d.dialTimeout,
		KeepAlive: d.keepAlive,
	}
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	err = conn.SetDeadline(time.Now().Add(d.dialTimeout))
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, err
}

type socks5Dialer struct {
	directDialer            directDialer
	proxyNetwork, proxyAddr string
	username, password      string
}

func (d socks5Dialer) DialWithContext(network, addr string, _ *ConnectionContext) (net.Conn, error) {
	if d.proxyNetwork == "" || d.proxyAddr == "" {
		return nil, errors.New("socks5 proxy network and addr must be not empty")
	}
	var auth *proxy.Auth
	if d.username != "" && d.password != "" {
		auth = &proxy.Auth{
			User:     d.username,
			Password: d.password,
		}
	}
	socks5Dialer, err := proxy.SOCKS5(d.proxyNetwork, d.proxyAddr, auth, d.directDialer)
	if err != nil {
		return nil, err
	}
	conn, err := socks5Dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type tlsDialer struct {
	timeout   time.Duration
	rawDialer DialerWithContext
	config    *tls.Config
	certStore CertStore
}

// see tls.DialWithDialer
func (d tlsDialer) DialWithContext(network, addr string, ctx *ConnectionContext) (net.Conn, error) {
	if d.config == nil {
		return nil, errors.New("tlsConfig must not be nil")
	}
	if d.rawDialer == nil {
		return nil, errors.New("rawDialer must not be nil")
	}
	if ctx == nil {
		return nil, errors.New("ctx must not be nil")
	}
	if ctx.clientID == nil || *ctx.clientID == "" {
		return nil, errors.New("clientID must not be nil or empty")
	}

	config, err := d.getTLSConfig(addr, ctx)
	if err != nil {
		return nil, err
	}

	timeout := d.timeout

	var errChannel chan error

	if timeout != 0 {
		errChannel = make(chan error, 2)
		timer := time.AfterFunc(timeout, func() {
			errChannel <- errors.Errorf("Handshake timeout to %s after %v", addr, timeout)
		})
		defer timer.Stop()
	}

	rawConn, err := d.rawDialer.DialWithContext(network, addr, ctx)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(rawConn, config)

	if timeout == 0 {
		err = conn.Handshake()
	} else {
		go func() {
			errChannel <- conn.Handshake()
		}()

		err = <-errChannel
	}

	if err != nil {
		rawConn.Close()
		return nil, err
	}

	return conn, nil
}

func (d tlsDialer) getTLSConfig(addr string, ctx *ConnectionContext) (*tls.Config, error) {
	if d.certStore == nil {
		return nil, errors.New("certStore must not be nil")
	}

	var config = d.config

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	} 
	hostname := addr[:colonPos]
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := config.Clone()
		c.ServerName = hostname
		config = c
	}

	// Look up the certificate for the clientID
	if cert, ok := d.certStore.Get(*ctx.clientID); ok {
		logrus.Debugf("Using certificate %s for %s", &cert.Leaf.Subject, *ctx.clientID)
		c := config.Clone()
		c.Certificates = []tls.Certificate{cert}
		config = c
	} else {	
		return nil, errors.Errorf("No certificate found for %s", *ctx.clientID)
	}

	return config, nil
}

type httpProxy struct {
	forwardDialer      DialerWithContext
	network            string
	hostPort           string
	username, password string
}

func (s *httpProxy) DialWithContext(network, addr string, ctx *ConnectionContext) (net.Conn, error) {
	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("CONNECT", reqURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Close = false
	if s.username != "" && s.password != "" {
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.username+":"+s.password))
		req.Header.Set("Proxy-Authorization", basic)
	}

	c, err := s.forwardDialer.DialWithContext(s.network, s.hostPort, ctx)
	if err != nil {
		return nil, err
	}
	err = req.Write(c)
	if err != nil {
		c.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		c.Close()
		return nil, fmt.Errorf("connect server using proxy error, statuscode [%d]", resp.StatusCode)
	}

	return c, nil
}
