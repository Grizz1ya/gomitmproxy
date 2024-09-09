package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/AdguardTeam/golibs/log"
	"github.com/Grizz1ya/gomitmproxy"
	"github.com/Grizz1ya/gomitmproxy/mitm"
	"github.com/Grizz1ya/gomitmproxy/proxyutil"

	_ "net/http/pprof"
)

var proxy *gomitmproxy.Proxy 

func main() {
	log.SetLevel(log.INFO)

	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:6060", nil))
	// }()

	// Read the MITM cert and key.
	tlsCert, err := tls.LoadX509KeyPair("demo.crt", "demo.key")
	if err != nil {
		log.Fatal(err)
	}
	privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	mitmConfig, err := mitm.NewConfig(x509c, privateKey, &CustomCertsStorage{
		certsCache: map[string]*tls.Certificate{}},
	)

	if err != nil {
		log.Fatal(err)
	}

	// // Generate certs valid for 7 days.
	// mitmConfig.SetValidity(time.Hour * 24 * 7)
	// // Set certs organization.
	// mitmConfig.SetOrganization("gomitmproxy")

	// // Generate a cert-key pair for the HTTP-over-TLS proxy.
	// proxyCert, err := mitmConfig.GetOrCreateCert("127.0.0.1")
	// if err != nil {
	// 	panic(err)
	// }
	// tlsConfig := &tls.Config{
	// 	Certificates: []tls.Certificate{*proxyCert},
	// }

	// Prepare the proxy.
	addr := &net.TCPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 3333,
	}

	proxy = gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: addr,
		// TLSConfig:  tlsConfig,

		Credentials: make(map[string]string),
		// APIHost:  "gomitmproxy",

		MITMConfig:     mitmConfig,
		// MITMExceptions: []string{"example.com"},

		OnRequest:  onRequest,
		// OnResponse: onResponse,
		// OnConnect:  onConnect,
	})

	err = proxy.Start()
	if err != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Stop the proxy.
	proxy.Close()
}

func onRequest(session *gomitmproxy.Session) (*http.Request, *http.Response) {
	req := session.Request()

	log.Printf("onRequest: %s %s", req.Method, req.URL.String())
	username, ok := session.Ctx().GetProp("username")
	if !ok {
		log.Error("username not found")

		// body := strings.NewReader("<html><body><h1>username not found</h1></body></html>")
		// res := proxyutil.NewResponse(http.StatusProxyAuthRequired, body, req)
		// // See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authenticate.
		// res.Header.Set("Proxy-Authenticate", "Basic")
		// return nil, res
	} else {
		log.Printf("username: %s", username)
	}
	proxy.AddCredentials("test", "test")
	

	if req.URL.Host == "example.net" {
		body := strings.NewReader("<html><body><h1>Replaced response</h1></body></html>")
		res := proxyutil.NewResponse(http.StatusOK, body, req)
		res.Header.Set("Content-Type", "text/html")
		session.SetProp("blocked", true)
		return nil, res
	}

	if req.URL.Host == "testgomitmproxy" {
		body := strings.NewReader("<html><body><h1>Served by gomitmproxy</h1></body></html>")
		res := proxyutil.NewResponse(http.StatusOK, body, req)
		res.Header.Set("Content-Type", "text/html")
		return nil, res
	}

	return nil, nil
}

func onResponse(session *gomitmproxy.Session) *http.Response {
	log.Printf("onResponse: %s", session.Request().URL.String())

	if _, ok := session.GetProp("blocked"); ok {
		log.Printf("onResponse: was blocked")
		return nil
	}

	res := session.Response()
	req := session.Request()

	if strings.Index(res.Header.Get("Content-Type"), "text/html") != 0 {
		// Do nothing with non-HTML responses
		return nil
	}

	b, err := proxyutil.ReadDecompressedBody(res)
	// Close the original body.
	_ = res.Body.Close()
	if err != nil {
		return proxyutil.NewErrorResponse(req, err)
	}

	// Use latin1 before modifying the body. Using this 1-byte encoding will
	// let us preserve all original characters regardless of what exactly is
	// the encoding.
	body, err := proxyutil.DecodeLatin1(bytes.NewReader(b))
	if err != nil {
		return proxyutil.NewErrorResponse(session.Request(), err)
	}

	// Modifying the original body.
	modifiedBody, err := proxyutil.EncodeLatin1(body + "<!-- EDITED -->")
	if err != nil {
		return proxyutil.NewErrorResponse(session.Request(), err)
	}

	res.Body = io.NopCloser(bytes.NewReader(modifiedBody))
	res.Header.Del("Content-Encoding")
	res.ContentLength = int64(len(modifiedBody))

	return res
}

func onConnect(_ *gomitmproxy.Session, _ string, addr string) (conn net.Conn) {
	host, _, err := net.SplitHostPort(addr)

	if err == nil && host == "testgomitmproxy" {
		// Don't let it connecting there, we'll serve it by ourselves.
		return &proxyutil.NoopConn{}
	}

	return nil
}

// CustomCertsStorage is an example of a custom cert storage.
type CustomCertsStorage struct {
	// certsCache is a cache with the generated certificates.
	certsCache map[string]*tls.Certificate
}

// Get gets the certificate from the storage.
func (c *CustomCertsStorage) Get(key string) (cert *tls.Certificate, ok bool) {
	cert, ok = c.certsCache[key]

	return cert, ok
}

// Set saves the certificate to the storage.
func (c *CustomCertsStorage) Set(key string, cert *tls.Certificate) {
	c.certsCache[key] = cert
}
