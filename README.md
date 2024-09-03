[![Code Coverage](https://img.shields.io/codecov/c/github/AdguardTeam/gomitmproxy/master.svg)](https://codecov.io/github/AdguardTeam/gomitmproxy?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/Grizz1ya/gomitmproxy)](https://goreportcard.com/report/AdguardTeam/gomitmproxy)
[![GolangCI](https://golangci.com/badges/github.com/Grizz1ya/gomitmproxy.svg)](https://golangci.com/r/github.com/Grizz1ya/gomitmproxy)
[![Go Doc](https://godoc.org/github.com/Grizz1ya/gomitmproxy?status.svg)](https://godoc.org/github.com/Grizz1ya/gomitmproxy)

# gomitmproxy

This is a customizable HTTP proxy with TLS interception support.
It was created as a part of [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome).
However, it can be used for different purposes so we decided to make it a separate project.

## Features

- HTTP proxy
- HTTP over TLS (HTTPS) proxy
- Proxy authorization
- TLS termination

## How to use gomitmproxy

### Simple HTTP proxy

```go
package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Grizz1ya/gomitmproxy"
)

func main() {
	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: &net.TCPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: 8080,
		},
	})
	err := proxy.Start()
	if err != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Clean up
	proxy.Close()
}
```

### Modifying requests and responses

You can modify requests and responses using `OnRequest` and `OnResponse` handlers.

The example below will block requests to `example.net` and add a short comment to
the end of every HTML response.

```go
proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
    ListenAddr: &net.TCPAddr{
        IP:   net.IPv4(0, 0, 0, 0),
        Port: 8080,
    },
    OnRequest: func(session *gomitmproxy.Session) (request *http.Request, response *http.Response) {
        req := session.Request()

        log.Printf("onRequest: %s %s", req.Method, req.URL.String())

        if req.URL.Host == "example.net" {
            body := strings.NewReader("<html><body><h1>Replaced response</h1></body></html>")
            res := proxyutil.NewResponse(http.StatusOK, body, req)
            res.Header.Set("Content-Type", "text/html")

            // Use session props to pass the information about request being blocked
            session.SetProp("blocked", true)
            return nil, res
        }

        return nil, nil
    },
    OnResponse: func(session *gomitmproxy.Session) *http.Response {
        log.Printf("onResponse: %s", session.Request().URL.String())

        if _, ok := session.GetProp("blocked"); ok {
            log.Printf("onResponse: was blocked")
        }

        res := session.Response()
        req := session.Request()

        if strings.Index(res.Header.Get("Content-Type"), "text/html") != 0 {
            // Do nothing with non-HTML responses
            return nil
        }

        b, err := proxyutil.ReadDecompressedBody(res)
        // Close the original body
        _ = res.Body.Close()
        if err != nil {
            return proxyutil.NewErrorResponse(req, err)
        }

        // Use latin1 before modifying the body
        // Using this 1-byte encoding will let us preserve all original characters
        // regardless of what exactly is the encoding
        body, err := proxyutil.DecodeLatin1(bytes.NewReader(b))
        if err != nil {
            return proxyutil.NewErrorResponse(session.Request(), err)
        }

        // Modifying the original body
        modifiedBody, err := proxyutil.EncodeLatin1(body + "<!-- EDITED -->")
        if err != nil {
            return proxyutil.NewErrorResponse(session.Request(), err)
        }

        res.Body = ioutil.NopCloser(bytes.NewReader(modifiedBody))
        res.Header.Del("Content-Encoding")
        res.ContentLength = int64(len(modifiedBody))
        return res
    },
})
```

### Proxy authorization

If you want to protect your proxy with Basic authentication, set `Username` and `Password`
fields in the proxy configuration.

```go
proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
    ListenAddr: &net.TCPAddr{
        IP:   net.IPv4(0, 0, 0, 0),
        Port: 8080,
    },
    Username: "user",
    Password: "pass",
})
```

### HTTP over TLS (HTTPS) proxy

If you want to protect yourself from eavesdropping on your traffic to proxy, you can configure
it to work over a TLS tunnel. This is really simple to do, just set a `*tls.Config` instance
in your proxy configuration.

```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{*proxyCert},
}
proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
    ListenAddr: addr,
    TLSConfig:  tlsConfig,
})
```

### TLS interception

If you want to do TLS termination, you first need to prepare a self-signed certificate
that will be used as a certificates authority. Use the following `openssl` commands to do this.

```bash
openssl genrsa -out demo.key 2048
openssl req -new -x509 -key demo.key -out demo.crt -days 3650 -addext subjectAltName=DNS:<hostname>,IP:<ip>
```

Now you can use it to initialize `MITMConfig`:

```go
tlsCert, err := tls.LoadX509KeyPair("demo.crt", "demo.key")
if err != nil {
    log.Fatal(err)
}
privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
if err != nil {
    log.Fatal(err)
}

mitmConfig, err := mitm.NewConfig(x509c, privateKey, nil)
if err != nil {
    log.Fatal(err)
}

mitmConfig.SetValidity(time.Hour * 24 * 7) // generate certs valid for 7 days
mitmConfig.SetOrganization("gomitmproxy")  // cert organization
```

Please note that you can set `MITMExceptions` to a list of hostnames,
which will be excluded from TLS interception.

```go
proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
    ListenAddr: &net.TCPAddr{
        IP:   net.IPv4(0, 0, 0, 0),
        Port: 3333,
    },
    MITMConfig:     mitmConfig,
    MITMExceptions: []string{"example.com"},
})
```

If you configure the `APIHost`, you'll be able to download the CA certificate
from `http://[APIHost]/cert.crt` when the proxy is configured.

```go
// Navigate to http://gomitmproxy/cert.crt to download the CA certificate
proxy.APIHost = "gomitmproxy"
```

### Custom certs storage

By default, `gomitmproxy` uses an in-memory map-based storage for the certificates,
generated while doing TLS interception. It is often necessary to use a different kind
of certificates storage. If this is your case, you can supply your own implementation
of the `CertsStorage` interface.

```go
// CustomCertsStorage - an example of a custom cert storage
type CustomCertsStorage struct {
	certsCache map[string]*tls.Certificate // cache with the generated certificates
}

// Get gets the certificate from the storage
func (c *CustomCertsStorage) Get(key string) (*tls.Certificate, bool) {
	v, ok := c.certsCache[key]
	return v, ok
}

// Set saves the certificate to the storage
func (c *CustomCertsStorage) Set(key string, cert *tls.Certificate) {
	c.certsCache[key] = cert
}
```

Then pass it to the `NewConfig` function.

```go
mitmConfig, err := mitm.NewConfig(x509c, privateKey, &CustomCertsStorage{
    certsCache: map[string]*tls.Certificate{}},
)
```

## Notable alternatives

- [martian](https://github.com/google/martian) - an awesome debugging proxy with TLS interception support.
- [goproxy](https://github.com/elazarl/goproxy) - also supports TLS interception and requests.

## TODO

- [x] Basic HTTP proxy without MITM
- [ ] Proxy
  - [x] Expose APIs for the library users
  - [x] How-to doc
  - [x] Travis configuration
  - [x] Proxy-Authorization
  - [x] WebSockets support (see [this](https://github.com/google/martian/issues/31))
  - [x] `certsCache` -- allow custom implementations
  - [x] Support HTTP CONNECT over TLS
  - [x] Test plain HTTP requests inside HTTP CONNECT
  - [x] Test memory leaks
  - [x] Editing response body in a callback
  - [x] Handle unknown content-encoding values
  - [x] Handle CONNECT to APIHost properly (without trying to actually connect anywhere)
  - [x] Allow hijacking connections (!)
  - [x] Multiple listeners
  - [ ] Unit tests
  - [ ] Check & fix TODOs
  - [ ] Allow specifying net.Dialer
  - [ ] Specify timeouts for http.Transport
- [ ] MITM
  - [x] Basic MITM
  - [x] MITM exceptions
  - [x] Handle invalid server certificates properly (not just reset connections)
  - [x] Pass the most important tests on badssl.com/dashboard
  - [x] Handle certificate authentication
  - [ ] Allow configuring minimum supported TLS version
  - [ ] OCSP check (see [example](https://stackoverflow.com/questions/46626963/golang-sending-ocsp-request-returns))
  - [ ] (?) HPKP (see [example](https://github.com/tam7t/hpkp))
  - [ ] (?) CT logs (see [example](https://github.com/google/certificate-transparency-go))
  - [ ] (?) CRLSets (see [example](https://github.com/agl/crlset-tools))
