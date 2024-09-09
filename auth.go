package gomitmproxy

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/Grizz1ya/gomitmproxy/proxyutil"
)

// basicAuth returns an HTTP authorization header value according to RFC2617.
// See 2 (end of page 4) https://www.ietf.org/rfc/rfc2617.txt:
// "To receive authorization, the client sends the userid and password,
// separated by a single colon (":") character, within a base64 encoded string
// in the credentials."
// It is not meant to be urlencoded.
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// parse username and password from the Authorization header
func parseBasicAuth(auth string) (username, password string, err error) {
	creds, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", err
	}

	parts := strings.SplitN(string(creds), ":", 2)
	if len(parts) != 2 {
		return "", "", nil
	}

	username = parts[0]
	password = parts[1]

	return username, password, nil
}

// newNotAuthorizedResponse creates a new "407 (Proxy Authentication Required)"
// response.
func newNotAuthorizedResponse(session *Session) *http.Response {
	res := proxyutil.NewResponse(http.StatusProxyAuthRequired, nil, session.req)

	// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authenticate.
	res.Header.Set("Proxy-Authenticate", "Basic")

	return res
}

// authorize checks the "Proxy-Authorization" header and returns true if the
// request is authorized. If it returns false, it also returns the response that
// should be written to the client.
func (p *Proxy) authorize(session *Session) (bool, *http.Response) {
	if session.ctx.parent != nil {
		// If we're here, it means the connection is authorized already.
		return true, nil
	}

	if len(p.Credentials) == 0 {
		return true, nil
	}

	// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization.
	proxyAuth := session.req.Header.Get("Proxy-Authorization")
	if strings.Index(proxyAuth, "Basic ") != 0 {
		return false, newNotAuthorizedResponse(session)
	}

	authHeader := proxyAuth[len("Basic "):]
	username, _, err := parseBasicAuth(authHeader)
	if err != nil {
		return false, newNotAuthorizedResponse(session)
	}

	if credPassword, ok := p.Credentials[username]; ok {
		if basicAuth(username, credPassword) != authHeader {
			return false, newNotAuthorizedResponse(session)
		}
	} else {
		return false, newNotAuthorizedResponse(session)
	}

	session.Ctx().SetProp("username", username)

	return true, nil
}
