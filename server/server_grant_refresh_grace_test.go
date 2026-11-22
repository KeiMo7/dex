package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/server/tokens"
	"github.com/dexidp/dex/storage"
)

// httpRefreshResult is one goroutine's outcome in the concurrency pressure test.
type httpRefreshResult struct {
	status int
	body   string
}

// newGraceTestServer builds an in-memory server whose clock and refresh policy
// share one controllable time, with a rotation grace period of grace.
func newGraceTestServer(t *testing.T, clk *mutableServerClock, grace time.Duration) *Server {
	t.Helper()
	httpServer, s := newTestServer(t, func(c *Config) {
		c.PasswordConnector = "local"
		c.Now = clk.now
		c.RefreshTokenPolicy = tokens.NewRefreshStrategy(true, 0, 0, grace, clk.now)
	})
	t.Cleanup(httpServer.Close)
	return s
}

type mutableServerClock struct{ t time.Time }

func (m *mutableServerClock) now() time.Time { return m.t }

func postRefresh(t *testing.T, s *Server, refreshToken string) httpRefreshResult {
	t.Helper()
	u, err := url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "/token")

	v := url.Values{}
	v.Add("grant_type", "refresh_token")
	v.Add("refresh_token", refreshToken)

	req, _ := http.NewRequest("POST", u.String(), bytes.NewBufferString(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test", "barfoo")

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return httpRefreshResult{status: rr.Code, body: rr.Body.String()}
}

func introspect(t *testing.T, s *Server, token string) map[string]any {
	t.Helper()
	u, err := url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "/token/introspect")

	v := url.Values{}
	v.Add("token", token)
	req, _ := http.NewRequest("POST", u.String(), bytes.NewBufferString(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test", "barfoo")

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "introspection failed: %s", rr.Body.String())
	var out map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	return out
}

// TestRefreshGracePeriodHTTPConcurrencyAndReplay is the end-to-end acceptance
// test over the real HTTP token endpoint. It drives one password grant, an
// initial rotation, then:
//   - a burst of N concurrent refreshes with the same obsolete token inside the
//     grace window (exactly one 200, N-1 distinct already-used rejections);
//   - a replay past the window that revokes the whole family;
//   - introspection proving an access token minted before the replay is now
//     inactive even though its own lifetime has not elapsed.
func TestRefreshGracePeriodHTTPConcurrencyAndReplay(t *testing.T) {
	ctx := context.Background()
	clk := &mutableServerClock{t: time.Now().UTC()}
	const grace = 30 * time.Second
	s := newGraceTestServer(t, clk, grace)
	seedLocalPasswordDB(t, s)

	first := doPasswordGrant(t, s)

	// Age the stored row so the first refresh actually rotates rather than
	// no-opping inside the freshly-created row's reuse window.
	var firstTok internal.RefreshToken
	require.NoError(t, internal.Unmarshal(first, &firstTok))
	require.NoError(t, s.storage.UpdateRefreshToken(ctx, firstTok.RefreshId, func(r storage.RefreshToken) (storage.RefreshToken, error) {
		r.LastUsed = clk.t.Add(-(grace + time.Second))
		return r, nil
	}))

	// The first rotation produces a new refresh token; the original becomes the
	// obsolete, grace-windowed secret.
	rotated := postRefresh(t, s, first)
	require.Equal(t, http.StatusOK, rotated.status, "initial rotation failed: %s", rotated.body)
	var rotatedResp tokenResponse
	require.NoError(t, json.Unmarshal([]byte(rotated.body), &rotatedResp))
	require.NotEqual(t, first, rotatedResp.RefreshToken)

	// The access token returned here belongs to the family and must be reachable
	// by the later revocation.
	accessToken := rotatedResp.AccessToken
	require.NotEmpty(t, accessToken)
	before := introspect(t, s, accessToken)
	require.Equal(t, true, before["active"], "access token starts active")

	// Burst: N concurrent refreshes all present the same pre-rotation token.
	const n = 50
	results := make([]httpRefreshResult, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = postRefresh(t, s, first)
		}(i)
	}
	close(start)
	wg.Wait()

	var ok, alreadyUsed, other int
	for _, r := range results {
		switch r.status {
		case http.StatusOK:
			ok++
		case http.StatusBadRequest:
			if bytes.Contains([]byte(r.body), []byte("already been used")) {
				alreadyUsed++
			} else {
				other++
			}
		default:
			other++
		}
	}
	require.Equal(t, 1, ok, "exactly one concurrent in-grace refresh must succeed")
	require.Equal(t, n-1, alreadyUsed, "the rest must be told the token was already used")
	require.Equal(t, 0, other, "no racer may hit an unrelated status")

	// Advance the wall clock past the grace period and replay the original
	// obsolete token again. The whole family must be revoked.
	clk.t = clk.t.Add(grace + time.Second)
	replay := postRefresh(t, s, first)
	require.Equal(t, http.StatusBadRequest, replay.status)
	require.Contains(t, replay.body, "replay detected")

	// Every refresh token in the family is now refused.
	for _, raw := range []string{first, rotatedResp.RefreshToken} {
		r := postRefresh(t, s, raw)
		require.Equal(t, http.StatusBadRequest, r.status, "a revoked family token must not refresh: %s", r.body)
	}

	// The access token minted before the replay introspects as inactive despite
	// its own expiry being well in the future.
	after := introspect(t, s, accessToken)
	require.Equal(t, false, after["active"], "family revocation must propagate to the access token")
}
