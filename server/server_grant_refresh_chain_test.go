package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
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

func TestRefreshChainHTTPReplayRevokesAllGenerations(t *testing.T) {
	t0 := time.Now()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	httpServer, s := newTestServer(t, func(c *Config) {
		c.Logger = logger
		c.Now = func() time.Time { return t0 }
		c.RefreshTokenPolicy = tokens.NewRefreshStrategy(true, 0, 0, 0, func() time.Time { return t0 })
	})
	defer httpServer.Close()

	mockRefreshTokenTestStorage(t, s.storage, false)
	first, err := internal.Marshal(&internal.RefreshToken{RefreshId: "test", Token: "bar"})
	require.NoError(t, err)
	generations := []string{first}

	refreshOnce := func(refreshToken string) (int, string, map[string]any) {
		form := url.Values{}
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", refreshToken)
		reqURL, err := url.Parse(s.issuerURL.String())
		require.NoError(t, err)
		reqURL.Path = path.Join(reqURL.Path, "/token")
		req, reqErr := http.NewRequest(http.MethodPost, reqURL.String(), bytes.NewBufferString(form.Encode()))
		require.NoError(t, reqErr)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test", "barfoo")

		resp, doErr := http.DefaultClient.Do(req)
		require.NoError(t, doErr)
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		var decoded map[string]any
		_ = json.Unmarshal(body, &decoded)
		newRefresh, _ := decoded["refresh_token"].(string)
		return resp.StatusCode, newRefresh, decoded
	}

	for i := 0; i < 3; i++ {
		status, next, body := refreshOnce(generations[len(generations)-1])
		require.Equalf(t, http.StatusOK, status, "refresh %d failed: %v", i+1, body)
		require.NotEmpty(t, next)
		generations = append(generations, next)
	}

	status, _, body := refreshOnce(generations[0])
	require.Equal(t, http.StatusBadRequest, status, "first generation replay must be invalid_grant: %v", body)

	// Every other generation, including the last current one, is now dead.
	for i, tok := range generations {
		status, _, response := refreshOnce(tok)
		require.Equalf(t, http.StatusBadRequest, status, "generation %d must be revoked: %v", i, response)
	}

	var replayAudits int
	for _, line := range bytes.Split(logs.Bytes(), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal(line, &record))
		if record["event"] == tokens.AuditEventReplay {
			replayAudits++
			require.Equal(t, "replay", record["reason"])
			require.NotEmpty(t, record["chain_id"])
			require.Equal(t, "test", record["client_id"])
			require.Equal(t, "1", record["user_id"])
			require.Equal(t, "test", record["connector_id"])
			require.NotEmpty(t, record["source_ip"])
		}
	}
	require.Equal(t, 1, replayAudits, logs.String())
	for _, secret := range []string{"bar"} {
		require.NotContains(t, logs.String(), secret)
	}
}

func TestRefreshChainHTTPIdempotentWindowConcurrent(t *testing.T) {
	t0 := time.Now()
	httpServer, s := newTestServer(t, func(c *Config) {
		c.Now = func() time.Time { return t0 }
		c.RefreshTokenPolicy = tokens.NewRefreshStrategy(true, 0, 0, time.Minute, func() time.Time { return t0 })
	})
	defer httpServer.Close()
	mockRefreshTokenTestStorage(t, s.storage, false)
	require.NoError(t, s.storage.UpdateRefreshToken(t.Context(), "test", func(old storage.RefreshToken) (storage.RefreshToken, error) {
		old.LastUsed = t0.Add(-time.Hour)
		return old, nil
	}))

	raw, err := internal.Marshal(&internal.RefreshToken{RefreshId: "test", Token: "bar"})
	require.NoError(t, err)
	reqURL, err := url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	reqURL.Path = path.Join(reqURL.Path, "/token")

	const n = 24
	var wg sync.WaitGroup
	statuses := make(chan int, n)
	newTokens := make(chan string, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			form := url.Values{}
			form.Set("grant_type", "refresh_token")
			form.Set("refresh_token", raw)
			req, reqErr := http.NewRequest(http.MethodPost, reqURL.String(), bytes.NewBufferString(form.Encode()))
			if reqErr != nil {
				statuses <- http.StatusInternalServerError
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth("test", "barfoo")
			resp, doErr := http.DefaultClient.Do(req)
			if doErr != nil {
				statuses <- http.StatusInternalServerError
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			var decoded map[string]any
			_ = json.Unmarshal(body, &decoded)
			statuses <- resp.StatusCode
			if rt, ok := decoded["refresh_token"].(string); ok {
				newTokens <- rt
			}
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)
	close(newTokens)

	for status := range statuses {
		require.Equal(t, http.StatusOK, status)
	}
	var first string
	count := 0
	for rt := range newTokens {
		count++
		if first == "" {
			first = rt
		}
		require.Equal(t, first, rt)
	}
	require.Equal(t, n, count)
}
