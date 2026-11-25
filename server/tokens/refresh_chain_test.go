package tokens

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func newChainTestStore(t *testing.T) (storage.Storage, *RefreshStore, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	store := memory.New(logger)
	now := time.Now().UTC()
	rt := NewRefreshStore(store, func() time.Time { return now }, logger)
	return store, rt, &logs
}

func seedChainRefresh(t *testing.T, ctx context.Context, store storage.Storage, secret string, now time.Time) {
	t.Helper()
	require.NoError(t, store.CreateRefresh(ctx, storage.RefreshToken{
		ID: "r1", Token: secret, ClientID: "client-1", ConnectorID: "mock",
		Claims:    storage.Claims{UserID: "u1", Username: "alice"},
		CreatedAt: now, LastUsed: now,
	}))
	require.NoError(t, store.CreateOfflineSessions(ctx, storage.OfflineSessions{
		UserID: "u1", ConnID: "mock",
		Refresh: map[string]*storage.RefreshTokenRef{"client-1": {ID: "r1", ClientID: "client-1"}},
	}))
}

func rotateChainSecret(t *testing.T, ctx context.Context, store storage.Storage, rt *RefreshStore, strategy *RefreshStrategy, secret string) string {
	t.Helper()
	stored, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)
	raw, _, err := rt.Rotate(ctx, &stored, &internal.RefreshToken{RefreshId: "r1", Token: secret}, strategy, func(context.Context) (connector.Identity, error) {
		return connector.Identity{UserID: "u1", Username: "bob"}, nil
	})
	require.NoError(t, err)
	var tok internal.RefreshToken
	require.NoError(t, internal.Unmarshal(raw, &tok))
	return tok.Token
}

func TestRefreshChainReplayRevokesWholeChainAndAuditsOnce(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store, rt, logs := newChainTestStore(t)
	seedChainRefresh(t, ctx, store, "g1", now)
	strategy := NewRefreshStrategy(true, 0, 0, 0, func() time.Time { return now })

	g2 := rotateChainSecret(t, ctx, store, rt, strategy, "g1")
	g3 := rotateChainSecret(t, ctx, store, rt, strategy, g2)
	g4 := rotateChainSecret(t, ctx, store, rt, strategy, g3)

	stored, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)
	require.Equal(t, int64(4), stored.Generation)
	require.Len(t, stored.Chain.Generations, 4)

	replayStored := stored
	_, _, err = rt.Rotate(ctx, &replayStored, &internal.RefreshToken{RefreshId: "r1", Token: "g1"}, strategy, func(context.Context) (connector.Identity, error) {
		t.Fatal("identity must not resolve for replay")
		return connector.Identity{}, nil
	})
	require.ErrorIs(t, err, ErrRefreshTokenReplayed)

	after, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err, "revocation retains the chain record for management/audit")
	require.True(t, after.Chain.IsRevoked())
	require.Equal(t, storage.RefreshChainReasonReplay, after.Chain.Reason)
	require.NotZero(t, after.Chain.RevokedAt)

	for _, secret := range []string{"g1", g2, g3, g4} {
		current, gerr := store.GetRefresh(ctx, "r1")
		require.NoError(t, gerr)
		_, _, rerr := rt.Rotate(ctx, &current, &internal.RefreshToken{RefreshId: "r1", Token: secret}, strategy, func(context.Context) (connector.Identity, error) {
			t.Fatal("identity must not resolve after chain revocation")
			return connector.Identity{}, nil
		})
		require.ErrorIs(t, rerr, ErrRefreshChainRevoked, "secret %q must be rejected", secret)
	}

	replayEvents := 0
	revokeEvents := 0
	for _, line := range bytes.Split(logs.Bytes(), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal(line, &record))
		switch record["event"] {
		case AuditEventReplay:
			replayEvents++
			require.Equal(t, after.ChainID, record["chain_id"])
			require.Equal(t, "client-1", record["client_id"])
			require.Equal(t, "u1", record["user_id"])
			require.Equal(t, "mock", record["connector_id"])
			require.EqualValues(t, 1, record["generation"])
			require.NotEmpty(t, record["source"])
		case AuditEventChainRevoked:
			revokeEvents++
		}
	}
	require.Equal(t, 1, replayEvents, "exactly one replay audit event: %s", logs.String())
	require.GreaterOrEqual(t, revokeEvents, 1)
	for _, sensitive := range []string{"g1", g2, g3, g4} {
		require.NotContains(t, logs.String(), sensitive)
	}

	chain, err := rt.GetRefreshChain(ctx, after.ChainID)
	require.NoError(t, err)
	require.Equal(t, storage.RefreshChainStatusRevoked, chain.Status)
}

func TestRefreshChainIdempotentWindowConcurrentSingleUpstream(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store, rt, _ := newChainTestStore(t)
	// Age LastUsed outside the window so one caller performs the initial
	// generation advance; after the claim it becomes current and concurrent
	// duplicates observe the idempotency window.
	seedChainRefresh(t, ctx, store, "g1", now.Add(-2*time.Minute))
	strategy := NewRefreshStrategy(true, 0, 0, time.Minute, func() time.Time { return now })

	stored, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)

	const n = 32
	var wg sync.WaitGroup
	raws := make(chan string, n)
	errs := make(chan error, n)
	var resolutions int32
	var resolutionMu sync.Mutex
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			raw, _, rerr := rt.Rotate(ctx, &stored, &internal.RefreshToken{RefreshId: "r1", Token: "g1"}, strategy, func(context.Context) (connector.Identity, error) {
				resolutionMu.Lock()
				resolutions++
				resolutionMu.Unlock()
				return connector.Identity{UserID: "u1"}, nil
			})
			if rerr != nil {
				errs <- rerr
				return
			}
			raws <- raw
		}()
	}
	close(start)
	wg.Wait()
	close(raws)
	close(errs)

	for rerr := range errs {
		require.NoError(t, rerr)
	}
	var first string
	count := 0
	for raw := range raws {
		count++
		if first == "" {
			first = raw
		}
		require.Equal(t, first, raw, "all in-window callers must receive the same new generation")
	}
	require.Equal(t, n, count)
	resolutionMu.Lock()
	defer resolutionMu.Unlock()
	require.Equal(t, int32(1), resolutions)

	after, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)
	require.Equal(t, int64(2), after.Generation)
}

func TestRefreshChainWithoutWindowConcurrentLoserSuperseded(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store, rt, _ := newChainTestStore(t)
	seedChainRefresh(t, ctx, store, "g1", now)
	strategy := NewRefreshStrategy(true, 0, 0, 0, func() time.Time { return now })
	stored, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)

	const n = 16
	var wg sync.WaitGroup
	var success, superseded int32
	var mu sync.Mutex
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, rerr := rt.Rotate(ctx, &stored, &internal.RefreshToken{RefreshId: "r1", Token: "g1"}, strategy, func(context.Context) (connector.Identity, error) {
				return connector.Identity{UserID: "u1"}, nil
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case rerr == nil:
				success++
			case errors.Is(rerr, ErrRefreshTokenSuperseded):
				superseded++
			default:
				t.Errorf("unexpected concurrent rotation error: %v", rerr)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.Equal(t, int32(1), success)
	require.Equal(t, int32(n-1), superseded)
}

func TestRefreshChainLegacyRowAdoptsSingleMemberChain(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store, rt, _ := newChainTestStore(t)
	seedChainRefresh(t, ctx, store, "legacy-secret", now)
	// Simulate a pre-chain row.
	require.NoError(t, store.UpdateRefreshToken(ctx, "r1", func(old storage.RefreshToken) (storage.RefreshToken, error) {
		old.ChainID, old.Generation, old.Chain = "", 0, nil
		return old, nil
	}))
	strategy := NewRefreshStrategy(true, 0, 0, 0, func() time.Time { return now })
	newSecret := rotateChainSecret(t, ctx, store, rt, strategy, "legacy-secret")

	after, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)
	require.NotEmpty(t, after.ChainID)
	require.Equal(t, after.ChainID, after.Chain.ID)
	require.Equal(t, int64(2), after.Generation)
	require.Equal(t, []int64{1, 2}, []int64{after.Chain.Generations[0].Number, after.Chain.Generations[1].Number})
	require.Equal(t, hashGenerationSecret("legacy-secret"), after.Chain.Generations[0].SecretHash)
	require.Equal(t, hashGenerationSecret(newSecret), after.Chain.Generations[1].SecretHash)
}

func TestRefreshChainExpiryDoesNotClassifyAsReplay(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store, rt, logs := newChainTestStore(t)
	seedChainRefresh(t, ctx, store, "g1", now.Add(-2*time.Hour))
	strategy := NewRefreshStrategy(true, time.Hour, 0, 0, func() time.Time { return now })

	stored, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)
	_, err = LookupRefreshToken(ctx, store, strategy, rt.logger, nil, &internal.RefreshToken{RefreshId: "r1", Token: "g1"})
	require.ErrorIs(t, err, ErrRefreshTokenExpired)
	require.False(t, stored.Chain.IsRevoked())
	require.NotContains(t, logs.String(), AuditEventReplay)
}

func TestRefreshChainDisabledRotationKeepsGenerationButAllowsRevocation(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store, rt, _ := newChainTestStore(t)
	seedChainRefresh(t, ctx, store, "same-secret", now.Add(-time.Hour))
	strategy := NewRefreshStrategy(false, 0, 0, 0, func() time.Time { return now })

	stored, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)
	raw, _, err := rt.Rotate(ctx, &stored, &internal.RefreshToken{RefreshId: "r1", Token: "same-secret"}, strategy, func(context.Context) (connector.Identity, error) {
		return connector.Identity{UserID: "u1"}, nil
	})
	require.NoError(t, err)
	var tok internal.RefreshToken
	require.NoError(t, internal.Unmarshal(raw, &tok))
	require.Equal(t, "same-secret", tok.Token)
	after, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)
	require.Equal(t, int64(1), after.Generation)

	chainID := after.ChainID
	if chainID == "" {
		chainID = after.Chain.ID
	}
	_, _, err = rt.RevokeRefreshChain(ctx, chainID, storage.RefreshChainSourceAdminAPI, "")
	require.NoError(t, err)
	current, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)
	_, _, err = rt.Rotate(ctx, &current, &internal.RefreshToken{RefreshId: "r1", Token: "same-secret"}, strategy, func(context.Context) (connector.Identity, error) {
		t.Fatal("must not resolve after revocation")
		return connector.Identity{}, nil
	})
	require.ErrorIs(t, err, ErrRefreshChainRevoked)
}

func TestRefreshChainBulkRevokesUnadoptedLegacyRows(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store, rt, _ := newChainTestStore(t)
	seedChainRefresh(t, ctx, store, "legacy", now)
	require.NoError(t, store.UpdateRefreshToken(ctx, "r1", func(old storage.RefreshToken) (storage.RefreshToken, error) {
		old.ChainID, old.Generation, old.Chain = "", 0, nil
		return old, nil
	}))

	ids, err := rt.RevokeRefreshChainsByUser(ctx, "u1", "mock", "")
	require.NoError(t, err)
	require.Len(t, ids, 1)
	stored, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)
	require.True(t, stored.Chain.IsRevoked())

	// A repeated bulk revocation is successful/idempotent.
	_, err = rt.RevokeRefreshChainsByUser(ctx, "u1", "mock", "")
	require.NoError(t, err)
}

func TestRefreshChainAdminRevocationIdempotent(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store, rt, _ := newChainTestStore(t)
	seedChainRefresh(t, ctx, store, "g1", now)
	stored, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)
	stored = normalizeRefreshChain(stored, now)
	require.NoError(t, store.UpdateRefreshToken(ctx, "r1", func(old storage.RefreshToken) (storage.RefreshToken, error) {
		return normalizeRefreshChain(old, now), nil
	}))
	stored, _ = store.GetRefresh(ctx, "r1")

	chain, changed, err := rt.RevokeRefreshChain(ctx, stored.ChainID, storage.RefreshChainSourceAdminAPI, "")
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, storage.RefreshChainStatusRevoked, chain.Status)
	again, changed, err := rt.RevokeRefreshChain(ctx, stored.ChainID, storage.RefreshChainSourceAdminAPI, "")
	require.NoError(t, err, "repeat revocation is idempotent")
	require.False(t, changed)
	require.Equal(t, chain.RevokedAt, again.RevokedAt)

	_, err = rt.RevokeRefreshChainsByUser(ctx, "u1", "mock", "")
	require.NoError(t, err)
}
