package conformance

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
)

func testRefreshTokenChainPersistence(t *testing.T, s storage.Storage) {
	ctx := t.Context()
	now := time.Now().UTC().Round(time.Millisecond)
	token := storage.RefreshToken{
		ID:          "refresh-chain-persistence",
		Token:       "current-secret",
		ChainID:     "chain-persistence",
		Generation:  2,
		ClientID:    "client",
		ConnectorID: "connector",
		Claims:      storage.Claims{UserID: "user"},
		CreatedAt:   now,
		LastUsed:    now,
		Chain: &storage.RefreshChain{
			ID:                "chain-persistence",
			UserID:            "user",
			ClientID:          "client",
			ConnectorID:       "connector",
			CurrentGeneration: 2,
			Status:            storage.RefreshChainStatusActive,
			CreatedAt:         now,
			UpdatedAt:         now,
			Generations: []storage.RefreshGeneration{
				{ChainID: "chain-persistence", Number: 1, SecretHash: "sha256:old", IssuedAt: now, Status: storage.RefreshGenerationStatusRotated, Reason: "rotated"},
				{ChainID: "chain-persistence", Number: 2, SecretHash: "sha256:current", IssuedAt: now, Status: storage.RefreshGenerationStatusCurrent},
			},
		},
	}
	require.NoError(t, s.CreateRefresh(ctx, token))
	got, err := s.GetRefresh(ctx, token.ID)
	require.NoError(t, err)
	require.Equal(t, token.ChainID, got.ChainID)
	require.Equal(t, token.Generation, got.Generation)
	require.NotNil(t, got.Chain)
	require.Equal(t, token.Chain.ID, got.Chain.ID)
	require.Equal(t, token.Chain.Status, got.Chain.Status)
	require.Len(t, got.Chain.Generations, 2)
	require.Equal(t, int64(1), got.Chain.Generations[0].Number)
	require.Equal(t, storage.RefreshGenerationStatusRotated, got.Chain.Generations[0].Status)
	require.Equal(t, "sha256:current", got.Chain.Generations[1].SecretHash)

	require.NoError(t, s.UpdateRefreshToken(ctx, token.ID, func(old storage.RefreshToken) (storage.RefreshToken, error) {
		old.Chain.Status = storage.RefreshChainStatusRevoked
		old.Chain.Reason = storage.RefreshChainReasonReplay
		old.Chain.RevokedAt = now.Add(time.Second)
		return old, nil
	}))
	revoked, err := s.GetRefresh(ctx, token.ID)
	require.NoError(t, err)
	require.True(t, revoked.Chain.IsRevoked())
	require.Equal(t, storage.RefreshChainReasonReplay, revoked.Chain.Reason)
}

func testRefreshTokenGenerationCAS(t *testing.T, s storage.Storage) {
	ctx := t.Context()
	now := time.Now().UTC().Round(time.Millisecond)
	base := storage.RefreshToken{
		ID:          "refresh-generation-cas",
		Token:       "generation-1-secret",
		ChainID:     "chain-cas",
		Generation:  1,
		ClientID:    "client",
		ConnectorID: "connector",
		Scopes:      []string{"openid"},
		CreatedAt:   now,
		LastUsed:    now,
		Claims:      storage.Claims{UserID: "user"},
		Chain:       &storage.RefreshChain{ID: "chain-cas", CurrentGeneration: 1, Status: storage.RefreshChainStatusActive},
	}
	require.NoError(t, s.CreateRefresh(ctx, base))

	// A wrong premise must not write and must report the live row.
	wrong := base
	wrong.Generation = 99
	wrong.Token = "must-not-win"
	current, swapped, err := s.CompareAndSwapRefreshTokenGeneration(ctx, base.ID, 99, wrong)
	require.NoError(t, err)
	require.False(t, swapped)
	require.Equal(t, int64(1), current.Generation)
	require.Equal(t, "generation-1-secret", current.Token)

	const n = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	conflicts := 0
	errs := make([]error, 0)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			next := base
			next.Generation = 2
			next.Token = fmt.Sprintf("generation-2-secret-%02d", i)
			_, didSwap, casErr := s.CompareAndSwapRefreshTokenGeneration(ctx, base.ID, 1, next)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case casErr != nil:
				errs = append(errs, casErr)
			case didSwap:
				wins++
			default:
				conflicts++
			}
		}(i)
	}
	close(start)
	wg.Wait()

	require.Empty(t, errs, "CAS conflicts must be reported as swapped=false, not storage errors: %v", errs)
	require.Equal(t, 1, wins, "exactly one writer must pass the generation premise")
	require.Equal(t, n-1, conflicts)

	stored, err := s.GetRefresh(ctx, base.ID)
	require.NoError(t, err)
	require.Equal(t, int64(2), stored.Generation)
	require.Regexp(t, `^generation-2-secret-\d{2}$`, stored.Token)

	// Once generation two is committed, another generation-one CAS cannot win.
	stale := stored
	stale.Token = "stale-writer"
	_, swapped, err = s.CompareAndSwapRefreshTokenGeneration(ctx, base.ID, 1, stale)
	require.NoError(t, err)
	require.False(t, swapped)
	again, err := s.GetRefresh(ctx, base.ID)
	require.NoError(t, err)
	require.Equal(t, stored.Token, again.Token)
}
