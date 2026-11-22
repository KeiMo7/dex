package tokens

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

// newFamilyTestStore builds a store with a controllable clock.
func newFamilyTestStore(t *testing.T) (store storage.Storage, rt *RefreshStore, clk *mutableClock) {
	t.Helper()
	clk = newMutableClock(time.Now().UTC())
	logger := slog.New(slog.DiscardHandler)
	store = memory.New(logger)
	rt = NewRefreshStore(store, clk.now, logger)
	return store, rt, clk
}

// seedFamilyRefresh creates a family with its refresh row exactly the way the
// production Create path does: family root, refresh node, and a stamped row.
func seedFamilyRefresh(t *testing.T, ctx context.Context, rt *RefreshStore, store storage.Storage) (*internal.RefreshToken, storage.RefreshToken) {
	t.Helper()
	raw, err := rt.Create(ctx, testAuthorization())
	require.NoError(t, err)
	var req internal.RefreshToken
	require.NoError(t, internal.Unmarshal(raw, &req))
	row, err := store.GetRefresh(ctx, req.RefreshId)
	require.NoError(t, err)
	require.NotEmpty(t, row.FamilyID, "Create must provision a family")
	return &req, row
}

// ageRefreshRow moves a refresh row's LastUsed into the past by d and returns
// the re-read row, so a subsequent Rotate is outside the reuse window and
// actually rotates rather than no-opping. d should exceed the test's grace
// interval.
func ageRefreshRow(t *testing.T, ctx context.Context, store storage.Storage, id string, d time.Duration) storage.RefreshToken {
	t.Helper()
	require.NoError(t, store.UpdateRefreshToken(ctx, id, func(r storage.RefreshToken) (storage.RefreshToken, error) {
		r.LastUsed = r.LastUsed.Add(-d)
		return r, nil
	}))
	row, err := store.GetRefresh(ctx, id)
	require.NoError(t, err)
	return row
}

func freshIdentityStub() func(context.Context) (connector.Identity, error) {
	return func(context.Context) (connector.Identity, error) {
		return connector.Identity{UserID: "u1", Username: "alice", Email: "alice@example.com"}, nil
	}
}

// TestRotateGracePeriodConcurrentSingleWinner is the concurrency acceptance
// test: N concurrent refreshes presenting the same obsolete secret inside the
// grace period must produce exactly one successful redemption and N-1 distinct
// "already used" rejections, never a second rotation and never a 500-class
// error.
func TestRotateGracePeriodConcurrentSingleWinner(t *testing.T) {
	ctx := context.Background()
	store, rt, clk := newFamilyTestStore(t)
	req, row := seedFamilyRefresh(t, ctx, rt, store)

	const grace = 30 * time.Second
	strategy := NewRefreshStrategy(true, 0, 0, grace, clk.now)

	// Age the row past the window so the first rotation actually rotates.
	row = ageRefreshRow(t, ctx, store, req.RefreshId, grace+time.Second)

	// First rotation: t -> t2, leaving the original secret obsolete inside its
	// window.
	raw, _, err := rt.Rotate(ctx, &row, req, strategy, freshIdentityStub())
	require.NoError(t, err)
	var rotated internal.RefreshToken
	require.NoError(t, internal.Unmarshal(raw, &rotated))

	obsoleteReq := &internal.RefreshToken{RefreshId: req.RefreshId, Token: req.Token}

	const n = 50
	var wg sync.WaitGroup
	var okCount, alreadyUsed, otherErr atomic.Int32
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, _, rerr := rt.Rotate(ctx, &row, obsoleteReq, strategy, freshIdentityStub())
			switch {
			case rerr == nil:
				var out internal.RefreshToken
				if uerr := internal.Unmarshal(got, &out); uerr == nil && out.Token == rotated.Token {
					okCount.Add(1)
					return
				}
				otherErr.Add(1)
			case errors.Is(rerr, ErrRefreshTokenAlreadyUsed):
				alreadyUsed.Add(1)
			default:
				otherErr.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	require.Equal(t, int32(1), okCount.Load(), "exactly one concurrent reuse must succeed")
	require.Equal(t, int32(n-1), alreadyUsed.Load(), "all other racers must be told the token was already used")
	require.Equal(t, int32(0), otherErr.Load(), "no racer may hit an unrelated error")

	after, err := store.GetRefresh(ctx, req.RefreshId)
	require.NoError(t, err)
	require.False(t, after.ObsoleteConsumedAt.IsZero(), "the single-use marker must be persisted")
	require.Equal(t, rotated.Token, after.Token, "the losing racers must not have rotated the token")
}

// TestRotateGracePeriodStateSurvivesRestart proves the grace state is durable:
// a fresh store handle over the same backend still honors a single reuse after
// the "process" restarted, because ObsoleteConsumedAt lives on the row.
func TestRotateGracePeriodStateSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	store, rt, clk := newFamilyTestStore(t)
	req, row := seedFamilyRefresh(t, ctx, rt, store)
	strategy := NewRefreshStrategy(true, 0, 0, 30*time.Second, clk.now)

	row = ageRefreshRow(t, ctx, store, req.RefreshId, 31*time.Second)
	_, _, err := rt.Rotate(ctx, &row, req, strategy, freshIdentityStub())
	require.NoError(t, err)

	// Simulate a restart: a brand new store/issuer over the same persisted data.
	restarted := NewRefreshStore(store, clk.now, slog.New(slog.DiscardHandler))
	obsoleteReq := &internal.RefreshToken{RefreshId: req.RefreshId, Token: req.Token}

	// The first post-restart reuse still works (the marker was never set).
	_, _, err = restarted.Rotate(ctx, &row, obsoleteReq, strategy, freshIdentityStub())
	require.NoError(t, err)

	// The second one must be refused: the marker survived on the row.
	_, _, err = restarted.Rotate(ctx, &row, obsoleteReq, strategy, freshIdentityStub())
	require.ErrorIs(t, err, ErrRefreshTokenAlreadyUsed)
}

// TestRotateReplayOutsideGraceRevokesFamily is the replay-sensitivity acceptance
// test: presenting an obsolete secret after the grace window ends must revoke
// the whole family and mark every node, and the refresh row must disappear.
func TestRotateReplayOutsideGraceRevokesFamily(t *testing.T) {
	ctx := context.Background()
	store, rt, clk := newFamilyTestStore(t)
	req, row := seedFamilyRefresh(t, ctx, rt, store)
	familyID := row.FamilyID
	const grace = 30 * time.Second
	strategy := NewRefreshStrategy(true, 0, 0, grace, clk.now)

	// Age past the window so the rotation actually runs and the original secret
	// becomes obsolete.
	row = ageRefreshRow(t, ctx, store, req.RefreshId, grace+time.Second)

	// Register an access token node as the refresh grant would, so revocation
	// propagation can be verified.
	_, _, err := rt.Rotate(ctx, &row, req, strategy, freshIdentityStub())
	require.NoError(t, err)
	accessExpiry := clk.now().Add(time.Hour)
	require.NoError(t, rt.RegisterAccessToken(ctx, familyID, row, "access-jti-1", accessExpiry))

	// Advance past the grace period and replay the original (now obsolete) secret.
	clk.advance(grace + time.Second)
	obsoleteReq := &internal.RefreshToken{RefreshId: req.RefreshId, Token: req.Token}
	_, _, err = rt.Rotate(ctx, &row, obsoleteReq, strategy, freshIdentityStub())
	require.ErrorIs(t, err, ErrRefreshTokenReplayed)

	family, err := store.GetTokenFamily(ctx, familyID)
	require.NoError(t, err)
	require.False(t, family.RevokedAt.IsZero(), "the family root must be marked revoked")
	require.Equal(t, storage.RevokeReasonReplay, family.RevokeReason)
	require.Equal(t, row.ID, family.LastReplayedToken)

	nodes, err := store.ListTokenNodes(ctx, familyID)
	require.NoError(t, err)
	require.NotEmpty(t, nodes)
	for _, n := range nodes {
		require.False(t, n.RevokedAt.IsZero(), "node %s must be marked revoked", n.ID)
	}

	// The refresh row is removed, so any later presentation fails at lookup.
	_, err = store.GetRefresh(ctx, req.RefreshId)
	require.ErrorIs(t, err, storage.ErrNotFound)

	// The access token introspects as revoked despite its own expiry being an
	// hour away.
	revoked, err := rt.IsAccessTokenRevoked(ctx, "access-jti-1")
	require.NoError(t, err)
	require.True(t, revoked)
}

// TestFamilyRevocationDoesNotTouchOtherFamilies proves revocation is scoped: a
// replay in one family must not revoke an unrelated family's tokens.
func TestFamilyRevocationDoesNotTouchOtherFamilies(t *testing.T) {
	ctx := context.Background()
	store, rt, clk := newFamilyTestStore(t)

	req1, row1 := seedFamilyRefresh(t, ctx, rt, store)
	// A second authorization for a different subject gets its own family.
	otherAuth := testAuthorization()
	otherAuth.Claims.UserID = "u2"
	raw2, err := rt.Create(ctx, otherAuth)
	require.NoError(t, err)
	var req2 internal.RefreshToken
	require.NoError(t, internal.Unmarshal(raw2, &req2))
	row2, err := store.GetRefresh(ctx, req2.RefreshId)
	require.NoError(t, err)

	strategy := NewRefreshStrategy(true, 0, 0, 30*time.Second, clk.now)
	row1 = ageRefreshRow(t, ctx, store, req1.RefreshId, 31*time.Second)
	_, _, err = rt.Rotate(ctx, &row1, req1, strategy, freshIdentityStub())
	require.NoError(t, err)

	clk.advance(31 * time.Second)
	_, _, err = rt.Rotate(ctx, &row1, &internal.RefreshToken{RefreshId: req1.RefreshId, Token: req1.Token}, strategy, freshIdentityStub())
	require.ErrorIs(t, err, ErrRefreshTokenReplayed)

	// The other family is untouched.
	otherFamily, err := store.GetTokenFamily(ctx, row2.FamilyID)
	require.NoError(t, err)
	require.True(t, otherFamily.RevokedAt.IsZero())
	_, err = store.GetRefresh(ctx, req2.RefreshId)
	require.NoError(t, err, "an unrelated family's refresh token must survive")
}

// TestAccessTokenFallsBackToNaturalExpiry verifies the degradation rule: a jti
// with no node (signal lost, GC'd, or a pre-family token) is not treated as
// revoked; the JWT's own expiry is the backstop.
func TestAccessTokenFallsBackToNaturalExpiry(t *testing.T) {
	ctx := context.Background()
	_, rt, _ := newFamilyTestStore(t)

	revoked, err := rt.IsAccessTokenRevoked(ctx, "unknown-jti")
	require.NoError(t, err)
	require.False(t, revoked, "a missing node must not be read as a revocation")

	revoked, err = rt.IsAccessTokenRevoked(ctx, "")
	require.NoError(t, err)
	require.False(t, revoked)
}

// TestDefaultOneShotRotationUnchanged guards the default: with no grace interval
// an obsolete secret is refused on its second use, and no family graph is
// provisioned — the historical behavior.
func TestDefaultOneShotRotationUnchanged(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)
	store := memory.New(logger)
	clk := newMutableClock(time.Now().UTC())
	rt := NewRefreshStore(store, clk.now, logger)

	// Seed directly, the way legacy deployments store rows (no family).
	require.NoError(t, store.CreateRefresh(ctx, storage.RefreshToken{
		ID: "legacy", Token: "t1", ObsoleteToken: "t0", ClientID: "client-1", ConnectorID: "mock",
		Claims: storage.Claims{UserID: "u1"}, CreatedAt: clk.now(), LastUsed: clk.now(),
	}))
	require.NoError(t, store.CreateOfflineSessions(ctx, storage.OfflineSessions{
		UserID: "u1", ConnID: "mock",
		Refresh: map[string]*storage.RefreshTokenRef{"client-1": {ID: "legacy", ClientID: "client-1"}},
	}))
	row, err := store.GetRefresh(ctx, "legacy")
	require.NoError(t, err)

	strategy := NewRefreshStrategy(true, 0, 0, 0, clk.now) // grace disabled
	_, _, err = rt.Rotate(ctx, &row, &internal.RefreshToken{RefreshId: "legacy", Token: "t1"}, strategy, freshIdentityStub())
	require.NoError(t, err)

	after, err := store.GetRefresh(ctx, "legacy")
	require.NoError(t, err)
	require.Empty(t, after.FamilyID, "the default path must not provision a family graph")

	// An obsolete secret out of window on a family-less row keeps the historical
	// one-shot answer: a plain claim error, never a replay revocation and the row
	// is left in place.
	_, _, err = rt.Rotate(ctx, &after, &internal.RefreshToken{RefreshId: "legacy", Token: "t1"}, strategy, freshIdentityStub())
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrRefreshTokenReplayed))
	require.False(t, errors.Is(err, ErrRefreshTokenAlreadyUsed))

	// The row still exists: a non-replay claim error must not delete it.
	_, err = store.GetRefresh(ctx, "legacy")
	require.NoError(t, err)
}

// failingFamilyStorage wraps memory and fails the family graph operations, to
// prove the refresh path fails closed rather than issuing tokens without the
// revocation graph.
type failingFamilyStorage struct {
	storage.Storage
	failNodes atomic.Bool
}

func (f *failingFamilyStorage) CreateTokenNode(ctx context.Context, n storage.TokenNode) error {
	if f.failNodes.Load() {
		return errors.New("injected token node failure")
	}
	return f.Storage.CreateTokenNode(ctx, n)
}

func (f *failingFamilyStorage) GetTokenNode(ctx context.Context, id string) (storage.TokenNode, error) {
	if f.failNodes.Load() {
		return storage.TokenNode{}, errors.New("injected token node read failure")
	}
	return f.Storage.GetTokenNode(ctx, id)
}

// TestFailClosedWhenFamilyStorageUnavailable verifies the degradation rule: when
// the grace-period state cannot be written, the grant must fail instead of
// handing out an access token the family revocation could not reach.
func TestFailClosedWhenFamilyStorageUnavailable(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)
	base := memory.New(logger)
	failing := &failingFamilyStorage{Storage: base}
	clk := newMutableClock(time.Now().UTC())
	rt := NewRefreshStore(failing, clk.now, logger)

	// Create itself must fail when the access/family node cannot be written.
	failing.failNodes.Store(true)
	_, err := rt.Create(ctx, testAuthorization())
	require.Error(t, err, "a family write failure must fail the grant, not issue an orphaned token")

	// Introspection on an unknown jti with a failing node read must surface the
	// storage error rather than answer "not revoked".
	failing.failNodes.Store(false)
	raw, err := rt.Create(ctx, testAuthorization())
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	failing.failNodes.Store(true)
	_, err = rt.IsAccessTokenRevoked(ctx, "some-jti")
	require.Error(t, err, "a revocation-state read failure must propagate so the caller can fail closed")
}
