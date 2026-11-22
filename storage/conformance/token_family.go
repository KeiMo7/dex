package conformance

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
)

// testTokenFamilyCRUD exercises the refresh-token family graph surface every
// backend must provide: roots, nodes, the family listing used by the revocation
// sweep, and not-found/already-exists semantics.
func testTokenFamilyCRUD(t *testing.T, s storage.Storage) {
	ctx := context.Background()
	now := time.Now().UTC().Round(time.Millisecond)

	family := storage.TokenFamily{
		ID:          "family-1",
		ClientID:    "client-1",
		UserID:      "user-1",
		ConnectorID: "connector-1",
		CreatedAt:   now,
	}
	require.NoError(t, s.CreateTokenFamily(ctx, family))
	mustBeErrAlreadyExists(t, "token family", s.CreateTokenFamily(ctx, family))

	gotFamily, err := s.GetTokenFamily(ctx, family.ID)
	require.NoError(t, err)
	require.Equal(t, family, gotFamily, "token family round trip changed the value")
	require.True(t, gotFamily.RevokedAt.IsZero(), "a new family must not be revoked")

	// Nodes: a refresh lineage of two refresh nodes plus one access node hanging
	// off the second, the shape the refresh flow writes.
	nodes := []storage.TokenNode{
		{ID: "n-refresh-1", FamilyID: family.ID, Kind: storage.TokenNodeKindRefresh, ClientID: "client-1", UserID: "user-1", ConnectorID: "connector-1", CreatedAt: now},
		{ID: "n-refresh-2", FamilyID: family.ID, ParentID: "n-refresh-1", Kind: storage.TokenNodeKindRefresh, ClientID: "client-1", UserID: "user-1", ConnectorID: "connector-1", CreatedAt: now},
		{ID: "n-access-1", FamilyID: family.ID, ParentID: "n-refresh-2", Kind: storage.TokenNodeKindAccess, ClientID: "client-1", UserID: "user-1", ConnectorID: "connector-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
	}
	for _, n := range nodes {
		require.NoError(t, s.CreateTokenNode(ctx, n))
	}
	mustBeErrAlreadyExists(t, "token node", s.CreateTokenNode(ctx, nodes[0]))

	gotNode, err := s.GetTokenNode(ctx, "n-access-1")
	require.NoError(t, err)
	require.Equal(t, nodes[2], gotNode, "access node round trip changed the value")

	listed, err := s.ListTokenNodes(ctx, family.ID)
	require.NoError(t, err)
	require.Len(t, listed, len(nodes), "the family listing must return every node")

	// An unrelated family's nodes must not appear in the listing.
	otherFamily := storage.TokenFamily{ID: "family-2", ClientID: "client-2", UserID: "user-2", ConnectorID: "connector-2", CreatedAt: now}
	require.NoError(t, s.CreateTokenFamily(ctx, otherFamily))
	require.NoError(t, s.CreateTokenNode(ctx, storage.TokenNode{ID: "n-other", FamilyID: otherFamily.ID, Kind: storage.TokenNodeKindRefresh, ClientID: "client-2", UserID: "user-2", ConnectorID: "connector-2", CreatedAt: now}))
	listed, err = s.ListTokenNodes(ctx, family.ID)
	require.NoError(t, err)
	require.Len(t, listed, len(nodes), "the family listing must be scoped to one family")

	// Marking the root revoked is the single signal introspection consults.
	revokedAt := now.Add(time.Minute)
	require.NoError(t, s.UpdateTokenFamily(ctx, family.ID, func(f storage.TokenFamily) (storage.TokenFamily, error) {
		f.RevokedAt = revokedAt
		f.RevokeReason = storage.RevokeReasonReplay
		f.LastReplayedToken = "n-refresh-1"
		return f, nil
	}))
	gotFamily, err = s.GetTokenFamily(ctx, family.ID)
	require.NoError(t, err)
	require.Equal(t, revokedAt, gotFamily.RevokedAt)
	require.Equal(t, storage.RevokeReasonReplay, gotFamily.RevokeReason)
	require.Equal(t, "n-refresh-1", gotFamily.LastReplayedToken)

	// Node update flips the per-node revocation marker independently.
	require.NoError(t, s.UpdateTokenNode(ctx, "n-access-1", func(n storage.TokenNode) (storage.TokenNode, error) {
		n.RevokedAt = revokedAt
		return n, nil
	}))
	gotNode, err = s.GetTokenNode(ctx, "n-access-1")
	require.NoError(t, err)
	require.Equal(t, revokedAt, gotNode.RevokedAt)

	// Updating a missing entity is not found.
	mustBeErrNotFound(t, "token family", s.UpdateTokenFamily(ctx, "missing", func(f storage.TokenFamily) (storage.TokenFamily, error) {
		return f, nil
	}))
	mustBeErrNotFound(t, "token node", s.UpdateTokenNode(ctx, "missing", func(n storage.TokenNode) (storage.TokenNode, error) {
		return n, nil
	}))
	mustBeErrNotFound(t, "token family", func() error {
		_, e := s.GetTokenFamily(ctx, "missing")
		return e
	}())
	mustBeErrNotFound(t, "token node", func() error {
		_, e := s.GetTokenNode(ctx, "missing")
		return e
	}())

	// Deletes honor not-found and actually remove the row.
	require.NoError(t, s.DeleteTokenNode(ctx, "n-other"))
	mustBeErrNotFound(t, "token node", s.DeleteTokenNode(ctx, "n-other"))
	require.NoError(t, s.DeleteTokenFamily(ctx, otherFamily.ID))
	mustBeErrNotFound(t, "token family", s.DeleteTokenFamily(ctx, otherFamily.ID))
}

// testTokenFamilyConcurrentUpdate verifies the storage serializes concurrent
// updater transactions on a family root and a node — the property the grace
// period's compare-and-set relies on. Every update must land; none may be lost.
func testTokenFamilyConcurrentUpdate(t *testing.T, s storage.Storage) {
	ctx := context.Background()
	now := time.Now().UTC().Round(time.Millisecond)

	require.NoError(t, s.CreateTokenFamily(ctx, storage.TokenFamily{ID: "fam", ClientID: "c", UserID: "u", ConnectorID: "conn", CreatedAt: now}))
	require.NoError(t, s.CreateTokenNode(ctx, storage.TokenNode{ID: "node", FamilyID: "fam", Kind: storage.TokenNodeKindRefresh, ClientID: "c", UserID: "u", ConnectorID: "conn", CreatedAt: now}))

	const workers = 50
	var wg sync.WaitGroup
	errs := make(chan error, workers*2)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.UpdateTokenFamily(ctx, "fam", func(f storage.TokenFamily) (storage.TokenFamily, error) {
				f.LastReplayedToken += "x"
				return f, nil
			})
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.UpdateTokenNode(ctx, "node", func(n storage.TokenNode) (storage.TokenNode, error) {
				n.ParentID += "y"
				return n, nil
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	fam, err := s.GetTokenFamily(ctx, "fam")
	require.NoError(t, err)
	require.Len(t, fam.LastReplayedToken, workers, "lost family updates detected")

	node, err := s.GetTokenNode(ctx, "node")
	require.NoError(t, err)
	require.Len(t, node.ParentID, workers, "lost node updates detected")
}

// testTokenNodeGarbageCollection verifies expired access nodes are collected
// while refresh nodes and unexpired access nodes survive.
func testTokenNodeGarbageCollection(t *testing.T, s storage.Storage) {
	ctx := context.Background()
	now := time.Now().UTC().Round(time.Millisecond)

	require.NoError(t, s.CreateTokenNode(ctx, storage.TokenNode{ID: "refresh-node", FamilyID: "fam", Kind: storage.TokenNodeKindRefresh, ClientID: "c", UserID: "u", ConnectorID: "conn", CreatedAt: now}))
	require.NoError(t, s.CreateTokenNode(ctx, storage.TokenNode{ID: "expired-access", FamilyID: "fam", Kind: storage.TokenNodeKindAccess, ClientID: "c", UserID: "u", ConnectorID: "conn", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}))
	require.NoError(t, s.CreateTokenNode(ctx, storage.TokenNode{ID: "live-access", FamilyID: "fam", Kind: storage.TokenNodeKindAccess, ClientID: "c", UserID: "u", ConnectorID: "conn", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}))

	result, err := s.GarbageCollect(ctx, now)
	require.NoError(t, err)
	require.GreaterOrEqual(t, result.TokenNodes, int64(1))

	_, err = s.GetTokenNode(ctx, "expired-access")
	require.ErrorIs(t, err, storage.ErrNotFound, "the expired access node must be collected")

	_, err = s.GetTokenNode(ctx, "refresh-node")
	require.NoError(t, err, "refresh nodes are never garbage collected")
	_, err = s.GetTokenNode(ctx, "live-access")
	require.NoError(t, err, "an unexpired access node must survive")
}
