package sql

import (
	"context"

	"github.com/dexidp/dex/storage"
)

// CompareAndSwapRefreshTokenGeneration implements storage.Storage. The
// generation predicate is evaluated inside the backend's transactional refresh
// update; the SQL implementation additionally persists generation/chain columns
// and can be tightened to a conditional UPDATE without changing callers.
func (c *conn) CompareAndSwapRefreshTokenGeneration(ctx context.Context, id string, expectedGeneration int64, next storage.RefreshToken) (storage.RefreshToken, bool, error) {
	return storage.UpdateRefreshTokenIfGeneration(ctx, c, id, expectedGeneration, func(old storage.RefreshToken) (storage.RefreshToken, error) {
		// The helper has already checked old.Generation. Preserve the identity
		// fields that identify the row and let the caller supply the next state.
		next.ID = old.ID
		return next, nil
	})
}
