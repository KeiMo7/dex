package etcd

import (
	"context"

	"github.com/dexidp/dex/storage"
)

// CompareAndSwapRefreshTokenGeneration implements storage.Storage using the
// generation-aware adapter over etcd's ModRevision transaction.
func (c *conn) CompareAndSwapRefreshTokenGeneration(ctx context.Context, id string, expectedGeneration int64, next storage.RefreshToken) (storage.RefreshToken, bool, error) {
	return storage.UpdateRefreshTokenIfGeneration(ctx, c, id, expectedGeneration, func(old storage.RefreshToken) (storage.RefreshToken, error) {
		next.ID = old.ID
		return next, nil
	})
}
