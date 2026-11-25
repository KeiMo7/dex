package client

import (
	"context"

	"github.com/dexidp/dex/storage"
)

// CompareAndSwapRefreshTokenGeneration implements storage.Storage. Ent's
// refresh update runs in a transaction; the shared adapter makes the expected
// generation premise explicit to callers and conformance tests.
func (d *Database) CompareAndSwapRefreshTokenGeneration(ctx context.Context, id string, expectedGeneration int64, next storage.RefreshToken) (storage.RefreshToken, bool, error) {
	return storage.UpdateRefreshTokenIfGeneration(ctx, d, id, expectedGeneration, func(old storage.RefreshToken) (storage.RefreshToken, error) {
		next.ID = old.ID
		return next, nil
	})
}
