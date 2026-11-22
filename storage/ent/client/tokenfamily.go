package client

import (
	"context"
	"time"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/ent/db"
	"github.com/dexidp/dex/storage/ent/db/tokennode"
)

// Token family graph CRUD for the ent backend. Update* runs inside a database
// transaction, so the refresh flow's claim-and-flip is serialized by the same
// row locks every other ent update uses.

func toStorageTokenFamily(f *db.TokenFamily) storage.TokenFamily {
	out := storage.TokenFamily{
		ID:                f.ID,
		ClientID:          f.ClientID,
		UserID:            f.UserID,
		ConnectorID:       f.ConnectorID,
		CreatedAt:         f.CreatedAt,
		RevokeReason:      f.RevokeReason,
		LastReplayedToken: f.LastReplayedToken,
	}
	if f.RevokedAt != nil {
		out.RevokedAt = *f.RevokedAt
	}
	return out
}

func toStorageTokenNode(n *db.TokenNode) storage.TokenNode {
	out := storage.TokenNode{
		ID:          n.ID,
		FamilyID:    n.FamilyID,
		ParentID:    n.ParentID,
		Kind:        n.Kind,
		ClientID:    n.ClientID,
		UserID:      n.UserID,
		ConnectorID: n.ConnectorID,
		CreatedAt:   n.CreatedAt,
	}
	if n.ExpiresAt != nil {
		out.ExpiresAt = *n.ExpiresAt
	}
	if n.RevokedAt != nil {
		out.RevokedAt = *n.RevokedAt
	}
	return out
}

// CreateTokenFamily saves a family root.
func (d *Database) CreateTokenFamily(ctx context.Context, f storage.TokenFamily) error {
	_, err := d.client.TokenFamily.Create().
		SetID(f.ID).
		SetClientID(f.ClientID).
		SetUserID(f.UserID).
		SetConnectorID(f.ConnectorID).
		SetCreatedAt(f.CreatedAt.UTC()).
		SetNillableRevokedAt(nonZeroTime(f.RevokedAt.UTC())).
		SetRevokeReason(f.RevokeReason).
		SetLastReplayedToken(f.LastReplayedToken).
		Save(ctx)
	if err != nil {
		return convertDBError("create token family: %w", err)
	}
	return nil
}

// GetTokenFamily reads a family root by ID.
func (d *Database) GetTokenFamily(ctx context.Context, id string) (storage.TokenFamily, error) {
	f, err := d.client.TokenFamily.Get(ctx, id)
	if err != nil {
		return storage.TokenFamily{}, convertDBError("get token family: %w", err)
	}
	return toStorageTokenFamily(f), nil
}

// UpdateTokenFamily changes a family root inside a transaction.
func (d *Database) UpdateTokenFamily(ctx context.Context, id string, updater func(f storage.TokenFamily) (storage.TokenFamily, error)) error {
	tx, err := d.BeginTx(ctx)
	if err != nil {
		return convertDBError("update token family tx: %w", err)
	}

	f, err := tx.TokenFamily.Get(ctx, id)
	if err != nil {
		return rollback(tx, "update token family database: %w", err)
	}

	newFamily, err := updater(toStorageTokenFamily(f))
	if err != nil {
		return rollback(tx, "update token family updating: %w", err)
	}

	_, err = tx.TokenFamily.UpdateOneID(id).
		SetClientID(newFamily.ClientID).
		SetUserID(newFamily.UserID).
		SetConnectorID(newFamily.ConnectorID).
		SetCreatedAt(newFamily.CreatedAt.UTC()).
		SetNillableRevokedAt(nonZeroTime(newFamily.RevokedAt.UTC())).
		SetRevokeReason(newFamily.RevokeReason).
		SetLastReplayedToken(newFamily.LastReplayedToken).
		Save(ctx)
	if err != nil {
		return rollback(tx, "update token family uploading: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return rollback(tx, "update token family commit: %w", err)
	}
	return nil
}

// DeleteTokenFamily removes a family root.
func (d *Database) DeleteTokenFamily(ctx context.Context, id string) error {
	err := d.client.TokenFamily.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return convertDBError("delete token family: %w", err)
	}
	return nil
}

// CreateTokenNode saves a graph node.
func (d *Database) CreateTokenNode(ctx context.Context, n storage.TokenNode) error {
	_, err := d.client.TokenNode.Create().
		SetID(n.ID).
		SetFamilyID(n.FamilyID).
		SetParentID(n.ParentID).
		SetKind(n.Kind).
		SetClientID(n.ClientID).
		SetUserID(n.UserID).
		SetConnectorID(n.ConnectorID).
		SetCreatedAt(n.CreatedAt.UTC()).
		SetNillableExpiresAt(nonZeroTime(n.ExpiresAt.UTC())).
		SetNillableRevokedAt(nonZeroTime(n.RevokedAt.UTC())).
		Save(ctx)
	if err != nil {
		return convertDBError("create token node: %w", err)
	}
	return nil
}

// GetTokenNode reads a graph node by ID.
func (d *Database) GetTokenNode(ctx context.Context, id string) (storage.TokenNode, error) {
	n, err := d.client.TokenNode.Get(ctx, id)
	if err != nil {
		return storage.TokenNode{}, convertDBError("get token node: %w", err)
	}
	return toStorageTokenNode(n), nil
}

// ListTokenNodes returns every node belonging to a family.
func (d *Database) ListTokenNodes(ctx context.Context, familyID string) ([]storage.TokenNode, error) {
	rows, err := d.client.TokenNode.Query().
		Where(tokennode.FamilyID(familyID)).
		All(ctx)
	if err != nil {
		return nil, convertDBError("list token nodes: %w", err)
	}

	nodes := make([]storage.TokenNode, 0, len(rows))
	for _, n := range rows {
		nodes = append(nodes, toStorageTokenNode(n))
	}
	return nodes, nil
}

// UpdateTokenNode changes a graph node inside a transaction.
func (d *Database) UpdateTokenNode(ctx context.Context, id string, updater func(n storage.TokenNode) (storage.TokenNode, error)) error {
	tx, err := d.BeginTx(ctx)
	if err != nil {
		return convertDBError("update token node tx: %w", err)
	}

	n, err := tx.TokenNode.Get(ctx, id)
	if err != nil {
		return rollback(tx, "update token node database: %w", err)
	}

	newNode, err := updater(toStorageTokenNode(n))
	if err != nil {
		return rollback(tx, "update token node updating: %w", err)
	}

	_, err = tx.TokenNode.UpdateOneID(id).
		SetFamilyID(newNode.FamilyID).
		SetParentID(newNode.ParentID).
		SetKind(newNode.Kind).
		SetClientID(newNode.ClientID).
		SetUserID(newNode.UserID).
		SetConnectorID(newNode.ConnectorID).
		SetCreatedAt(newNode.CreatedAt.UTC()).
		SetNillableExpiresAt(nonZeroTime(newNode.ExpiresAt.UTC())).
		SetNillableRevokedAt(nonZeroTime(newNode.RevokedAt.UTC())).
		Save(ctx)
	if err != nil {
		return rollback(tx, "update token node uploading: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return rollback(tx, "update token node commit: %w", err)
	}
	return nil
}

// DeleteTokenNode removes a graph node.
func (d *Database) DeleteTokenNode(ctx context.Context, id string) error {
	err := d.client.TokenNode.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return convertDBError("delete token node: %w", err)
	}
	return nil
}

// gcExpiredTokenNodes deletes access nodes whose JWT has naturally expired and
// returns how many were removed.
func (d *Database) gcExpiredTokenNodes(ctx context.Context, now time.Time) (int, error) {
	return d.client.TokenNode.Delete().
		Where(
			tokennode.KindEQ(storage.TokenNodeKindAccess),
			tokennode.ExpiresAtNotNil(),
			tokennode.ExpiresAtLT(now.UTC()),
		).
		Exec(ctx)
}
