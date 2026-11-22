package sql

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/dexidp/dex/storage"
)

// Token family graph CRUD for the legacy SQL backend (SQLite3, Postgres,
// MySQL). Updates run in the same ExecTx transactions as every other entity, so
// the refresh flow's claim-and-flip is serialized by the database itself.
//
// The nullable columns (revoked_at, expires_at) use sql.NullTime rather than
// the stored epoch sentinel, so "unset" stays distinguishable from a real
// timestamp.

func (c *conn) CreateTokenFamily(ctx context.Context, f storage.TokenFamily) error {
	_, err := c.Exec(`
		insert into token_family (
			id, client_id, user_id, connector_id, created_at,
			revoked_at, revoke_reason, last_replayed_token
		)
		values ($1, $2, $3, $4, $5, $6, $7, $8);
	`,
		f.ID, f.ClientID, f.UserID, f.ConnectorID, f.CreatedAt,
		sql.NullTime{Time: f.RevokedAt.UTC(), Valid: !f.RevokedAt.IsZero()},
		f.RevokeReason, f.LastReplayedToken,
	)
	if err != nil {
		if c.alreadyExistsCheck(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("insert token_family: %v", err)
	}
	return nil
}

func (c *conn) GetTokenFamily(ctx context.Context, id string) (f storage.TokenFamily, err error) {
	return getTokenFamily(ctx, c, id)
}

func getTokenFamily(ctx context.Context, q querier, id string) (f storage.TokenFamily, err error) {
	var revokedAt sql.NullTime
	err = q.QueryRow(`
		select
			id, client_id, user_id, connector_id, created_at,
			revoked_at, revoke_reason, last_replayed_token
		from token_family where id = $1;
	`, id).Scan(
		&f.ID, &f.ClientID, &f.UserID, &f.ConnectorID, &f.CreatedAt,
		&revokedAt, &f.RevokeReason, &f.LastReplayedToken,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return f, storage.ErrNotFound
		}
		return f, fmt.Errorf("select token_family: %v", err)
	}
	if revokedAt.Valid {
		f.RevokedAt = fromStoredTime(revokedAt.Time)
	}
	return f, nil
}

func (c *conn) UpdateTokenFamily(ctx context.Context, id string, updater func(f storage.TokenFamily) (storage.TokenFamily, error)) error {
	return c.ExecTx(func(tx *trans) error {
		f, err := getTokenFamily(ctx, tx, id)
		if err != nil {
			return err
		}
		if f, err = updater(f); err != nil {
			return err
		}
		_, err = tx.Exec(`
			update token_family
			set
				client_id = $1,
				user_id = $2,
				connector_id = $3,
				created_at = $4,
				revoked_at = $5,
				revoke_reason = $6,
				last_replayed_token = $7
			where id = $8;
		`,
			f.ClientID, f.UserID, f.ConnectorID, f.CreatedAt,
			sql.NullTime{Time: f.RevokedAt.UTC(), Valid: !f.RevokedAt.IsZero()},
			f.RevokeReason, f.LastReplayedToken, id,
		)
		if err != nil {
			return fmt.Errorf("update token_family: %v", err)
		}
		return nil
	})
}

func (c *conn) DeleteTokenFamily(ctx context.Context, id string) error {
	res, err := c.Exec(`delete from token_family where id = $1;`, id)
	if err != nil {
		return fmt.Errorf("delete token_family: %v", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (c *conn) CreateTokenNode(ctx context.Context, n storage.TokenNode) error {
	_, err := c.Exec(`
		insert into token_node (
			id, family_id, parent_id, kind,
			client_id, user_id, connector_id,
			created_at, expires_at, revoked_at
		)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
	`,
		n.ID, n.FamilyID, n.ParentID, n.Kind,
		n.ClientID, n.UserID, n.ConnectorID,
		n.CreatedAt,
		sql.NullTime{Time: n.ExpiresAt.UTC(), Valid: !n.ExpiresAt.IsZero()},
		sql.NullTime{Time: n.RevokedAt.UTC(), Valid: !n.RevokedAt.IsZero()},
	)
	if err != nil {
		if c.alreadyExistsCheck(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("insert token_node: %v", err)
	}
	return nil
}

func (c *conn) GetTokenNode(ctx context.Context, id string) (n storage.TokenNode, err error) {
	return getTokenNode(ctx, c, id)
}

func getTokenNode(ctx context.Context, q querier, id string) (n storage.TokenNode, err error) {
	var expiresAt, revokedAt sql.NullTime
	err = q.QueryRow(`
		select
			id, family_id, parent_id, kind,
			client_id, user_id, connector_id,
			created_at, expires_at, revoked_at
		from token_node where id = $1;
	`, id).Scan(
		&n.ID, &n.FamilyID, &n.ParentID, &n.Kind,
		&n.ClientID, &n.UserID, &n.ConnectorID,
		&n.CreatedAt, &expiresAt, &revokedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return n, storage.ErrNotFound
		}
		return n, fmt.Errorf("select token_node: %v", err)
	}
	if expiresAt.Valid {
		n.ExpiresAt = fromStoredTime(expiresAt.Time)
	}
	if revokedAt.Valid {
		n.RevokedAt = fromStoredTime(revokedAt.Time)
	}
	return n, nil
}

func (c *conn) ListTokenNodes(ctx context.Context, familyID string) ([]storage.TokenNode, error) {
	rows, err := c.Query(`
		select
			id, family_id, parent_id, kind,
			client_id, user_id, connector_id,
			created_at, expires_at, revoked_at
		from token_node where family_id = $1;
	`, familyID)
	if err != nil {
		return nil, fmt.Errorf("query token_node: %v", err)
	}
	defer rows.Close()

	var nodes []storage.TokenNode
	for rows.Next() {
		var n storage.TokenNode
		var expiresAt, revokedAt sql.NullTime
		if err := rows.Scan(
			&n.ID, &n.FamilyID, &n.ParentID, &n.Kind,
			&n.ClientID, &n.UserID, &n.ConnectorID,
			&n.CreatedAt, &expiresAt, &revokedAt,
		); err != nil {
			return nil, fmt.Errorf("scan token_node: %v", err)
		}
		if expiresAt.Valid {
			n.ExpiresAt = fromStoredTime(expiresAt.Time)
		}
		if revokedAt.Valid {
			n.RevokedAt = fromStoredTime(revokedAt.Time)
		}
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan token_node: %v", err)
	}
	return nodes, nil
}

func (c *conn) UpdateTokenNode(ctx context.Context, id string, updater func(n storage.TokenNode) (storage.TokenNode, error)) error {
	return c.ExecTx(func(tx *trans) error {
		n, err := getTokenNode(ctx, tx, id)
		if err != nil {
			return err
		}
		if n, err = updater(n); err != nil {
			return err
		}
		_, err = tx.Exec(`
			update token_node
			set
				family_id = $1,
				parent_id = $2,
				kind = $3,
				client_id = $4,
				user_id = $5,
				connector_id = $6,
				created_at = $7,
				expires_at = $8,
				revoked_at = $9
			where id = $10;
		`,
			n.FamilyID, n.ParentID, n.Kind,
			n.ClientID, n.UserID, n.ConnectorID,
			n.CreatedAt,
			sql.NullTime{Time: n.ExpiresAt.UTC(), Valid: !n.ExpiresAt.IsZero()},
			sql.NullTime{Time: n.RevokedAt.UTC(), Valid: !n.RevokedAt.IsZero()},
			id,
		)
		if err != nil {
			return fmt.Errorf("update token_node: %v", err)
		}
		return nil
	})
}

func (c *conn) DeleteTokenNode(ctx context.Context, id string) error {
	res, err := c.Exec(`delete from token_node where id = $1;`, id)
	if err != nil {
		return fmt.Errorf("delete token_node: %v", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return storage.ErrNotFound
	}
	return nil
}
