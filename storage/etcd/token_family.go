package etcd

import (
	"context"
	"encoding/json"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/dexidp/dex/storage"
)

// Token family graph CRUD for the etcd backend. Keys are JSON documents under
// their own prefixes; updates go through txnUpdate's ModRevision compare, which
// is the storage-level CAS the grace-period claim relies on — no application
// lock, no clock dependency.

func (c *conn) CreateTokenFamily(ctx context.Context, f storage.TokenFamily) error {
	ctx, cancel := context.WithTimeout(ctx, defaultStorageTimeout)
	defer cancel()
	return c.txnCreate(ctx, keyID(tokenFamilyPrefix, f.ID), fromStorageTokenFamily(f))
}

func (c *conn) GetTokenFamily(ctx context.Context, id string) (f storage.TokenFamily, err error) {
	ctx, cancel := context.WithTimeout(ctx, defaultStorageTimeout)
	defer cancel()
	var raw TokenFamily
	if err = c.getKey(ctx, keyID(tokenFamilyPrefix, id), &raw); err == nil {
		f = toStorageTokenFamily(raw)
	}
	return f, err
}

func (c *conn) UpdateTokenFamily(ctx context.Context, id string, updater func(f storage.TokenFamily) (storage.TokenFamily, error)) error {
	ctx, cancel := context.WithTimeout(ctx, defaultStorageTimeout)
	defer cancel()
	return c.txnUpdate(ctx, keyID(tokenFamilyPrefix, id), func(currentValue []byte) ([]byte, error) {
		var current TokenFamily
		if len(currentValue) > 0 {
			if err := json.Unmarshal(currentValue, &current); err != nil {
				return nil, err
			}
		}
		updated, err := updater(toStorageTokenFamily(current))
		if err != nil {
			return nil, err
		}
		return json.Marshal(fromStorageTokenFamily(updated))
	})
}

func (c *conn) DeleteTokenFamily(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, defaultStorageTimeout)
	defer cancel()
	return c.deleteKey(ctx, keyID(tokenFamilyPrefix, id))
}

func (c *conn) CreateTokenNode(ctx context.Context, n storage.TokenNode) error {
	ctx, cancel := context.WithTimeout(ctx, defaultStorageTimeout)
	defer cancel()
	return c.txnCreate(ctx, keyID(tokenNodePrefix, n.ID), fromStorageTokenNode(n))
}

func (c *conn) GetTokenNode(ctx context.Context, id string) (n storage.TokenNode, err error) {
	ctx, cancel := context.WithTimeout(ctx, defaultStorageTimeout)
	defer cancel()
	var raw TokenNode
	if err = c.getKey(ctx, keyID(tokenNodePrefix, id), &raw); err == nil {
		n = toStorageTokenNode(raw)
	}
	return n, err
}

func (c *conn) ListTokenNodes(ctx context.Context, familyID string) (nodes []storage.TokenNode, err error) {
	ctx, cancel := context.WithTimeout(ctx, defaultStorageTimeout)
	defer cancel()
	res, err := c.db.Get(ctx, tokenNodePrefix, clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}
	for _, kv := range res.Kvs {
		var raw TokenNode
		if err = json.Unmarshal(kv.Value, &raw); err != nil {
			return nil, err
		}
		if raw.FamilyID == familyID {
			nodes = append(nodes, toStorageTokenNode(raw))
		}
	}
	return nodes, nil
}

func (c *conn) UpdateTokenNode(ctx context.Context, id string, updater func(n storage.TokenNode) (storage.TokenNode, error)) error {
	ctx, cancel := context.WithTimeout(ctx, defaultStorageTimeout)
	defer cancel()
	return c.txnUpdate(ctx, keyID(tokenNodePrefix, id), func(currentValue []byte) ([]byte, error) {
		var current TokenNode
		if len(currentValue) > 0 {
			if err := json.Unmarshal(currentValue, &current); err != nil {
				return nil, err
			}
		}
		updated, err := updater(toStorageTokenNode(current))
		if err != nil {
			return nil, err
		}
		return json.Marshal(fromStorageTokenNode(updated))
	})
}

func (c *conn) DeleteTokenNode(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, defaultStorageTimeout)
	defer cancel()
	return c.deleteKey(ctx, keyID(tokenNodePrefix, id))
}

// gcTokenNodes deletes access nodes whose JWT reached its natural expiry and
// returns the count. It mirrors the full-scan shape of the other etcd GC
// sweeps.
func (c *conn) gcTokenNodes(ctx context.Context, now time.Time) (int64, error) {
	res, err := c.db.Get(ctx, tokenNodePrefix, clientv3.WithPrefix())
	if err != nil {
		return 0, err
	}
	var deleted int64
	for _, kv := range res.Kvs {
		var raw TokenNode
		if err := json.Unmarshal(kv.Value, &raw); err != nil {
			return deleted, err
		}
		if raw.Kind == storage.TokenNodeKindAccess && !raw.ExpiresAt.IsZero() && now.After(raw.ExpiresAt) {
			if err := c.deleteKey(ctx, string(kv.Key)); err != nil {
				return deleted, err
			}
			deleted++
		}
	}
	return deleted, nil
}
