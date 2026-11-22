package kubernetes

import (
	"context"

	"github.com/dexidp/dex/storage"
)

// Token family graph CRUD for the Kubernetes backend. Updates ride the same
// resourceVersion compare-and-swap the other resources use (retryOnConflict on
// 409), so the grace-period claim is a storage-level CAS rather than an
// application lock.

func (cli *client) CreateTokenFamily(ctx context.Context, f storage.TokenFamily) error {
	return cli.post(resourceTokenFamily, cli.fromStorageTokenFamily(f))
}

func (cli *client) getTokenFamily(id string) (f TokenFamily, err error) {
	err = cli.get(resourceTokenFamily, id, &f)
	return f, err
}

func (cli *client) GetTokenFamily(ctx context.Context, id string) (storage.TokenFamily, error) {
	f, err := cli.getTokenFamily(id)
	if err != nil {
		return storage.TokenFamily{}, err
	}
	return toStorageTokenFamily(f), nil
}

func (cli *client) UpdateTokenFamily(ctx context.Context, id string, updater func(f storage.TokenFamily) (storage.TokenFamily, error)) error {
	return retryOnConflict(ctx, func() error {
		current, err := cli.getTokenFamily(id)
		if err != nil {
			return err
		}

		updated, err := updater(toStorageTokenFamily(current))
		if err != nil {
			return err
		}
		updated.ID = id

		newFamily := cli.fromStorageTokenFamily(updated)
		newFamily.ObjectMeta = current.ObjectMeta
		return cli.put(resourceTokenFamily, current.ObjectMeta.Name, newFamily)
	})
}

func (cli *client) DeleteTokenFamily(ctx context.Context, id string) error {
	return cli.delete(resourceTokenFamily, id)
}

func (cli *client) CreateTokenNode(ctx context.Context, n storage.TokenNode) error {
	return cli.post(resourceTokenNode, cli.fromStorageTokenNode(n))
}
func (cli *client) getTokenNode(id string) (n TokenNode, err error) {
	err = cli.get(resourceTokenNode, id, &n)
	return n, err
}

func (cli *client) GetTokenNode(ctx context.Context, id string) (storage.TokenNode, error) {
	n, err := cli.getTokenNode(id)
	if err != nil {
		return storage.TokenNode{}, err
	}
	return toStorageTokenNode(n), nil
}

func (cli *client) ListTokenNodes(ctx context.Context, familyID string) ([]storage.TokenNode, error) {
	var list TokenNodeList
	if err := cli.list(resourceTokenNode, &list); err != nil {
		return nil, err
	}

	nodes := make([]storage.TokenNode, 0, len(list.TokenNodes))
	for _, n := range list.TokenNodes {
		if n.FamilyID == familyID {
			nodes = append(nodes, toStorageTokenNode(n))
		}
	}
	return nodes, nil
}

func (cli *client) UpdateTokenNode(ctx context.Context, id string, updater func(n storage.TokenNode) (storage.TokenNode, error)) error {
	return retryOnConflict(ctx, func() error {
		current, err := cli.getTokenNode(id)
		if err != nil {
			return err
		}

		updated, err := updater(toStorageTokenNode(current))
		if err != nil {
			return err
		}
		updated.ID = id

		newNode := cli.fromStorageTokenNode(updated)
		newNode.ObjectMeta = current.ObjectMeta
		return cli.put(resourceTokenNode, current.ObjectMeta.Name, newNode)
	})
}

func (cli *client) DeleteTokenNode(ctx context.Context, id string) error {
	return cli.delete(resourceTokenNode, id)
}
