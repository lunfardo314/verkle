package trie

import (
	"sort"
	"strings"
)

// KVStore abstract interface only used in this trie implementation
type KVStore interface {
	Set(k []byte, v []byte)
	Del(k []byte)
	Get(k []byte) ([]byte, bool)
	Has(k []byte) bool
	Partition(prefix string) KVStore
	Keys() []string
	Size() int
}

type kvStoreSimple struct {
	store map[string][]byte
}

func NewSimpleKVStore() *kvStoreSimple {
	return &kvStoreSimple{
		store: make(map[string][]byte),
	}
}

func (kvs *kvStoreSimple) Partition(prefix string) KVStore {
	return &partition{
		store:  kvs,
		prefix: prefix,
	}
}

func (kvs *kvStoreSimple) Set(k []byte, v []byte) {
	t := make([]byte, len(v))
	copy(t, v)
	if len(k) == 0 {
		kvs.store[""] = t
	} else {
		kvs.store[string(k)] = t
	}
}

func (kvs *kvStoreSimple) Del(k []byte) {
	if len(k) == 0 {
		return
	}
	delete(kvs.store, string(k))
}

// nil key always is present
func (kvs *kvStoreSimple) Get(k []byte) ([]byte, bool) {
	key := ""
	if len(k) != 0 {
		key = string(k)
	}
	ret, ok := kvs.store[key]
	return ret, ok
}

func (kvs *kvStoreSimple) Has(k []byte) bool {
	key := ""
	if len(k) != 0 {
		key = string(k)
	}
	_, ok := kvs.store[key]
	return ok
}

func (kvs *kvStoreSimple) Keys() []string {
	ret := make([]string, len(kvs.store))
	for k := range kvs.store {
		ret = append(ret, k)
	}
	sort.Strings(ret)
	return ret
}

func (kvs *kvStoreSimple) Size() int {
	return len(kvs.store)
}

type partition struct {
	store  KVStore
	prefix string
}

func (kvs *partition) Partition(prefix string) KVStore {
	panic("implement me")
}

func (p *partition) Set(k []byte, v []byte) {
	key := []byte(p.prefix + string(k))
	p.store.Set(key, v)
}

func (p *partition) Del(k []byte) {
	key := []byte(p.prefix + string(k))
	p.store.Del(key)
}

func (p *partition) Get(k []byte) ([]byte, bool) {
	key := []byte(p.prefix + string(k))
	return p.store.Get(key)
}

func (p *partition) Has(k []byte) bool {
	key := []byte(p.prefix + string(k))
	return p.store.Has(key)
}

func (p *partition) Keys() []string {
	ret := make([]string, 0)
	for _, k := range p.store.Keys() {
		if strings.HasPrefix(k, p.prefix) {
			ret = append(ret, k[len(p.prefix):])
		}
	}
	sort.Strings(ret)
	return ret

}

func (p *partition) Size() int {
	var ret int
	for _, k := range p.store.Keys() {
		if strings.HasPrefix(k, p.prefix) {
			ret++
		}
	}
	return ret
}
