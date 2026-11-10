// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testipcache

import (
	"maps"
	"net"
	"slices"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/source"
)

// LiveIPCache is the local ipcache of an agent without kvstore, reduced to the
// keys currently present, the identity each maps to, and the order of the
// writes ("+key") and removals ("-key") (ipcache.LocalIPCache).
type LiveIPCache struct {
	mu   lock.Mutex
	keys map[string]identity.NumericIdentity
	ops  []string
}

// NewLiveIPCache returns a LiveIPCache holding keys.
func NewLiveIPCache(keys ...string) *LiveIPCache {
	l := &LiveIPCache{keys: map[string]identity.NumericIdentity{}}
	for _, k := range keys {
		l.keys[k] = identity.IdentityUnknown
	}
	return l
}

func (l *LiveIPCache) Upsert(ip string, _ net.IP, _ uint8, _ *ipcache.K8sMetadata, id ipcache.Identity) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys[ip] = id.ID
	l.ops = append(l.ops, "+"+ip)
	return false, nil
}

func (l *LiveIPCache) DeleteOnMetadataMatch(ip string, _ source.Source, _, _ string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.keys, ip)
	l.ops = append(l.ops, "-"+ip)
	return false
}

// Keys returns the present keys, sorted.
func (l *LiveIPCache) Keys() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Sorted(maps.Keys(l.keys))
}

// Identity returns the identity key maps to.
func (l *LiveIPCache) Identity(key string) (identity.NumericIdentity, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	id, ok := l.keys[key]
	return id, ok
}

// Ops returns the writes and removals in order.
func (l *LiveIPCache) Ops() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.ops)
}
