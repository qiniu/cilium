// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bandwidth

import (
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/option"
)

func newTestManager(t *testing.T, chainingMode string) *manager {
	t.Helper()

	db := statedb.New()
	tbl, err := bwmap.NewEdtTable(db)
	require.NoError(t, err)

	return &manager{
		enabled: true,
		params: bandwidthManagerParams{
			DB:           db,
			EdtTable:     tbl,
			DaemonConfig: &option.DaemonConfig{CNIChainingMode: chainingMode},
		},
	}
}

func limits(t *testing.T, m *manager, epID uint16) map[uint8]uint64 {
	t.Helper()

	out := map[uint8]uint64{}
	for _, direction := range []uint8{DirectionEgress, DirectionIngress, DirectionEgressPolice} {
		obj, _, found := m.params.EdtTable.Get(m.params.DB.ReadTxn(), bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
			EndpointID: epID,
			Direction:  direction,
		}))
		if found {
			out[direction] = obj.BytesPerSecond
		}
	}
	return out
}

// TestEgressLimitIsPolicedWhenChained pins where the egress limit is enforced.
// Outside CNI chaining it is paced by EDT in cil_to_netdev, which needs
// nothing but the egress entry. In generic-veth chaining the chained CNI
// re-injects the packet into the stack, dropping the EDT aggregate carried in
// skb->queue_mapping, so cil_to_netdev never matches the endpoint: the limit
// has to be policed in cil_from_container, which reads the extra entry written
// here. Writing that entry unconditionally would police traffic that EDT
// already paces.
func TestEgressLimitIsPolicedWhenChained(t *testing.T) {
	const epID = 1234

	chained := newTestManager(t, "generic-veth")
	chained.UpdateBandwidthLimit(epID, 1250000, 0)
	require.Equal(t, map[uint8]uint64{
		DirectionEgress:       1250000,
		DirectionEgressPolice: 1250000,
	}, limits(t, chained, epID), "chained: the policer needs its own entry, with the same limit")

	plain := newTestManager(t, "none")
	plain.UpdateBandwidthLimit(epID, 1250000, 0)
	require.Equal(t, map[uint8]uint64{
		DirectionEgress: 1250000,
	}, limits(t, plain, epID), "not chained: EDT paces, no policer entry")

	// Both entries have to go, or a stale policer would keep dropping the
	// traffic of an endpoint whose limit was removed.
	chained.DeleteBandwidthLimit(epID)
	require.Empty(t, limits(t, chained, epID))
}
