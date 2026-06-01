// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/hive"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

// newMetadataFetcherFixture builds a cachedEndpointMetadataFetcher backed by an
// in-memory namespace table seeded with the given namespaces. No reflector is
// registered, so the table is considered initialized immediately and lookups do
// not block.
func newMetadataFetcherFixture(t testing.TB, config *option.DaemonConfig, nss ...daemonk8s.Namespace) *cachedEndpointMetadataFetcher {
	var (
		db  *statedb.DB
		tbl statedb.RWTable[daemonk8s.Namespace]
	)

	logger := hivetest.Logger(t)
	require.NoError(t, hive.New(
		cell.Provide(
			daemonk8s.NewNamespaceTable,
			statedb.RWTable[daemonk8s.Namespace].ToTable,
		),
		cell.Invoke(func(d *statedb.DB, tb statedb.RWTable[daemonk8s.Namespace]) {
			db = d
			tbl = tb
		}),
	).Populate(logger))

	wtxn := db.WriteTxn(tbl)
	for _, ns := range nss {
		_, _, err := tbl.Insert(wtxn, ns)
		require.NoError(t, err)
	}
	wtxn.Commit()

	return &cachedEndpointMetadataFetcher{
		logger:     logger,
		config:     config,
		db:         db,
		namespaces: tbl,
	}
}

func policyDisabledConfig() *option.DaemonConfig {
	return &option.DaemonConfig{
		EnablePolicy:             option.NeverEnforce,
		DisableCiliumEndpointCRD: true,
		IdentityAllocationMode:   option.IdentityAllocationModeCRD,
	}
}

// TestFetchNamespaceExposesAnnotations ensures the namespace annotations (used
// by source IP verification delegation) are resolved regardless of whether
// network policy enforcement is enabled.
func TestFetchNamespaceExposesAnnotations(t *testing.T) {
	const nsName = "team-a"
	delegateAnno := map[string]string{annotation.DelegateSourceIPVerification: "true"}
	ns := daemonk8s.Namespace{Name: nsName, Annotations: delegateAnno}

	policyDisabled := policyDisabledConfig()
	require.False(t, option.NetworkPolicyEnabled(policyDisabled))

	policyEnabled := &option.DaemonConfig{EnableK8sNetworkPolicy: true}
	require.True(t, option.NetworkPolicyEnabled(policyEnabled))

	// Network policy disabled: annotations must still be exposed. This is the
	// regression: previously a name-only namespace was returned and the
	// delegation annotation was silently dropped.
	f := newMetadataFetcherFixture(t, policyDisabled, ns)
	got, err := f.fetchNamespace(nsName)
	require.NoError(t, err)
	require.Equal(t, delegateAnno, got.Annotations)

	// Network policy enabled: behaviour unchanged, annotations exposed.
	f = newMetadataFetcherFixture(t, policyEnabled, ns)
	got, err = f.fetchNamespace(nsName)
	require.NoError(t, err)
	require.Equal(t, delegateAnno, got.Annotations)
}

// TestFetchNamespaceFallsBackWhenMissing ensures endpoint creation is not
// blocked when the namespace cannot be resolved while network policy is
// disabled.
func TestFetchNamespaceFallsBackWhenMissing(t *testing.T) {
	f := newMetadataFetcherFixture(t, policyDisabledConfig())

	got, err := f.fetchNamespace("missing")
	require.NoError(t, err)
	require.Equal(t, "missing", got.Name)
	require.Nil(t, got.Annotations)
}

func TestIsPodStoreOutdatedForUID(t *testing.T) {
	storeUID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	otherUID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	tests := []struct {
		name string
		uid  string
		pod  *slim_corev1.Pod
		want bool
	}{
		{
			name: "empty uid never outdated",
			uid:  "",
			pod:  &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{UID: types.UID(storeUID)}},
			want: false,
		},
		{
			name: "uid match not outdated",
			uid:  storeUID,
			pod:  &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{UID: types.UID(storeUID)}},
			want: false,
		},
		{
			name: "uid mismatch without mirror annotation is outdated",
			uid:  otherUID,
			pod: &slim_corev1.Pod{
				ObjectMeta: slim_metav1.ObjectMeta{
					UID: types.UID(storeUID),
				},
			},
			want: true,
		},
		{
			name: "uid mismatch mirror pod not outdated",
			uid:  otherUID,
			pod: &slim_corev1.Pod{
				ObjectMeta: slim_metav1.ObjectMeta{
					UID: types.UID(storeUID),
					Annotations: map[string]string{
						corev1.MirrorPodAnnotationKey: otherUID,
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPodStoreOutdatedForUID(tt.uid, tt.pod)
			require.Equal(t, tt.want, got)
		})
	}
}
