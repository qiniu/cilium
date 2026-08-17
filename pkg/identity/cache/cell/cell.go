// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitycachecell

import (
	"cmp"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/stream"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
	"github.com/cilium/cilium/pkg/time"
)

// Cell provides the IdentityAllocator for allocating security identities
var Cell = cell.Module(
	"identity",
	"Allocating and managing security identities",

	cell.Provide(newIdentityAllocator),
	cell.Config(defaultConfig),
)

// CachingIdentityAllocator provides an abstraction over the concrete type in
// pkg/identity/cache so that the underlying implementation can be mocked out
// in unit tests.
type CachingIdentityAllocator interface {
	cache.IdentityAllocator
	clustermesh.RemoteIdentityWatcher

	InitIdentityAllocator(versioned.Interface, kvstore.Client) <-chan struct{}

	// RestoreLocalIdentities reads in the checkpointed local allocator state
	// from disk and allocates a reference to every previously existing identity.
	//
	// Once all identity-allocating objects are synchronized (e.g. network policies,
	// remote nodes), call ReleaseRestoredIdentities to release the held references.
	RestoreLocalIdentities() (map[identity.NumericIdentity]*identity.Identity, error)

	// ReleaseRestoredIdentities releases any identities that were restored, reducing their reference
	// count and cleaning up as necessary.
	ReleaseRestoredIdentities()

	Close()

	LocalIdentityChanges() stream.Observable[cache.IdentityChange]
}

type identityAllocatorParams struct {
	cell.In

	Log       *slog.Logger
	Lifecycle cell.Lifecycle
	IDUpdater policycell.IdentityUpdater

	IdentityHandlers []identity.UpdateIdentities `group:"identity-handlers"`

	Config config
}

type identityAllocatorOut struct {
	cell.Out

	IdentityAllocator      CachingIdentityAllocator
	CacheIdentityAllocator cache.IdentityAllocator
	RemoteIdentityWatcher  clustermesh.RemoteIdentityWatcher
	IdentityObservable     stream.Observable[cache.IdentityChange]
}

type config struct {
	IdentityManagementMode         string `mapstructure:"identity-management-mode"`
	IdentityAllocationTimeout      time.Duration
	IdentityAllocationSyncInterval time.Duration
}

func (c config) Flags(flags *pflag.FlagSet) {
	flags.String(option.IdentityManagementMode, c.IdentityManagementMode, "Configure whether Cilium Identities are managed by cilium-agent, cilium-operator, or both")
	flags.Duration("identity-allocation-timeout", c.IdentityAllocationTimeout, "Timeout for identity allocation operations")
	flags.Duration("identity-allocation-sync-interval", c.IdentityAllocationSyncInterval, "Periodic synchronization interval of the allocated identities")
}

var defaultConfig = config{
	IdentityManagementMode:         option.IdentityManagementModeAgent,
	IdentityAllocationTimeout:      2 * time.Minute,
	IdentityAllocationSyncInterval: allocator.DefaultSyncInterval,
}

// nativeVPCIdentityModeError reports whether the configured identity
// management mode is compatible with native-vpc. The VNI identity label is
// computed by the agent from the pod's tunnel_key annotation; the operator's
// CiliumIdentity controller derives identities from pod and namespace labels
// only, so operator-managed CIDs would drop the VNI label and garbage collect
// the agent's VNI-scoped identities, merging every VPC into one identity.
func nativeVPCIdentityModeError(mode string) error {
	if !option.Config.EnableNativeVPC {
		return nil
	}
	switch mode {
	case option.IdentityManagementModeOperator, option.IdentityManagementModeBoth:
		return fmt.Errorf("native-vpc mode is incompatible with --%s=%s: identities must be managed by the agent so that the VNI identity label is preserved",
			option.IdentityManagementMode, mode)
	}
	return nil
}

func newIdentityAllocator(params identityAllocatorParams) identityAllocatorOut {
	// iao: updates SelectorCache and regenerates endpoints when
	// identity allocation / deallocation has occurred.
	iao := &identityAllocatorOwner{
		IdentityUpdater: params.IDUpdater,
		logger:          params.Log,
	}

	var idAlloc CachingIdentityAllocator

	if option.NetworkPolicyEnabled(option.Config) {
		isOperatorManageCIDsEnabled := cmp.Or(
			params.Config.IdentityManagementMode == option.IdentityManagementModeOperator,
			params.Config.IdentityManagementMode == option.IdentityManagementModeBoth,
		)

		// Native-vpc: the identity of an endpoint carries its VNI label, which
		// is derived from the pod's tunnel_key annotation by the *agent*. The
		// operator's CiliumIdentity controller computes identities from pod and
		// namespace labels only, so with operator-managed CIDs it would create
		// identities without the VNI label, consider the agent's VNI-scoped
		// identities unused and garbage collect them - merging all VPCs into
		// one identity. Refuse to start instead.
		if err := nativeVPCIdentityModeError(params.Config.IdentityManagementMode); err != nil {
			params.Log.Error(
				"native-vpc mode requires agent-managed CiliumIdentities",
				logfields.Error, err,
				logfields.Value, params.Config.IdentityManagementMode,
			)
			params.Lifecycle.Append(cell.Hook{
				OnStart: func(cell.HookContext) error { return err },
			})
		}

		allocatorConfig := cache.AllocatorConfig{
			EnableOperatorManageCIDs: isOperatorManageCIDsEnabled,
			Timeout:                  params.Config.IdentityAllocationTimeout,
			SyncInterval:             params.Config.IdentityAllocationSyncInterval,
		}

		// Allocator: allocates local and cluster-wide security identities.
		cacheIDAlloc := cache.NewCachingIdentityAllocator(params.Log, iao, allocatorConfig)

		if option.Config.RestoreState && !option.Config.DryMode {
			cacheIDAlloc.EnableCheckpointing()
		}

		idAlloc = cacheIDAlloc
	} else {
		idAlloc = cache.NewNoopIdentityAllocator(params.Log)
	}

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hc cell.HookContext) error {
			idAlloc.Close()
			return nil
		},
	})

	identity.IterateReservedIdentities(func(_ identity.NumericIdentity, _ *identity.Identity) {
		metrics.Identity.WithLabelValues(identity.ReservedIdentityType).Inc()
		metrics.IdentityLabelSources.WithLabelValues(labels.LabelSourceReserved).Inc()
	})

	return identityAllocatorOut{
		IdentityAllocator:      idAlloc,
		CacheIdentityAllocator: idAlloc,
		RemoteIdentityWatcher:  idAlloc,
		IdentityObservable:     idAlloc,
	}
}

type identityAllocatorOwner struct {
	policycell.IdentityUpdater
	logger *slog.Logger
}

// GetNodeSuffix returns the suffix to be appended to kvstore keys of this
// agent
func (iao *identityAllocatorOwner) GetNodeSuffix() string {
	var ip net.IP

	switch {
	case option.Config.EnableIPv4:
		ip = node.GetIPv4(iao.logger)
	case option.Config.EnableIPv6:
		ip = node.GetIPv6(iao.logger)
	}

	if ip == nil {
		logging.Fatal(iao.logger, "Node IP not available yet")
	}

	return ip.String()
}
