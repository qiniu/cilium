// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

var goleakOptions = []testutils.GoleakOption{
	// Ignore all the currently running goroutines spawned
	// by prior tests or by package init() functions (like the
	// client-go logger).
	testutils.GoleakIgnoreCurrent(),
	// Ignore goroutines started by the policy trifecta, see [newPolicyTrifecta].
	testutils.GoleakIgnoreTopFunction("github.com/cilium/cilium/pkg/identity/cache.(*identityWatcher).watch.func1"),
	testutils.GoleakIgnoreTopFunction("github.com/cilium/cilium/pkg/trigger.(*Trigger).waiter"),
	// Ignore goroutine started by the ipset reconciler rate limiter
	testutils.GoleakIgnoreTopFunction("github.com/cilium/cilium/pkg/rate.NewLimiter.func1"),
}

// TestAgentCell verifies that the Agent hive can be instantiated with
// default configuration and thus the Agent hive can be inspected with
// the hive commands and documentation can be generated from it.
func TestAgentCell(t *testing.T) {
	defer testutils.GoleakVerifyNone(t, goleakOptions...)
	defer metrics.Reinitialize()

	logging.SetLogLevelToDebug()

	// Populate config with default values normally set by Viper flag defaults
	option.Config.IPv4ServiceRange = AutoCIDR
	option.Config.IPv6ServiceRange = AutoCIDR

	err := hive.New(Agent).Populate(hivetest.Logger(t))
	assert.NoError(t, err, "Populate()")
}

// TestAgentCellNativeVPC verifies that the agent object graph also builds with
// native-vpc enabled. The mode adds providers and consumers (the VNI-scoped
// ipcache map, the local-ipcache adapter of the identity synchronizer) and
// several consumers reach VNI-aware behavior through optional interfaces; a
// constructor parameter that no cell provides makes the *whole agent* fail to
// start, which no package-level test would catch.
func TestAgentCellNativeVPC(t *testing.T) {
	defer testutils.GoleakVerifyNone(t, goleakOptions...)
	defer metrics.Reinitialize()

	logging.SetLogLevelToDebug()

	option.Config.IPv4ServiceRange = AutoCIDR
	option.Config.IPv6ServiceRange = AutoCIDR

	prevEnabled, prevAnnotation := option.Config.EnableNativeVPC, option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = "ovn.kubernetes.io/tunnel_key"
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prevEnabled
		option.Config.NativeVPCVNIAnnotation = prevAnnotation
	})

	err := hive.New(Agent).Populate(hivetest.Logger(t))
	assert.NoError(t, err, "Populate() with native-vpc enabled")
}
