// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package genericveth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/netns"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	"github.com/cilium/cilium/plugins/cilium-cni/lib"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

type GenericVethChainer struct{}

// primaryInterfaceName is what the container runtime calls the default
// network's interface (containerd uses "eth0",
// internal/cri/server/helpers.go). It is only used to warn about a likely
// missing “secondary-interface“ declaration, never to decide: see
// types.NetConf.SecondaryInterface.
const primaryInterfaceName = "eth0"

// validateAttachmentCEPName checks the CiliumEndpoint name this attachment
// will require. It is a Kubernetes object name, so it has to be valid as a
// whole: an interface name that is not a DNS-1123 label ("vpc_0" is a legal
// Linux name), or a pod name long enough to push the result past the
// 253-character limit, would make every CiliumEndpoint write fail long after
// CNI ADD returned, leaving the attachment without an identity on every other
// node. Reject it here instead, where the error reaches the user.
func validateAttachmentCEPName(podName, ifName string) error {
	if errs := validation.IsDNS1123Label(ifName); len(errs) > 0 {
		return fmt.Errorf("interface name %q cannot be used by a secondary interface: it must be a DNS-1123 label so that the CiliumEndpoint name is valid (%s)",
			ifName, strings.Join(errs, "; "))
	}
	if podName == "" {
		// Not a Kubernetes workload: there is no CiliumEndpoint to name.
		return nil
	}
	cepName := endpointid.AttachmentCEPName(podName, ifName)
	if errs := validation.IsDNS1123Subdomain(cepName); len(errs) > 0 {
		return fmt.Errorf("pod %q cannot carry a secondary interface named %q: its CiliumEndpoint would be named %q (%s)",
			podName, ifName, cepName, strings.Join(errs, "; "))
	}
	return nil
}

func (f *GenericVethChainer) Add(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) (res *cniTypesVer.Result, err error) {
	err = cniVersion.ParsePrevResult(&pluginCtx.NetConf.NetConf)
	if err != nil {
		err = fmt.Errorf("unable to understand network config: %w", err)
		return
	}

	var prevRes *cniTypesVer.Result
	prevRes, err = cniTypesVer.NewResultFromResult(pluginCtx.NetConf.PrevResult)
	if err != nil {
		err = fmt.Errorf("unable to get previous network result: %w", err)
		return
	}

	defer func() {
		if err != nil {
			pluginCtx.Logger.Error(
				"Unable to create endpoint",
				logfields.Error, err,
				logfields.Previous, pluginCtx.NetConf.PrevResult,
			)
		}
	}()
	var (
		hostMac, vethHostName, vethLXCMac, vethLXCName, vethIP, vethIPv6 string
		vethHostIdx, peerIndex                                           int
		peer                                                             netlink.Link
	)

	ns, err := netns.OpenPinned(pluginCtx.Args.Netns)
	if err != nil {
		return nil, fmt.Errorf("failed to open netns %q: %w", pluginCtx.Args.Netns, err)
	}
	defer ns.Close()

	if err = ns.Do(func() error {
		links, err := safenetlink.LinkList()
		if err != nil {
			return err
		}

		linkFound := false
		for _, link := range links {
			pluginCtx.Logger.Debug(
				"Found interface in container",
				logfields.Interface, link.Attrs(),
			)

			if link.Type() != "veth" {
				continue
			}

			// Pick the interface this CNI ADD is about. With multus a pod has
			// several veth interfaces (eth0 plus net1, net2, ...) and the
			// plugin is invoked once per attachment, so taking the first veth
			// found would create a second endpoint for eth0 instead of one for
			// the attachment.
			if link.Attrs().Name != pluginCtx.Args.IfName {
				continue
			}

			vethLXCMac = link.Attrs().HardwareAddr.String()
			vethLXCName = link.Attrs().Name

			veth, ok := link.(*netlink.Veth)
			if !ok {
				return fmt.Errorf("link %s is not a veth interface", vethHostName)
			}

			peerIndex, err = netlink.VethPeerIndex(veth)
			if err != nil {
				return fmt.Errorf("unable to retrieve index of veth peer %s: %w", vethHostName, err)
			}

			addrs, err := safenetlink.AddrList(link, netlink.FAMILY_V4)
			if err == nil && len(addrs) > 0 {
				vethIP = addrs[0].IPNet.IP.String()
			} else if err != nil {
				pluginCtx.Logger.Warn(
					"No valid IPv4 address found",
					logfields.Error, err,
					logfields.Interface, link.Attrs().Name,
				)
			}

			addrsv6, err := safenetlink.AddrList(link, netlink.FAMILY_V6)
			if err == nil && len(addrsv6) > 0 {
				if len(addrsv6) == 1 {
					vethIPv6 = addrsv6[0].IPNet.IP.String()
				} else {
					for _, addrv6 := range addrsv6 {
						if addrv6.IP.IsGlobalUnicast() {
							vethIPv6 = addrv6.IPNet.IP.String()
							break
						}
					}
				}
			} else if err != nil {
				pluginCtx.Logger.Warn(
					"No valid IPv6 address found",
					logfields.Error, err,
					logfields.Interface, link.Attrs().Name,
				)
			}

			linkFound = true
			break
		}

		if !linkFound {
			return fmt.Errorf("no link %q found inside container", pluginCtx.Args.IfName)
		}

		if pluginCtx.NetConf.EnableRouteMTU || pluginCtx.CiliumConf.EnableRouteMTUForCNIChaining {
			routes, err := safenetlink.RouteList(nil, netlink.FAMILY_V4)
			if err != nil {
				err = fmt.Errorf("unable to list the IPv4 routes: %w", err)
				return err
			}
			for _, rt := range routes {
				if rt.MTU != int(pluginCtx.CiliumConf.RouteMTU) {
					rt.MTU = int(pluginCtx.CiliumConf.RouteMTU)
					err = netlink.RouteReplace(&rt)
					if err != nil {
						err = fmt.Errorf("unable to replace the mtu %d for the route %s: %s", rt.MTU, rt.String(), err.Error())
						return err
					}
				}
			}

			routes, err = safenetlink.RouteList(nil, netlink.FAMILY_V6)
			if err != nil {
				err = fmt.Errorf("unable to list the IPv6 routes: %w", err)
				return err
			}
			for _, rt := range routes {
				if rt.MTU != int(pluginCtx.CiliumConf.RouteMTU) {
					rt.MTU = int(pluginCtx.CiliumConf.RouteMTU)
					err = netlink.RouteReplace(&rt)
					if err != nil {
						err = fmt.Errorf("unable to replace the mtu %d for the route %s: %s", rt.MTU, rt.String(), err.Error())
						return err
					}
				}
			}
		}

		return nil
	}); err != nil {
		return
	}

	peer, err = netlink.LinkByIndex(peerIndex)
	if err != nil {
		err = fmt.Errorf("unable to lookup link %d: %w", peerIndex, err)
		return
	}

	hostMac = peer.Attrs().HardwareAddr.String()
	vethHostName = peer.Attrs().Name
	vethHostIdx = peer.Attrs().Index

	switch {
	case vethHostName == "":
		err = errors.New("unable to determine name of veth pair on the host side")
		return
	case vethLXCMac == "":
		err = errors.New("unable to determine MAC address of veth pair on the container side")
		return
	case vethIP == "" && vethIPv6 == "":
		err = errors.New("unable to determine IP address of the container")
		return
	case vethHostIdx == 0:
		err = errors.New("unable to determine index interface of veth pair on the host side")
		return
	}

	var disabled = false
	// An attachment is declared by the CNI configuration, never guessed from the
	// interface name (see types.NetConf.SecondaryInterface).
	secondary := pluginCtx.NetConf.SecondaryInterface
	if secondary {
		if err = validateAttachmentCEPName(string(pluginCtx.CniArgs.K8S_POD_NAME), pluginCtx.Args.IfName); err != nil {
			return nil, err
		}
	} else if pluginCtx.Args.IfName != primaryInterfaceName {
		pluginCtx.Logger.Warn(
			"Interface is not the usual primary name and is not declared as a secondary interface; "+
				"if this is a multus attachment, set \"secondary-interface\": true in its cilium-cni configuration, "+
				"otherwise it will share the pod's legacy identifiers and CiliumEndpoint with the primary endpoint",
			logfields.Interface, pluginCtx.Args.IfName,
		)
	}
	ep := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPv4: vethIP,
			IPv6: vethIPv6,
		},
		ContainerID:            pluginCtx.Args.ContainerID,
		State:                  models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		HostMac:                hostMac,
		InterfaceIndex:         int64(vethHostIdx),
		Mac:                    vethLXCMac,
		InterfaceName:          vethHostName,
		ContainerInterfaceName: vethLXCName,
		// A secondary (multus) attachment shares the container ID and the pod
		// name with the pod's primary endpoint, so it must be addressed by its
		// CNI attachment ID only: the legacy identifiers would collide and its
		// CiliumEndpoint would overwrite the primary one. The primary endpoint
		// keeps them, so existing deployments are unaffected.
		DisableLegacyIdentifiers: secondary,
		K8sPodName:               string(pluginCtx.CniArgs.K8S_POD_NAME),
		K8sNamespace:             string(pluginCtx.CniArgs.K8S_POD_NAMESPACE),
		K8sUID:                   string(pluginCtx.CniArgs.K8S_POD_UID),
		SyncBuildEndpoint:        true,
		DatapathConfiguration: &models.EndpointDatapathConfiguration{
			// aws-cni requires ARP passthrough between Linux and
			// the pod
			RequireArpPassthrough: true,

			// The route is pointing directly into the veth of the
			// pod, install a host-facing egress program to
			// implement ingress policy and to provide reverse NAT
			RequireEgressProg: true,

			// The IP is managed by the aws-cni plugin, no need for
			// Cilium to manage any aspect of addressing
			ExternalIpam: true,

			// All routing is performed by the Linux stack
			RequireRouting: &disabled,
		},
	}

	scopedLogger := pluginCtx.Logger.With(
		logfields.ContainerID, ep.ContainerID,
		logfields.ContainerInterface, ep.ContainerInterfaceName,
	)
	var newEp *models.Endpoint
	newEp, err = cli.EndpointCreate(ep)
	if err != nil {
		scopedLogger.Warn("Unable to create endpoint", logfields.Error, err)
		err = fmt.Errorf("unable to create endpoint: %w", err)
		return
	}
	if newEp != nil && newEp.Status != nil && newEp.Status.Networking != nil && newEp.Status.Networking.Mac != "" &&
		newEp.Status.Networking.Mac != vethLXCMac {

		err = ns.Do(func() error {
			return mac.ReplaceMacAddressWithLinkName(vethLXCName, newEp.Status.Networking.Mac)
		})
		if err != nil {
			err = fmt.Errorf("unable to set MAC address on interface %s: %w", vethLXCName, err)
			return
		}
		for i := range prevRes.Interfaces {
			if prevRes.Interfaces[i].Name == vethLXCName {
				prevRes.Interfaces[i].Mac = newEp.Status.Networking.Mac
			}
		}
	}
	scopedLogger.Debug("Endpoint successfully created")

	res = prevRes

	return
}

func (f *GenericVethChainer) Delete(ctx context.Context, pluginCtx chainingapi.PluginContext, delClient *lib.DeletionFallbackClient) (err error) {
	// shortcut: deletes every endpoint of the container, not just the
	// attachment this CNI DEL is about. Harmless today because a pod is torn
	// down as a whole: multus deletes its delegates in reverse order, so the
	// attachment's DEL runs first and takes the primary endpoint with it, and
	// the primary's own DEL is then the no-op. Delete by CNI attachment ID once
	// an interface can be detached from a running pod.
	req := &models.EndpointBatchDeleteRequest{ContainerID: pluginCtx.Args.ContainerID}
	if err := delClient.EndpointDeleteMany(req); err != nil {
		if errors.Is(err, lib.ErrClientFailure) {
			pluginCtx.Logger.Error("Failed to delete endpoint", logfields.Error, err)
			return err
		}

		pluginCtx.Logger.Warn(
			"Errors encountered while deleting endpoint",
			logfields.Error, err,
		)
	}
	return nil
}

func (f *GenericVethChainer) Check(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) error {
	// Just confirm that the endpoint is healthy
	eID := endpointid.NewCNIAttachmentID(pluginCtx.Args.ContainerID, pluginCtx.Args.IfName)
	pluginCtx.Logger.Warn(
		"Asking agent for healthz for endpoint",
		logfields.EndpointID, eID,
	)
	epHealth, err := cli.EndpointHealthGet(eID)
	if err != nil {
		return cniTypes.NewError(types.CniErrHealthzGet, "HealthzFailed",
			fmt.Sprintf("failed to retrieve container health: %s", err))
	}

	if epHealth.OverallHealth == models.EndpointHealthStatusFailure {
		return cniTypes.NewError(types.CniErrUnhealthy, "Unhealthy",
			"container is unhealthy in agent")
	}
	pluginCtx.Logger.Debug(
		"Container has a healthy agent endpoint",
		logfields.ContainerID, pluginCtx.Args.ContainerID,
		logfields.Interface, pluginCtx.Args.IfName,
	)
	return nil
}

func (f *GenericVethChainer) Status(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) error {
	if _, err := cli.Daemon.GetHealthz(nil); err != nil {
		return cniTypes.NewError(types.CniErrPluginNotAvailable, "DaemonHealthzFailed",
			fmt.Sprintf("Cilium agent healthz check failed: %s", client.Hint(err)))
	}
	return nil
}

func init() {
	chainingapi.Register("generic-veth", &GenericVethChainer{})
}
