// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package classtree

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestParsePolicy(t *testing.T) {
	annotations := map[string]string{"kubernetes.io/ingress-bandwidth": "50M"}
	p, err := ParsePolicy(annotations)
	require.NoError(t, err)
	require.Equal(t, Policy{}, p)
	const key = "qos.cilium.io/east-west-ingress-bandwidth"
	annotations[key] = "1.5M"
	p, err = ParsePolicy(annotations)
	require.NoError(t, err)
	require.Equal(t, Policy{Ingress: &Limits{Total: 50000000, EastWest: 1500000}}, p)
	for _, v := range []string{"", "0", "-1M", "12345.6", "18446744073709551616", "oops"} {
		annotations["qos.cilium.io/north-south-egress-bandwidth"] = v
		p, err = ParsePolicy(annotations)
		require.Error(t, err)
		require.Equal(t, Policy{}, p)
	}
}

func TestLimits(t *testing.T) {
	for _, limits := range []Limits{{}, {Total: 100000}, {EastWest: 1}, {NorthSouth: 8001}, {EastWest: 1 << 40}} {
		_, err := plan(limits)
		require.Error(t, err)
	}
	classes, err := plan(Limits{80000, 160000, 0})
	require.NoError(t, err)
	require.Len(t, classes, 4)
	for _, c := range classes {
		require.EqualValues(t, 80000, c.ceil)
	}
	classes, err = plan(Limits{EastWest: 160000})
	require.NoError(t, err)
	require.Equal(t, []class{{EastWest, 0, 160000, 160000}}, classes)
}

// A veth and its peer stand for the two endpoint queues. Inject class IDs on
// raw test sockets, NOT through Pod-provided priorities in the datapath. Count
// bytes on the opposite link (not offered bytes or qdisc configuration).
func TestPrivilegedClassBandwidth(t *testing.T) {
	testutils.PrivilegedTest(t)
	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		a := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "east"}, PeerName: "west"}
		require.NoError(t, netlink.LinkAdd(a))
		b, err := netlink.LinkByName("west")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(a))
		require.NoError(t, netlink.LinkSetUp(b))
		aLink, err := netlink.LinkByName("east")
		require.NoError(t, err)
		const M = 1000000
		p, err := ParsePolicy(map[string]string{
			"qos.cilium.io/east-west-egress-bandwidth":    "3M",
			"qos.cilium.io/north-south-egress-bandwidth":  "7M",
			"qos.cilium.io/east-west-ingress-bandwidth":   "5M",
			"qos.cilium.io/north-south-ingress-bandwidth": "9M",
		})
		require.NoError(t, err)
		ra, err := Install(aLink, *p.Egress)
		require.NoError(t, err)
		rb, err := Install(b, *p.Ingress)
		require.NoError(t, err)
		_, err = Install(aLink, Limits{EastWest: M})
		require.Error(t, err, "must not replace installed root")
		probe := newProbe(t, aLink, b)
		reverse := newProbe(t, b, aLink)
		// Run in parallel so all four class caps are exercised at once.
		ch := make(chan [3]float64, 1)
		go func() { ch <- probe.run(t, []int{1, 2}) }()
		rev := reverse.run(t, []int{1, 2})
		fwd := <-ch
		check := func(got, want float64) { t.Helper(); require.InDelta(t, want, got, 0.12*want) }
		t.Logf("class-only forward=%v reverse=%v Mbit/s", fwd, rev)
		check(fwd[1], 3)
		check(fwd[2], 7)
		check(rev[1], 5)
		check(rev[2], 9)
		require.NoError(t, ra.Update(Limits{EastWest: 6 * M, NorthSouth: 4 * M}))
		require.ErrorIs(t, ra.Update(Limits{EastWest: M}), ErrRestage)
		updated := probe.run(t, []int{1, 2})
		check(updated[1], 6)
		check(updated[2], 4)
		require.NoError(t, ra.Remove())
		require.NoError(t, rb.Remove())
		_, err = Install(aLink, Limits{Total: 10 * M, EastWest: 3 * M, NorthSouth: 9 * M})
		require.NoError(t, err)
		rate := probe.run(t, []int{1, 2})
		t.Logf("shared parent %v Mbit/s", rate)
		check(rate[1], 3)
		check(rate[2]+rate[1], 10)
		rate = probe.run(t, []int{2})
		check(rate[2], 9) // no fixed partition
		rate = probe.run(t, []int{0})
		check(rate[0], 10) // unknown is not a bypass
		require.NoError(t, unix.SetsockoptInt(probe.tx[0], unix.SOL_SOCKET, unix.SO_PRIORITY, int(ClassID(0))))
		rate = probe.run(t, []int{0})
		require.Zero(t, rate[0], "direct FIFO must be disabled when the parent is capped")
		return nil
	}))
}

const frameSize = 1014

type wireProbe struct {
	rx     int
	tx     [3]int
	dst    unix.SockaddrLinklayer
	frames [3][frameSize]byte
}

func newProbe(t *testing.T, src, dst netlink.Link) *wireProbe {
	t.Helper()
	const proto = 0x88b5
	var word [2]byte
	binary.BigEndian.PutUint16(word[:], proto)
	be := binary.NativeEndian.Uint16(word[:])
	open := func() int {
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(be))
		require.NoError(t, err)
		t.Cleanup(func() { unix.Close(fd) })
		return fd
	}
	p := &wireProbe{rx: open(), dst: unix.SockaddrLinklayer{Protocol: be, Ifindex: src.Attrs().Index, Halen: 6}}
	require.NoError(t, unix.Bind(p.rx, &unix.SockaddrLinklayer{Protocol: be, Ifindex: dst.Attrs().Index}))
	for i, id := range []uint16{0, EastWest, NorthSouth} {
		fd := open()
		p.tx[i] = fd
		if id != 0 {
			require.NoError(t, unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PRIORITY, int(ClassID(id))))
		}
		f := p.frames[i][:]
		copy(f[:6], dst.Attrs().HardwareAddr)
		copy(f[6:12], src.Attrs().HardwareAddr)
		binary.BigEndian.PutUint16(f[12:], proto)
		f[14] = byte(i)
	}
	return p
}

func (p *wireProbe) run(t *testing.T, classes []int) (rates [3]float64) {
	// Offer ~50 Mbit/s to each selected class, warm up, then measure for 2s.
	start := time.Now()
	begin := start.Add(time.Second)
	end := begin.Add(2 * time.Second)
	var buf [2048]byte
	for time.Now().Before(end) {
		for range 6 {
			for _, i := range classes {
				err := unix.Sendto(p.tx[i], p.frames[i][:], 0, &p.dst)
				if err != nil && !errors.Is(err, unix.ENOBUFS) && !errors.Is(err, unix.EAGAIN) {
					t.Errorf("send: %v", err)
					return
				}
			}
		}
		for {
			n, _, err := unix.Recvfrom(p.rx, buf[:], 0)
			if errors.Is(err, unix.EAGAIN) {
				break
			}
			if err != nil {
				t.Errorf("receive: %v", err)
				return
			}
			if n == frameSize && buf[14] < 3 && time.Now().After(begin) {
				rates[buf[14]] += float64(n) * 8
			}
		}
		time.Sleep(time.Millisecond)
	}
	for i := range rates {
		rates[i] /= time.Since(begin).Seconds() * 1e6
	}
	return
}
