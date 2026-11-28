# Chained endpoint class scheduler (#74)

This is a candidate scheduling backend, **not an enabled Pod annotation feature**. It has no agent call sites. It can be reviewed and measured independently of how Kube-OVN supplies trustworthy internal/external connection information. The #73 FQ/EDT paths, native routing and old map ABI are unchanged.

`ParsePolicy` reads `qos.cilium.io/{east-west,north-south}-{ingress,egress}-bandwidth` and the existing per-direction total, in Kubernetes quantity syntax. Only directions with class annotations opt in. Missing class caps inherit only the total; missing totals impose no synthetic link-speed cap. Remove an annotation rather than setting it to zero. This backend currently accepts whole-byte rates of 8 kbit/s through `(2^32-1)` bytes/s, rejecting unsupported updates as a whole. It does not impose these bounds on the legacy bandwidth manager.

## Why test HTB rather than chaining two EDT calls?

A single FIFO departure clock shared by the classes can push a second class behind a low-rate class's future head packet even if the total still has capacity. Here HTB selects among independently eligible leaf queues at dequeue time. A direction total is a parent with three children (internal, external, unknown). An idle child's share is available to other children, but each child's ceiling is an upper bound. Without a total, capped children are independent root classes. FQ-CoDel is local to each leaf; these queues do **not** implement the legacy EDT time horizon. Kernel `sch_htb` and `sch_fq_codel` are required for opt-in only.

`Install` prepares a fresh, exclusively owned device. Rate changes retaining the tree topology use `ClassChange`, not root replacement. Other topology changes return `ErrRestage` without altering queues. The caller must stage the replacement before switching traffic; the package does not take over a live veth root, redirect a packet, or classify a connection. With a total, the default child is subject to that total and the HTB direct FIFO is disabled.

## Verification

```sh
PRIVILEGED_TESTS=1 go test -count=1 -v ./pkg/datapath/linux/bandwidth/classtree
```

The privileged test creates a private network namespace, two class trees and a veth pair. Synthetic Ethernet frames are assigned known class IDs on sender sockets. Receiver counts cover four simultaneous caps, rate changes, a contended parent, borrowing when a class goes idle, the unknown default and direct-FIFO exclusion. No Pod routes or host qdiscs are changed. This does **not** validate classification through NAT.

Before enabling this in the agent: provide staging/switch/recovery on both endpoint directions; avoid double scheduling with #73; normalize priority at the last trusted hook, never from Pod metadata; retain host/proxy exemptions; bind the direction/class to trusted peer or connection metadata; report unsupported/unknown paths. An OVN join address alone is not proof of an external LB connection. Repeat the kind SNAT/DNAT tests with concurrent independent workloads after integrating those pieces.
