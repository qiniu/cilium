// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package classtree

import (
	"fmt"
	"math"

	"k8s.io/apimachinery/pkg/api/resource"
)

// Policy contains only the directions opted into class scheduling. A nil
// direction stays on the aggregate bandwidth manager, even if it has an
// existing kubernetes.io bandwidth annotation.
type Policy struct {
	Ingress, Egress *Limits
}

// ParsePolicy reads one snapshot. On an invalid change it returns no partial
// policy: the caller can keep the previous working schedule in both directions.
// This parser is not an admission webhook; call it only for generic-veth.
func ParsePolicy(annotations map[string]string) (Policy, error) {
	var p Policy
	for _, d := range []struct {
		name   string
		limits **Limits
	}{{"ingress", &p.Ingress}, {"egress", &p.Egress}} {
		ns := "qos.cilium.io/north-south-" + d.name + "-bandwidth"
		if _, override := annotations[ns]; !override {
			continue
		}
		l := new(Limits)
		for _, field := range []struct {
			key   string
			value *uint64
		}{{ns, &l.NorthSouth}, {"kubernetes.io/" + d.name + "-bandwidth", &l.Default}} {
			s, ok := annotations[field.key]
			if !ok {
				continue
			}
			q, err := resource.ParseQuantity(s)
			if err != nil {
				return Policy{}, fmt.Errorf("%s: %w", field.key, err)
			}
			if q.Sign() <= 0 || q.CmpInt64(math.MaxUint32*8) > 0 {
				return Policy{}, fmt.Errorf("%s: rate %q out of range", field.key, s)
			}
			rate := q.Value()
			if q.CmpInt64(rate) != 0 {
				return Policy{}, fmt.Errorf("%s: expected whole bits/s", field.key)
			}
			*field.value = uint64(rate)
		}
		if _, err := plan(*l); err != nil {
			return Policy{}, fmt.Errorf("%s: %w", d.name, err)
		}
		*d.limits = l
	}
	return p, nil
}
