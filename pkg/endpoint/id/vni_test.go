// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package id

import "testing"

func TestSplitVNIIP(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		ok                bool
	}{
		{"v4", "36:192.0.2.1", "192.0.2.1", true},
		{"v6", "17:2001:db8::1", "2001:db8::1", true},
		{"missing vni", ":192.0.2.1", "", false},
		{"invalid vni", "x:192.0.2.1", "", false},
		{"missing ip", "36:", "", false},
		{"invalid ip", "36:not-an-ip", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SplitVNIIP(tc.input)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("SplitVNIIP(%q) = (%q, %v), want (%q, %v)", tc.input, got, ok, tc.want, tc.ok)
			}
		})
	}
}
