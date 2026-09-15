package aquasec

import (
	"context"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestNormalizeNetworkResource(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		resource     string
		want         string
	}{
		{name: "empty anywhere", resourceType: "anywhere", want: "0.0.0.0/0"},
		{name: "whitespace anywhere", resourceType: "anywhere", resource: "  ", want: "0.0.0.0/0"},
		{name: "explicit anywhere", resourceType: "anywhere", resource: "10.0.0.0/8", want: "10.0.0.0/8"},
		{name: "empty custom", resourceType: "custom", want: ""},
		{name: "explicit custom", resourceType: "custom", resource: "10.0.0.0/8", want: "10.0.0.0/8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeNetworkResource(tt.resourceType, tt.resource); got != tt.want {
				t.Fatalf("normalizeNetworkResource(%q, %q) = %q, want %q", tt.resourceType, tt.resource, got, tt.want)
			}
		})
	}
}

func TestResourceServiceAnywhereRuleCanonicalStateHasNoDiff(t *testing.T) {
	serviceResource := resourceService()
	stateData := schema.TestResourceDataRaw(t, serviceResource.Schema, serviceAnywhereRuleConfig(true))
	stateData.SetId("service-anywhere")

	diff, err := serviceResource.Diff(
		context.Background(),
		stateData.State(),
		terraform.NewResourceConfigRaw(serviceAnywhereRuleConfig(false)),
		nil,
	)
	if err != nil {
		t.Fatalf("calculating service diff: %v", err)
	}
	if !diff.Empty() {
		t.Fatalf("expected no diff when anywhere resources are omitted from config, got %#v", diff.Attributes)
	}
}

func TestExpandServiceCanonicalizesInboundAndOutboundAnywhereRules(t *testing.T) {
	data := schema.TestResourceDataRaw(t, resourceService().Schema, serviceAnywhereRuleConfig(false))

	expanded := expandService(data)
	if len(expanded.LocalPolicies) != 1 {
		t.Fatalf("got %d local policies, want 1", len(expanded.LocalPolicies))
	}

	policy := expanded.LocalPolicies[0]
	for direction, rules := range map[string][]client.NetworkRule{
		"inbound":  policy.InboundNetworks,
		"outbound": policy.OutboundNetworks,
	} {
		if len(rules) != 1 {
			t.Fatalf("got %d %s rules, want 1", len(rules), direction)
		}
		if rules[0].Resource != anywhereNetworkResourceCIDR {
			t.Errorf("%s resource = %q, want %q", direction, rules[0].Resource, anywhereNetworkResourceCIDR)
		}
	}
}

func serviceAnywhereRuleConfig(includeCanonicalResource bool) map[string]interface{} {
	networkRule := func(portRange string, allow bool) map[string]interface{} {
		rule := map[string]interface{}{
			"port_range":    portRange,
			"resource_type": anywhereNetworkResourceType,
			"allow":         allow,
		}
		if includeCanonicalResource {
			rule["resource"] = anywhereNetworkResourceCIDR
		}
		return rule
	}

	return map[string]interface{}{
		"name":               "service-anywhere",
		"application_scopes": []interface{}{"Global"},
		"policies":           []interface{}{"local-policy"},
		"target":             "container",
		"local_policies": []interface{}{
			map[string]interface{}{
				"name":              "local-policy",
				"type":              "access.control",
				"inbound_networks":  []interface{}{networkRule("22", true)},
				"outbound_networks": []interface{}{networkRule("443", false)},
			},
		},
	}
}
