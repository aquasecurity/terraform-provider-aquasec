package aquasec

import (
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	anywhereNetworkResourceType = "anywhere"
	anywhereNetworkResourceCIDR = "0.0.0.0/0"
)

func normalizeNetworkResource(resourceType, resource string) string {
	if resourceType == anywhereNetworkResourceType && strings.TrimSpace(resource) == "" {
		return anywhereNetworkResourceCIDR
	}
	return resource
}

func suppressEquivalentAnywhereNetworkResourceDiff(key, old, new string, d *schema.ResourceData) bool {
	resourceTypeKey := strings.TrimSuffix(key, ".resource") + ".resource_type"
	resourceType, ok := d.GetOk(resourceTypeKey)
	if !ok || resourceType.(string) != anywhereNetworkResourceType {
		return false
	}

	return strings.TrimSpace(old) == "" && new == anywhereNetworkResourceCIDR ||
		old == anywhereNetworkResourceCIDR && strings.TrimSpace(new) == ""
}
