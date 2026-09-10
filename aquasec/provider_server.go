package aquasec

import (
	"context"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const containerRuntimePolicyTypeName = "aquasec_container_runtime_policy"

type grpcProviderServer struct {
	tfprotov5.ProviderServer
}

// NewGRPCProviderServer returns the protocol server used by the provider.
func NewGRPCProviderServer(version string) tfprotov5.ProviderServer {
	return newGRPCProviderServer(Provider(version))
}

func newGRPCProviderServer(provider *schema.Provider) tfprotov5.ProviderServer {
	return &grpcProviderServer{ProviderServer: schema.NewGRPCProviderServer(provider)}
}

func (s *grpcProviderServer) UpgradeResourceState(ctx context.Context, req *tfprotov5.UpgradeResourceStateRequest) (*tfprotov5.UpgradeResourceStateResponse, error) {
	return s.ProviderServer.UpgradeResourceState(ctx, normalizeContainerRuntimePolicyV0Flatmap(req))
}

func normalizeContainerRuntimePolicyV0Flatmap(req *tfprotov5.UpgradeResourceStateRequest) *tfprotov5.UpgradeResourceStateRequest {
	if req == nil || req.TypeName != containerRuntimePolicyTypeName || req.Version != 0 || req.RawState == nil || len(req.RawState.Flatmap) == 0 {
		return req
	}

	executables, hasLegacyExecutables := legacyFlatmapList(req.RawState.Flatmap, "allowed_executables")
	registries, hasLegacyRegistries := legacyFlatmapList(req.RawState.Flatmap, "allowed_registries")
	if !hasLegacyExecutables && !hasLegacyRegistries {
		return req
	}

	normalizedReq := *req
	normalizedRawState := *req.RawState
	normalizedRawState.Flatmap = cloneFlatmap(req.RawState.Flatmap)
	normalizedReq.RawState = &normalizedRawState

	if hasLegacyExecutables {
		normalizeLegacyFlatmapList(normalizedRawState.Flatmap, "allowed_executables", "allow_executables", executables)
		normalizedRawState.Flatmap["allowed_executables.0.enabled"] = "true"
		normalizedRawState.Flatmap["allowed_executables.0.separate_executables"] = "false"
	}
	if hasLegacyRegistries {
		normalizeLegacyFlatmapList(normalizedRawState.Flatmap, "allowed_registries", "allowed_registries", registries)
		normalizedRawState.Flatmap["allowed_registries.0.enabled"] = "true"
	}

	return &normalizedReq
}

func legacyFlatmapList(flatmap map[string]string, field string) ([]string, bool) {
	count, err := strconv.Atoi(flatmap[field+".#"])
	if err != nil || count <= 0 {
		return nil, false
	}

	values := make([]string, count)
	for i := 0; i < count; i++ {
		value, ok := flatmap[field+"."+strconv.Itoa(i)]
		if !ok {
			return nil, false
		}
		values[i] = value
	}
	return values, true
}

func cloneFlatmap(flatmap map[string]string) map[string]string {
	cloned := make(map[string]string, len(flatmap))
	for key, value := range flatmap {
		cloned[key] = value
	}
	return cloned
}

func normalizeLegacyFlatmapList(flatmap map[string]string, field, nestedField string, values []string) {
	prefix := field + "."
	for key := range flatmap {
		if strings.HasPrefix(key, prefix) {
			delete(flatmap, key)
		}
	}

	flatmap[field+".#"] = "1"
	flatmap[field+".0."+nestedField+".#"] = strconv.Itoa(len(values))
	for i, value := range values {
		flatmap[field+".0."+nestedField+"."+strconv.Itoa(i)] = value
	}
}
