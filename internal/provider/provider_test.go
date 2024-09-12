package provider

import (
	"context"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/aquasec"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-mux/tf5to6server"
	"github.com/hashicorp/terraform-plugin-mux/tf6muxserver"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

var version string

func TestMuxServer(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"aquasec": func() (tfprotov6.ProviderServer, error) {
				ctx := context.Background()

				upgradedSdkServer, err := tf5to6server.UpgradeServer(
					ctx,
					aquasec.Provider(version).GRPCProvider,
				)

				if err != nil {
					return nil, err
				}

				providers := []func() tfprotov6.ProviderServer{
					providerserver.NewProtocol6(New(version)()),
					func() tfprotov6.ProviderServer {
						return upgradedSdkServer
					},
				}

				muxServer, err := tf6muxserver.NewMuxServer(ctx, providers...)

				if err != nil {
					return nil, err
				}

				return muxServer.ProviderServer(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `data "aquasec_suppression_rules" "test" {}`,
			},
		},
	})
}

const (
	// providerConfig is a shared configuration to combine with the actual
	// test configuration so the AquaSec client is properly configured.
	// It is also possible to use the AQUASEC_ environment variables instead,
	// such as updating the Makefile and running the testing through that tool.
	providerConfig = `
provider "aquasec" {
}
`
)

var (
	// testAccProtoV6ProviderFactories are used to instantiate a provider during
	// acceptance testing. The factory function will be invoked for every Terraform
	// CLI command executed to create a provider server to which the CLI can
	// reattach.
	testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"aquasec": providerserver.NewProtocol6WithError(New("test")()),
	}
)
