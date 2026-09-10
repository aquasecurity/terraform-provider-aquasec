package main

import (
	"github.com/aquasecurity/terraform-provider-aquasec/aquasec"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

var version string

func main() {
	plugin.Serve(&plugin.ServeOpts{
		GRPCProviderFunc: func() tfprotov5.ProviderServer {
			return aquasec.NewGRPCProviderServer(version)
		},
	})
}
