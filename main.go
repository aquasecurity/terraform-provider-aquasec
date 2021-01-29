package main

import (
	"github.com/aquasecurity/terraform-provider-aquasec/aqua"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

var version string

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return aqua.Provider(version)
		},
	})
}
