package aqua

import (
	"fmt"
	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
)

const (
	aquaUser     = "user"
	aquaPassword = "password"
	aquaURL      = "aqua_url"

	// MajorVersion is the major version
	MajorVersion = 0
	// MinorVersion is the minor version
	MinorVersion = 0
	// PatchVersion is the patch version
	PatchVersion = 1
)

// Version is the semver of this aqua
var Version = fmt.Sprintf("%d.%d.%d", MajorVersion, MinorVersion, PatchVersion)

// Provider returns a terraform aqua for Aqua Enterprise
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			aquaUser: {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_USER", nil),
			},
			aquaPassword: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_PASSWORD", nil),
			},
			aquaURL: {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_URL", nil),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"aqua_users":                         resourceUser(),
			"aqua_enforcer_groups":               resourceEnforcerGroup(),
			"aqua_integration_registry":          resourceRegistry(),
			"aqua_integration_serverless":        resourceServerless(),
			"aqua_access_management_scopes":      resourceAccessManagementScope(),
			"aqua_access_management_permissions": resourceAccessManagementPermission(),
			"aqua_access_management_roles":       resourceAccessManagementRole(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"aqua_users":                         dataSourceUser(),
			"aqua_enforcer_groups":               dataSourceEnforcerGroup(),
			"aqua_integration_registry":          dataSourceRegistry(),
			"aqua_integration_serverless":        dataSourceServerless(),
			"aqua_access_management_scopes":      dataSourceAccessManagementScope(),
			"aqua_access_management_permissions": dataSourcePermissionSet(),
			"aqua_access_management_roles":       dataSourceRole(),
		},
		ConfigureFunc: configureProvider,
	}
}

func configureProvider(d *schema.ResourceData) (interface{}, error) {
	user := d.Get(aquaUser).(string)
	password := d.Get(aquaPassword).(string)
	url := d.Get(aquaURL).(string)

	cli := client.NewClient(url, user, password)

	connected := cli.GetAuthToken()

	if !connected {
		log.Fatalln("Failed to retrieve JWT Authorization Token")
	}

	return cli, nil
}
