package aquasec

import (
	"context"
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider -
func Provider(v string) *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_USER", nil),
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_PASSWORD", nil),
			},
			"aqua_url": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_URL", nil),
			},
			"config_path": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_CONFIG", "~/.aqua/tf.config"),
				Description: "This is the file path for Aqua provider configuration. The default configuration path is ~/.aqua/tf.config",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"aquasec_user": resourceUser(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"aquasec_users": dataSourceUsers(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func getProviderConfigurationFromFile(d *schema.ResourceData) (string, string, string, error) {
	log.Print("[DEBUG] Trying to load configuration from file")
	return "", "", "", nil
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	var err error

	username := d.Get("username").(string)
	password := d.Get("password").(string)
	aquaURL := d.Get("aqua_url").(string)

	if username == "" && password == "" && aquaURL == "" {
		username, password, aquaURL, err = getProviderConfigurationFromFile(d)
		if err != nil {
			return nil, diag.FromErr(err)
		}
	}

	if username == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Initializing provider, username parameter is missing",
		})
	}

	if password == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Initializing provider, password parameter is missing",
		})
	}

	if aquaURL == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Initializing provider, aqua_url parameter is missing",
		})
	}

	if diags != nil && len(diags) > 0 {
		return nil, diags
	}

	aquaClient := client.NewClient(aquaURL, username, password)

	connected := aquaClient.GetAuthToken()

	if !connected {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to fetch token",
			Detail:   "Failed to retrieve JWT Authorization Token",
		})

		return nil, diags
	}

	return aquaClient, diags
}
