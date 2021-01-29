package aqua

import (
	"context"
	"log"

	"github.com/aquasecurity/aqua-sdk-go/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var version string

//Provider - Aquasec Provider
func Provider(v string) *schema.Provider {
	version = v

	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"aquaUser": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_USER", nil),
			},
			"aquaPassword": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_PASSWORD", nil),
			},
			"aquaURL": {
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
		ResourcesMap:         map[string]*schema.Resource{},
		DataSourcesMap:       map[string]*schema.Resource{},
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

	aquaUser := d.Get("aquaUser").(string)
	aquaPassword := d.Get("aquaPassword").(string)
	aquaURL := d.Get("aquaURL").(string)

	if aquaUser == "" && aquaPassword == "" && aquaURL == "" {
		aquaUser, aquaPassword, aquaURL, err = getProviderConfigurationFromFile(d)
		if err != nil {
			return nil, diag.FromErr(err)
		}
	}

	if aquaUser == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Initializing provider, aquaUser parameter is missing",
		})
	}

	if aquaPassword == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Initializing provider, aquaPassword parameter is missing",
		})
	}

	if aquaURL == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Initializing provider, aquaURL parameter is missing",
		})
	}

	if diags != nil && len(diags) > 0 {
		return nil, diags
	}

	aquaClient := client.NewClient(aquaURL, aquaUser, aquaPassword)

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
