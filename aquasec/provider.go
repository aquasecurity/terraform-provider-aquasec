package aquasec

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/mitchellh/go-homedir"
)

//Config - godoc
type Config struct {
	Username string `json:"tenant"`
	Password string `json:"token"`
	AquaURL  string `json:"aqua_url"`
}

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
				DefaultFunc: schema.EnvDefaultFunc("AQUA_CONFIG", "~/.aquasec/tf.config"),
				Description: "This is the file path for Aqua provider configuration. The default configuration path is ~/.aqua/tf.config",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"aquasec_user":                 resourceUser(),
			"aquasec_integration_registry": resourceRegistry(),
			"aquasec_firewall_policy":      resourceFirewallPolicy(),
			"aquasec_service":              resourceService(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"aquasec_users":                  dataSourceUsers(),
			"aquasec_integration_registries": dataSourceRegistry(),
			"aquasec_firewall_policy":        dataSourceFirewallPolicy(),
			"aquasec_service":                dataSourceService(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func getProviderConfigurationFromFile(d *schema.ResourceData) (string, string, string, error) {
	log.Print("[DEBUG] Trying to load configuration from file")
	if configPath, ok := d.GetOk("config_path"); ok && configPath.(string) != "" {
		path, err := homedir.Expand(configPath.(string))
		if err != nil {
			log.Printf("[DEBUG] Failed to expand config file path %s, error %s", configPath, err)
			return "", "", "", nil
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			log.Printf("[DEBUG] Terraform config file %s does not exist, error %s", path, err)
			return "", "", "", nil
		}
		log.Printf("[DEBUG] Terraform configuration file is: %s", path)
		configFile, err := os.Open(path)
		if err != nil {
			log.Printf("[DEBUG] Unable to open Terraform configuration file %s", path)
			return "", "", "", fmt.Errorf("Unable to open terraform configuration file. Error %v", err)
		}
		defer configFile.Close()

		configBytes, _ := ioutil.ReadAll(configFile)
		var config Config
		err = json.Unmarshal(configBytes, &config)
		if err != nil {
			log.Printf("[DEBUG] Failed to parse config file %s", path)
			return "", "", "", fmt.Errorf("Invalid terraform configuration file format. Error %v", err)
		}
		return config.Username, config.Password, config.AquaURL, nil
	}
	return "", "", "", nil
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	fmt.Println("----------------------------------------")
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
