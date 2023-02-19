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

// Config - godoc
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
				Description: "This is the user id that should be used to make the connection. Can alternatively be sourced from the `AQUA_USER` environment variable.",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_PASSWORD", nil),
				Description: "This is the password that should be used to make the connection. Can alternatively be sourced from the `AQUA_PASSWORD` environment variable.",
			},
			"aqua_url": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_URL", nil),
				Description: "This is the base URL of your Aqua instance. Can alternatively be sourced from the `AQUA_URL` environment variable.",
			},
			"verify_tls": {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_TLS_VERIFY", true),
				Description: "If true, server tls certificates will be verified by the client before making a connection. Defaults to true. Can alternatively be sourced from the `AQUA_TLS_VERIFY` environment variable.",
			},
			"ca_certificate_path": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_CA_CERT_PATH", nil),
				Description: "This is the file path for server CA certificates if they are not available on the host OS. Can alternatively be sourced from the `AQUA_CA_CERT_PATH` environment variable.",
			},
			"config_path": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_CONFIG", "~/.aquasec/tf.config"),
				Description: "This is the file path for Aqua provider configuration. The default configuration path is `~/.aqua/tf.config`. Can alternatively be sourced from the `AQUA_CONFIG` environment variable.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"aquasec_user":                        resourceUser(),
			"aquasec_role":                        resourceRole(),
			"aquasec_integration_registry":        resourceRegistry(),
			"aquasec_firewall_policy":             resourceFirewallPolicy(),
			"aquasec_enforcer_groups":             resourceEnforcerGroup(),
			"aquasec_service":                     resourceService(),
			"aquasec_image":                       resourceImage(),
			"aquasec_notification_slack":          resourceNotificationOld(),
			"aquasec_container_runtime_policy":    resourceContainerRuntimePolicy(),
			"aquasec_function_runtime_policy":     resourceFunctionRuntimePolicy(),
			"aquasec_host_runtime_policy":         resourceHostRuntimePolicy(),
			"aquasec_host_assurance_policy":       resourceHostAssurancePolicy(),
			"aquasec_image_assurance_policy":      resourceImageAssurancePolicy(),
			"aquasec_kubernetes_assurance_policy": resourceKubernetesAssurancePolicy(),
			"aquasec_function_assurance_policy":   resourceFunctionAssurancePolicy(),
			"aquasec_application_scope":           resourceApplicationScope(),
			"aquasec_permissions_sets":            resourcePermissionSet(),
			//"aquasec_sso":						 resourceSSO(),
			"aquasec_role_mapping": resourceRoleMapping(),
			"aquasec_aqua_label":   resourceAquaLabels(),
			"aquasec_acknowledge":  resourceAcknowledge(),
			"aquasec_notification": resourceSourceNotification(),
			//saas
			"aquasec_group":             resourceGroup(),
			"aquasec_user_saas":         resourceUserSaas(),
			"aquasec_role_mapping_saas": resourceRoleMappingSaas(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"aquasec_users":                       dataSourceUsers(),
			"aquasec_roles":                       dataSourceRoles(),
			"aquasec_integration_registries":      dataSourceRegistry(),
			"aquasec_firewall_policy":             dataSourceFirewallPolicy(),
			"aquasec_enforcer_groups":             dataSourceEnforcerGroup(),
			"aquasec_service":                     dataSourceService(),
			"aquasec_image":                       dataImage(),
			"aquasec_container_runtime_policy":    dataContainerRuntimePolicy(),
			"aquasec_function_runtime_policy":     dataFunctionRuntimePolicy(),
			"aquasec_host_runtime_policy":         dataHostRuntimePolicy(),
			"aquasec_image_assurance_policy":      dataImageAssurancePolicy(),
			"aquasec_kubernetes_assurance_policy": dataKubernetesAssurancePolicy(),
			"aquasec_host_assurance_policy":       dataHostAssurancePolicy(),
			"aquasec_function_assurance_policy":   dataFunctionAssurancePolicy(),
			"aquasec_gateways":                    dataSourceGateways(),
			"aquasec_application_scope":           dataApplicationScope(),
			"aquasec_permissions_sets":            dataSourcePermissionsSets(),
			"aquasec_integration_state":           dataIntegrationState(),
			//"aquasec_sso":							 	dataSourceSSO(),
			"aquasec_roles_mapping": dataSourceRolesMapping(),
			"aquasec_aqua_labels":   dataSourceAquaLabels(),
			"aquasec_acknowledges":  dataSourceAcknowledges(),
			"aquasec_notifications": dataSourceNotification(),
			//saas:
			"aquasec_groups":             dataSourceGroups(),
			"aquasec_users_saas":         dataSourceUsersSaas(),
			"aquasec_roles_mapping_saas": dataSourceRolesMappingSaas(),
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
	verifyTLS := d.Get("verify_tls").(bool)
	caCertPath := d.Get("ca_certificate_path").(string)

	if username == "" && password == "" && aquaURL == "" {
		username, password, aquaURL, err = getProviderConfigurationFromFile(d)
		if err != nil {
			return nil, diag.FromErr(err)
		}
	}

	if username == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Initializing provider, username parameter is missing.",
		})
	}

	if password == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Initializing provider, password parameter is missing.",
		})
	}

	if aquaURL == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Initializing provider, aqua_url parameter is missing.",
		})
	}

	var caCertByte []byte
	if caCertPath != "" {
		caCertByte, err = ioutil.ReadFile(caCertPath)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to read CA certificates",
				Detail:   err.Error(),
			})

			return nil, diags
		}
	}

	if diags != nil && len(diags) > 0 {
		return nil, diags
	}

	aquaClient := client.NewClient(aquaURL, username, password, verifyTLS, caCertByte)

	token, tokenPresent := os.LookupEnv("TESTING_AUTH_TOKEN")

	url, urlPresent := os.LookupEnv("TESTING_URL")

	if !tokenPresent || !urlPresent {
		_, _, err = aquaClient.GetAuthToken()

		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to fetch token",
				Detail:   err.Error(),
			})

			return nil, diags
		}
	} else {
		aquaClient.SetAuthToken(token)
		aquaClient.SetUrl(url)

	}

	return aquaClient, diags
}
