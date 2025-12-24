package aquasec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/mitchellh/go-homedir"
)

// Config - godoc
type Config struct {
	Username         string   `json:"tenant"`
	Password         string   `json:"token"`
	AquaURL          string   `json:"aqua_url"`
	APIKey           string   `json:"aqua_api_key"`
	SecretKey        string   `json:"aqua_api_secret"`
	Validity         int      `json:"validity"`
	AllowedEndpoints []string `json:"allowed_endpoints"`
	CSPRoles         []string `json:"csp_roles"`
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
			"aqua_api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_API_KEY", nil),
				Description: "API key for authentication. If set, API key mode is used instead of token-based auth.",
			},
			"aqua_api_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AQUA_API_SECRET", nil),
				Description: "Shared secret for API key HMAC signing.",
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
				Description: "This is the file path for Aqua provider configuration. The default configuration path is `~/.aquasec/tf.config`. Can alternatively be sourced from the `AQUA_CONFIG` environment variable.",
			},
			"validate": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Skip provider credential validation when set to false.",
			},
			"validity": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     240,
				Description: "Lifetime of the token, in minutes. Set between 1 and 1500. Once the token expires, need to generate a new one",
			},
			"allowed_endpoints": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "API methods the token has access to",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"csp_roles": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
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
			"aquasec_vmware_assurance_policy":     resourceVMwareAssurancePolicy(),
			"aquasec_image_assurance_policy":      resourceImageAssurancePolicy(),
			"aquasec_kubernetes_assurance_policy": resourceKubernetesAssurancePolicy(),
			"aquasec_function_assurance_policy":   resourceFunctionAssurancePolicy(),
			"aquasec_application_scope":           resourceApplicationScope(),
			"aquasec_application_scope_saas":      resourceApplicationScopeSaas(),
			"aquasec_permissions_sets":            resourcePermissionSet(),
			//"aquasec_sso":						 resourceSSO(),
			"aquasec_role_mapping": resourceRoleMapping(),
			"aquasec_aqua_label":   resourceAquaLabels(),
			"aquasec_acknowledge":  resourceAcknowledge(),
			"aquasec_notification": resourceSourceNotification(),
			//saas
			"aquasec_group":                   resourceGroup(),
			"aquasec_user_saas":               resourceUserSaas(),
			"aquasec_role_mapping_saas":       resourceRoleMappingSaas(),
			"aquasec_permission_set_saas":     resourcePermissionSetSaas(),
			"aquasec_assurance_custom_script": resourceAssuranceScript(),
			"aquasec_aqua_api_key":            resourceAPIKey(),
			"aquasec_scanner_group":           resourceScannerGroup(),
			"aquasec_log_management":          resourceLogManagement(),
			"aquasec_serverless_application":  resourceServerlessApplication(),
			"aquasec_monitoring_system":       resourceMonitoringSystem(),
			"aquasec_suppression_rule":        resourceSuppressionRule(),
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
			"aquasec_application_scope_saas":      dataApplicationScopeSaas(),
			"aquasec_permissions_sets":            dataSourcePermissionsSets(),
			"aquasec_integration_state":           dataIntegrationState(),
			//"aquasec_sso":							 	dataSourceSSO(),
			"aquasec_roles_mapping": dataSourceRolesMapping(),
			"aquasec_aqua_labels":   dataSourceAquaLabels(),
			"aquasec_acknowledges":  dataSourceAcknowledges(),
			"aquasec_notifications": dataSourceNotification(),
			//saas:
			"aquasec_groups":                  dataSourceGroups(),
			"aquasec_users_saas":              dataSourceUsersSaas(),
			"aquasec_roles_mapping_saas":      dataSourceRolesMappingSaas(),
			"aquasec_permissions_sets_saas":   dataSourcePermissionsSetsSaas(),
			"aquasec_assurance_custom_script": dataSourceAssuranceScript(),
			"aquasec_aqua_api_keys":           dataSourceAPIKeys(),
			"aquasec_scanner_group":           dataSourceScannerGroup(),
			"aquasec_vmware_assurance_policy": dataVmwareAssurancePolicy(),
			"aquasec_log_managements":         dataLogManagement(),
			"aquasec_serverless_applications": dataSourceServerlessApplication(),
			"aquasec_monitoring_systems":      dataSourceMonitoringSystem(),
			"aquasec_suppression_rules":       dataSourceSuppressionRule(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func getProviderConfigurationFromFile(d *schema.ResourceData) (string, string, string, string, string, error) {
	log.Print("[DEBUG] Trying to load configuration from file")
	if configPath, ok := d.GetOk("config_path"); ok && configPath.(string) != "" {
		path, err := homedir.Expand(configPath.(string))
		if err != nil {
			log.Printf("[DEBUG] Failed to expand config file path %s, error %s", configPath, err)
			return "", "", "", "", "", nil
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			log.Printf("[DEBUG] Terraform config file %s does not exist, error %s", path, err)
			return "", "", "", "", "", nil
		}
		log.Printf("[DEBUG] Terraform configuration file is: %s", path)
		configFile, err := os.Open(path)
		if err != nil {
			log.Printf("[DEBUG] Unable to open Terraform configuration file %s", path)
			return "", "", "", "", "", fmt.Errorf("Unable to open terraform configuration file. Error %v", err)
		}
		defer configFile.Close()

		configBytes, _ := io.ReadAll(configFile)
		var config Config
		err = json.Unmarshal(configBytes, &config)
		if err != nil {
			log.Printf("[DEBUG] Failed to parse config file %s", path)
			return "", "", "", "", "", fmt.Errorf("Invalid terraform configuration file format. Error %v", err)
		}
		return config.Username, config.Password, config.AquaURL, config.APIKey, config.SecretKey, nil
	}
	return "", "", "", "", "", nil
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	fmt.Println("----------------------------------------")
	var diags diag.Diagnostics
	var err error

	username := d.Get("username").(string)
	password := d.Get("password").(string)
	aquaURL := d.Get("aqua_url").(string)
	apiKey := d.Get("aqua_api_key").(string)
	secretkey := d.Get("aqua_api_secret").(string)
	verifyTLS := d.Get("verify_tls").(bool)
	caCertPath := d.Get("ca_certificate_path").(string)
	validate := d.Get("validate").(bool)

	if username == "" || password == "" || apiKey == "" || secretkey == "" {
		uF, pF, fileURL, akF, skF, ferr := getProviderConfigurationFromFile(d)
		if ferr != nil && validate {
			return nil, diag.FromErr(ferr)
		}
		if username == "" {
			username = uF
		}
		if password == "" {
			password = pF
		}
		if aquaURL == "" && fileURL != "" {
			aquaURL = fileURL
		}
		if apiKey == "" {
			apiKey = akF
		}
		if secretkey == "" {
			secretkey = skF
		}
	}

	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	apiKey = strings.TrimSpace(apiKey)
	secretkey = strings.TrimSpace(secretkey)
	aquaURL = strings.TrimSpace(aquaURL)

	if validate {
		if aquaURL == "" {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Initializing provider, aqua_url parameter is missing.",
			})
		}
		apiPairOK := apiKey != "" && secretkey != ""
		upOK := username != "" && password != ""
		if !apiPairOK && !upOK {
			if username != "" && password == "" {
				diags = append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Initializing provider, password parameter is missing.",
				})
			}

			if password != "" && username == "" {
				diags = append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Initializing provider, username parameter is missing.",
				})
			}

			if apiKey != "" && secretkey == "" {
				diags = append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Initializing provider, aqua_api_secret parameter is missing.",
				})
			}

			if secretkey != "" && apiKey == "" {
				diags = append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Initializing provider, aqua_api_key parameter is missing.",
				})
			}

			if username == "" && password == "" && apiKey == "" && secretkey == "" {
				diags = append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Initializing provider, credentials are missing.",
					Detail:   "Provide either username+password or aqua_api_key+aqua_api_secret.",
				})
			}
		}
	}

	var caCertByte []byte
	if caCertPath != "" {
		caCertByte, err = os.ReadFile(caCertPath)
		if err != nil && validate {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to read CA certificates",
				Detail:   err.Error(),
			})

			return nil, diags
		}
	}

	if len(diags) > 0 {
		return nil, diags
	}

	var aquaClient *client.Client
	if apiKey != "" {
		aquaClient, err = client.NewClientWithAPIKey(aquaURL, apiKey, secretkey, verifyTLS, caCertByte)
		if err != nil {
			return nil, diag.Diagnostics{diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error creating Aqua client with API key",
				Detail:   err.Error(),
			}}
		}
		if v, ok := d.GetOk("validity"); ok {
			aquaClient.Validity = v.(int)
		}
		if v, ok := d.GetOk("allowed_endpoints"); ok {
			aquaClient.AllowedEndpoints = convertStringArr(v.([]interface{}))
		}
		if v, ok := d.GetOk("csp_roles"); ok {
			aquaClient.CSPRoles = convertStringArr(v.([]interface{}))
		}
	} else if username != "" && password != "" {
		aquaClient, err = client.NewClientWithTokenAuth(aquaURL, username, password, verifyTLS, caCertByte)
		if err != nil {
			return nil, diag.Diagnostics{diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error creating Aqua client with token authentication",
				Detail:   err.Error(),
			}}
		}
	} else {
		return nil, diag.Diagnostics{diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Missing credentials",
			Detail:   "Provide username+password or aqua_api_key+aqua_api_secret.",
		}}
	}

	if validate {
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
	}

	return aquaClient, diags
}
