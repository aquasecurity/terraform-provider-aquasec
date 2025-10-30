package aquasec

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceLogManagement() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceLogManagementCreate,
		ReadContext:   resourceLogManagementRead,
		UpdateContext: resourceLogManagementUpdate,
		DeleteContext: resourceLogManagementDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type: schema.TypeString,
				Description: "The name of the log management configuration" +
					" accepted value [CloudWatch, Splunk, Syslog, AzureLogAnalytics, ArcSight, Elasticsearch," +
					" Exabeam, Stackdriver, QRadar, Logentries, Loggly, OMS, Sumologic, WebHook]",
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice(
					[]string{"CloudWatch", "Splunk", "Syslog", "AzureLogAnalytics", "ArcSight", "Elasticsearch", "Exabeam", "Stackdriver", "QRadar", "Logentries", "Loggly", "OMS", "Sumologic", "WebHook"},
					false,
				),
			},
			"enable": {
				Type:        schema.TypeBool,
				Description: "Enable or disable log management",
				Required:    true,
			},
			"audit_filter": {
				Type:        schema.TypeString,
				Description: "The audit filter for the log management service",
				Optional:    true,
			},
			"url": {
				Type:        schema.TypeString,
				Description: "The URL of the log management service",
				Optional:    true,
			},
			"network": {
				Type:        schema.TypeString,
				Description: "The network configuration for the log management service",
				Optional:    true,
			},
			"user": {
				Type:        schema.TypeString,
				Description: "The username for the log management service",
				Optional:    true,
				Sensitive:   true,
			},
			"password": {
				Type:        schema.TypeString,
				Description: "The password for the log management service",
				Optional:    true,
				Sensitive:   true,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old != "" && new == ""
				},
			},
			"token": {
				Type:        schema.TypeString,
				Description: "The token for the log management service",
				Optional:    true,
				Sensitive:   true,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old != "" && new == ""
				},
			},
			"workspace": {
				Type:        schema.TypeString,
				Description: "The workspace for the log management service",
				Optional:    true,
			},
			"key": {
				Type:        schema.TypeString,
				Description: "The key for the log management service",
				Optional:    true,
				Computed:    true,
				Sensitive:   true,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old == "" || new != ""
				},
			},
			"verify_cert": {
				Type:        schema.TypeBool,
				Description: "Enable or disable SSL certificate verification",
				Optional:    true,
			},
			"ca_cert": {
				Type:        schema.TypeString,
				Description: "The CA certificate for the log management service",
				Optional:    true,
				Sensitive:   true,
			},
			"enable_alphanumeric_sorting": {
				Type:        schema.TypeBool,
				Description: "Enable or disable alphanumeric sorting",
				Optional:    true,
			},
			"index": {
				Type:        schema.TypeString,
				Description: "The index for the log management service",
				Optional:    true,
			},
			"source": {
				Type:        schema.TypeString,
				Description: "Fixed source identifier; always set to \"aquasec\" and not configurable by the user.",
				Computed:    true,
			},
			"sourcetype": {
				Type:        schema.TypeString,
				Description: "The source type for the log management service",
				Optional:    true,
			},
			"authentication_option": {
				Type:        schema.TypeString,
				Description: "The authentication option for the log management service",
				Optional:    true,
			},
			"projectid": {
				Type:        schema.TypeString,
				Description: "The project ID for the log management service",
				Optional:    true,
			},
			"logname": {
				Type:        schema.TypeString,
				Description: "The log name for the log management service",
				Optional:    true,
			},
			"credentials_json": {
				Type:        schema.TypeString,
				Description: "The credentials JSON for the log management service",
				Optional:    true,
				Sensitive:   true,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old != "" && new == ""
				},
			},
			"external_id": {
				Type:        schema.TypeString,
				Description: "The external ID for the log management service",
				Optional:    true,
			},
			"role_arn": {
				Type:        schema.TypeString,
				Description: "The role ARN for the log management service",
				Optional:    true,
			},
			"region": {
				Type:        schema.TypeString,
				Description: "The region for the log management service",
				Optional:    true,
			},
			"loggroup": {
				Type:        schema.TypeString,
				Description: "The log group for the log management service",
				Optional:    true,
			},
			"keyid": {
				Type:        schema.TypeString,
				Description: "The key ID for the log management service",
				Optional:    true,
			},
			"rule": {
				Type:        schema.TypeString,
				Description: "The rule for the log management service",
				Optional:    true,
			},
			"stream_name": {
				Type:        schema.TypeString,
				Description: "The stream name for the log management service",
				Optional:    true,
			},
			"tenant_id": {
				Type:        schema.TypeString,
				Description: "The tenant ID for the log management service",
				Optional:    true,
			},
			"client_id": {
				Type:        schema.TypeString,
				Description: "The client ID for the log management service",
				Optional:    true,
			},
			"client_secret": {
				Type:        schema.TypeString,
				Description: "The client secret for the log management service",
				Optional:    true,
				Sensitive:   true,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old != "" && new == ""
				},
			},
			"cloud": {
				Type: schema.TypeString,
				Description: "The cloud provider for the log management service" +
					" accepted value [public, government, china]",
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"public", "government", "china"}, false),
			},
		},
	}
}

func resourceLogManagementCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	logService := client.LogService{
		Name:                      d.Get("name").(string),
		Enable:                    d.Get("enable").(bool),
		AuditFilter:               d.Get("audit_filter").(string),
		URL:                       d.Get("url").(string),
		Network:                   d.Get("network").(string),
		User:                      d.Get("user").(string),
		Password:                  d.Get("password").(string),
		Token:                     d.Get("token").(string),
		Workspace:                 d.Get("workspace").(string),
		VerifyCert:                d.Get("verify_cert").(bool),
		CACert:                    d.Get("ca_cert").(string),
		EnableAlphanumericSorting: d.Get("enable_alphanumeric_sorting").(bool),
		Index:                     d.Get("index").(string),
		SourceType:                d.Get("sourcetype").(string),
		AuthenticationOption:      d.Get("authentication_option").(string),
		ProjectID:                 d.Get("projectid").(string),
		LogName:                   d.Get("logname").(string),
		ExternalID:                d.Get("external_id").(string),
		RoleArn:                   d.Get("role_arn").(string),
		Region:                    d.Get("region").(string),
		LogGroup:                  d.Get("loggroup").(string),
		KeyID:                     d.Get("keyid").(string),
		Key:                       d.Get("key").(string),
		Rule:                      d.Get("rule").(string),
		StreamName:                d.Get("stream_name").(string),
		TenantID:                  d.Get("tenant_id").(string),
		ClientID:                  d.Get("client_id").(string),
		ClientSecret:              d.Get("client_secret").(string),
		Cloud:                     d.Get("cloud").(string),
		CredentialsJSON:           d.Get("credentials_json").(string),
	}

	err := ac.CreateLogManagement(logService)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(d.Get("name").(string))

	return resourceLogManagementRead(ctx, d, m)
}

func resourceLogManagementRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	logService, err := ac.GetLogManagement(d.Id())
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	if err := d.Set("name", logService.Name); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("enable", logService.Enable); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("audit_filter", logService.AuditFilter); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("url", logService.URL); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("network", logService.Network); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("user", logService.User); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("password", logService.Password); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("token", logService.Token); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("workspace", logService.Workspace); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("key", logService.Key); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("verify_cert", logService.VerifyCert); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("ca_cert", logService.CACert); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("enable_alphanumeric_sorting", logService.EnableAlphanumericSorting); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("index", logService.Index); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("source", logService.Source); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("sourcetype", logService.SourceType); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("authentication_option", logService.AuthenticationOption); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("projectid", logService.ProjectID); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("logname", logService.LogName); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("external_id", logService.ExternalID); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("role_arn", logService.RoleArn); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("region", logService.Region); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("loggroup", logService.LogGroup); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("keyid", logService.KeyID); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("rule", logService.Rule); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("stream_name", logService.StreamName); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("tenant_id", logService.TenantID); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("client_id", logService.ClientID); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("client_secret", logService.ClientSecret); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("cloud", logService.Cloud); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("credentials_json", logService.CredentialsJSON); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceLogManagementUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	if d.HasChanges("enable", "audit_filter", "url", "network", "user", "password", "token", "workspace", "verify_cert", "ca_cert", "enable_alphanumeric_sorting", "index", "sourcetype", "authentication_option", "projectid", "logname", "external_id", "role_arn", "region", "loggroup", "keyid", "rule", "stream_name", "tenant_id", "client_id", "client_secret", "cloud", "key", "credentials_json") {
		logService := client.LogService{
			Name:                      d.Get("name").(string),
			Enable:                    d.Get("enable").(bool),
			AuditFilter:               d.Get("audit_filter").(string),
			URL:                       d.Get("url").(string),
			Network:                   d.Get("network").(string),
			User:                      d.Get("user").(string),
			Password:                  d.Get("password").(string),
			Token:                     d.Get("token").(string),
			Workspace:                 d.Get("workspace").(string),
			VerifyCert:                d.Get("verify_cert").(bool),
			CACert:                    d.Get("ca_cert").(string),
			EnableAlphanumericSorting: d.Get("enable_alphanumeric_sorting").(bool),
			Index:                     d.Get("index").(string),
			SourceType:                d.Get("sourcetype").(string),
			AuthenticationOption:      d.Get("authentication_option").(string),
			ProjectID:                 d.Get("projectid").(string),
			LogName:                   d.Get("logname").(string),
			ExternalID:                d.Get("external_id").(string),
			RoleArn:                   d.Get("role_arn").(string),
			Region:                    d.Get("region").(string),
			LogGroup:                  d.Get("loggroup").(string),
			KeyID:                     d.Get("keyid").(string),
			Key:                       d.Get("key").(string),
			Rule:                      d.Get("rule").(string),
			StreamName:                d.Get("stream_name").(string),
			TenantID:                  d.Get("tenant_id").(string),
			ClientID:                  d.Get("client_id").(string),
			ClientSecret:              d.Get("client_secret").(string),
			Cloud:                     d.Get("cloud").(string),
			CredentialsJSON:           d.Get("credentials_json").(string),
		}

		err := ac.UpdateLogManagement(d.Id(), logService)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return resourceLogManagementRead(ctx, d, m)
}

func resourceLogManagementDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	id := d.Id()

	err := ac.DeleteLogManagement(id)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
