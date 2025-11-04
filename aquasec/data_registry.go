package aquasec

import (
	"context"
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceRegistry() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataRegistryRead,
		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Description: "The username for registry authentication.",
				Computed:    true,
			},
			"password": {
				Type:        schema.TypeString,
				Description: "The password for registry authentication",
				Computed:    true,
			},
			"type": {
				Type: schema.TypeString,
				Description: "Registry type (HUB / V1 / V2 / ACR / GAR / AWS / GCR / ENGINE / CTRDENGINE / " +
					"ART / NEXUS / QUAY / DTR / ATOMIC / OPENSHIFT / CF / HARBOR / ICR / PODMAN)",
				Computed: true,
			},
			"name": {
				Type:        schema.TypeString,
				Description: "The name of the registry; string, required - this will be treated as the registry's ID, so choose a simple alphanumerical name without special signs and spaces",
				Required:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "The description of the registry",
				Computed:    true,
			},
			"url": {
				Type:        schema.TypeString,
				Description: "The URL, address or region of the registry",
				Computed:    true,
			},
			"auto_pull": {
				Type:        schema.TypeBool,
				Description: "Whether to automatically pull images from the registry on creation and daily",
				Computed:    true,
			},
			"auto_pull_rescan": {
				Type:        schema.TypeBool,
				Description: "Whether to automatically pull and rescan images from the registry on creation and daily",
				Computed:    true,
			},
			"auto_pull_max": {
				Type:        schema.TypeInt,
				Description: "Maximum number of repositories to pull every day, defaults to 100",
				Computed:    true,
			},
			"auto_pull_time": {
				Type:        schema.TypeString,
				Description: "The time of day to start pulling new images from the registry, in the format HH:MM (24-hour clock), defaults to 03:00",
				Computed:    true,
			},
			"auto_pull_interval": {
				Type:        schema.TypeInt,
				Description: "The interval in days to start pulling new images from the registry, Defaults to 1",
				Computed:    true,
			},
			"auto_cleanup": {
				Type:        schema.TypeBool,
				Description: "Automatically clean up images and repositories which are no longer present in the registry from Aqua console",
				Computed:    true,
			},
			"image_creation_date_condition": {
				Type:        schema.TypeString,
				Description: "Additional condition for pulling and rescanning images, Defaults to 'none'",
				Optional:    true,
				Computed:    true,
			},
			"pull_image_age": {
				Type:        schema.TypeString,
				Description: "When auto pull image enabled, sets maximum age of auto pulled images",
				Optional:    true,
				Computed:    true,
			},
			"pull_image_count": {
				Type:        schema.TypeInt,
				Description: "When auto pull image enabled, sets maximum age of auto pulled images tags from each repository.",
				Optional:    true,
				Computed:    true,
			},
			"lastupdate": {
				Type:        schema.TypeInt,
				Description: "The last time the registry was modified in UNIX time",
				Optional:    true,
				Computed:    true,
			},
			"advanced_settings_cleanup": {
				Type:        schema.TypeBool,
				Description: "Automatically clean up that don't match the pull criteria",
				Optional:    true,
			},
			"always_pull_patterns": {
				Type:        schema.TypeList,
				Description: "List of image patterns to pull always",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"pull_image_tag_pattern": {
				Type:        schema.TypeList,
				Description: "List of image tags patterns to pull",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"pull_repo_patterns_excluded": {
				Type:        schema.TypeList,
				Description: "List of image patterns to exclude",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"registry_scan_timeout": {
				Type:        schema.TypeInt,
				Description: "Registry scan timeout in Minutes",
				Optional:    true,
			},
			"webhook": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "When enabled, registry events are sent to the given Aqua webhook url",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"url": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"auth_token": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"un_quarantine": {
							Type:     schema.TypeBool,
							Optional: true,
						},
					},
				},
			},
			"options": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"option": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"value": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"scanner_type": {
				Type:        schema.TypeString,
				Description: "Scanner type",
				Optional:    true,
				Computed:    true,
			},
			"scanner_name": {
				Type:        schema.TypeList,
				Description: "List of scanner names",
				Optional:    true,
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"prefixes": {
				Type:        schema.TypeList,
				Description: "List of possible prefixes to image names pulled from the registry",
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"auto_scan_time": {
				Type:        schema.TypeSet,
				Description: "When enabled, registry events are sent to the given Aqua webhook url",
				Optional:    true,
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"auto_pull_day": {
							Type:        schema.TypeInt,
							Description: "The day for auto pull",
							Optional:    true,
							Computed:    true,
						},
						"iteration": {
							Type:        schema.TypeInt,
							Description: "Number of iterations",
							Optional:    true,
							Computed:    true,
						},
						"iteration_type": {
							Type:        schema.TypeString,
							Description: "The type of iteration (day, week, month, year)",
							Optional:    true,
							Computed:    true,
						},
						"time": {
							Type:        schema.TypeString,
							Description: "the time for auto pull",
							Optional:    true,
							Computed:    true,
						},
						"week_days": {
							Type:        schema.TypeList,
							Description: "The days of week for auto pull",
							Optional:    true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"detected_type": {
				Type:        schema.TypeInt,
				Description: "The detected type of the registry",
				Computed:    true,
			},
			"force_save": {
				Type:        schema.TypeBool,
				Description: "Whether to force save the registry even if the test connection fails",
				Optional:    true,
				Default:     false,
			},
			"force_ootb": {
				Type:        schema.TypeBool,
				Description: "To identify and ignore supersonic client calls initiated from OOTB",
				Optional:    true,
				Default:     false,
			},
			"image_s3_prefixes": {
				Type:        schema.TypeList,
				Description: "The S3 prefixes for images",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"is_registry_connected": {
				Type:        schema.TypeBool,
				Description: "Whether the registry is connected",
				Computed:    true,
			},
			"permission": {
				Type:        schema.TypeString,
				Description: "Permission action",
				Optional:    true,
			},
			"pull_max_tags": {
				Type:        schema.TypeInt,
				Description: "The maximum number of tags for auto pull",
				Optional:    true,
			},
			"pull_tags_pattern": {
				Type:        schema.TypeList,
				Description: "Patterns for tags to be pulled from auto pull",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"pull_repo_patterns": {
				Type:        schema.TypeList,
				Description: "Patterns for repositories to be pulled from auto pull",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"registries_type": {
				Type:        schema.TypeString,
				Description: "The type of registries",
				Computed:    true,
			},
			"auto_pull_latest_xff_enabled": {
				Type:        schema.TypeBool,
				Description: "Auto pull latest xff enabled",
				Optional:    true,
			},
			"is_architecture_system_default": {
				Type:        schema.TypeBool,
				Description: "Whether the architecture is the system default",
				Optional:    true,
			},
			"client_cert": {
				Type:        schema.TypeString,
				Description: "The client certificate for the registry",
				Optional:    true,
			},
			"client_key": {
				Type:        schema.TypeString,
				Description: "The client key for the registry",
				Optional:    true,
			},
			"auto_pull_in_progress": {
				Type:        schema.TypeBool,
				Description: "Whether auto pull is in progress",
				Computed:    true,
			},
			"auto_pull_processed_page_number": {
				Type:        schema.TypeInt,
				Description: "The page number processed for auto pull",
				Computed:    true,
			},
			"architecture": {
				Type:        schema.TypeString,
				Description: "The architecture of the registry",
				Optional:    true,
			},
			"cloud_resources": {
				Type:        schema.TypeList,
				Description: "The cloud resource of the registry",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"error_msg": {
				Type:        schema.TypeString,
				Description: "The error message of the registry",
				Optional:    true,
			},
			"nexus_mtts_ff_enabled": {
				Type:        schema.TypeBool,
				Description: "Enable mutual TLS for Sonatype Nexus Repository",
				Optional:    true,
			},
		},
	}
}

func dataRegistryRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	log.Println("[DEBUG]  inside dataRegistryRead")
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	reg, err := ac.GetRegistry(name)
	if err == nil {
		prefixes := d.Get("prefixes").([]interface{})
		scanner_name := d.Get("scanner_name").([]interface{})
		d.Set("username", reg.Username)
		d.Set("password", reg.Password)
		d.Set("name", reg.Name)
		d.Set("description", reg.Description)
		d.Set("type", reg.Type)
		d.Set("url", reg.URL)
		d.Set("auto_pull", reg.AutoPull)
		d.Set("auto_pull_rescan", reg.AutoPullRescan)
		d.Set("auto_pull_max", reg.AutoPullMax)
		d.Set("auto_pull_time", reg.AutoPullTime)
		d.Set("auto_pull_interval", reg.AutoPullInterval)
		d.Set("auto_cleanup", reg.AutoCleanUp)
		d.Set("lastupdate", reg.Lastupdate)
		d.Set("scanner_type", reg.ScannerType)
		d.Set("advanced_settings_cleanup", reg.AdvancedSettingsCleanup)
		d.Set("always_pull_patterns", reg.AlwaysPullPatterns)
		d.Set("pull_image_tag_pattern", reg.PullImageTagPattern)
		d.Set("registry_scan_timeout", reg.RegistryScanTimeout)
		d.Set("pull_repo_patterns_excluded", reg.PullRepoPatternsExcluded)
		d.Set("options", flattenoptions(reg.Options))
		d.Set("webhook", flattenwebhook(reg.Webhook))
		d.Set("prefixes", convertStringArr(prefixes))
		scannerType := d.Get("scanner_type").(string)
		if scannerType == "specific" {
			d.Set("scanner_name", convertStringArr(scanner_name))
		}
		d.Set("is_architecture_system_default", reg.IsArchitectureSystemDefault)
		d.Set("client_cert", reg.ClientCert)
		d.Set("client_key", reg.ClientKey)
		d.Set("auto_pull_in_progress", reg.AutoPullInProgress)
		d.Set("auto_pull_processed_page_number", reg.AutoPullProcessedPageNumber)
		d.Set("architecture", reg.Architecture)
		d.Set("error_msg", reg.ErrorMsg)
		d.Set("nexus_mtts_ff_enabled", reg.NexusMttsFfEnabled)
		d.Set("force_save", reg.ForceSave)
		d.Set("force_ootb", reg.ForceOotb)
		d.Set("is_registry_connected", reg.IsRegistryConnected)
		d.Set("permission", reg.Permission)
		d.Set("pull_max_tags", reg.PullMaxTags)
		d.Set("registries_type", reg.RegistriesType)
		d.Set("detected_type", reg.DetectedType)
		d.Set("auto_pull_latest_xff_enabled", reg.AutoPullLatestXffEnabled)
		d.Set("image_s3_prefixes", reg.ImageS3Prefixes)
		d.Set("cloud_resources", reg.CloudResources)
		d.Set("pull_repo_patterns", reg.PullRepoPatterns)
		d.Set("pull_tags_pattern", reg.PullTagsPattern)
		d.SetId(name)
	} else {
		return diag.FromErr(err)
	}

	return nil
}
