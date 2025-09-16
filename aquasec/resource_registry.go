package aquasec

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceRegistry() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRegistryCreate,
		ReadContext:   resourceRegistryRead,
		UpdateContext: resourceRegistryUpdate,
		DeleteContext: resourceRegistryDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"lastupdate": {
				Type:        schema.TypeInt,
				Description: "The last time the registry was modified in UNIX time",
				Optional:    true,
				Computed:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "The description of the registry",
				Optional:    true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "The username of the user who created or last modified the registry",
				Optional:    true,
				Computed:    true,
			},
			"name": {
				Type:        schema.TypeString,
				Description: "The name of the registry; string, required - this will be treated as the registry's ID, so choose a simple alphanumerical name without special signs and spaces",
				Required:    true,
				ForceNew:    true,
			},
			"password": {
				Type:        schema.TypeString,
				Description: "The password for registry authentication",
				Optional:    true,
			},
			"type": {
				Type:        schema.TypeString,
				Description: "Registry type (HUB / V1 / V2 / ACR / GAR / ENGINE / AWS / GCR).",
				Required:    true,
			},
			"username": {
				Type:        schema.TypeString,
				Description: "The username for registry authentication.",
				Optional:    true,
			},
			"url": {
				Type:        schema.TypeString,
				Description: "The URL, address or region of the registry",
				Optional:    true,
				Computed:    true,
			},
			"auto_pull": {
				Type:        schema.TypeBool,
				Description: "Whether to automatically pull images from the registry on creation and daily",
				Optional:    true,
			},
			"auto_pull_rescan": {
				Type:        schema.TypeBool,
				Description: "Whether to automatically pull and rescan images from the registry on creation and daily",
				Optional:    true,
			},
			"auto_pull_max": {
				Type:        schema.TypeInt,
				Description: "Maximum number of repositories to pull every day, defaults to 100",
				Optional:    true,
			},
			"auto_pull_time": {
				Type:        schema.TypeString,
				Description: "The time of day to start pulling new images from the registry, in the format HH:MM (24-hour clock), defaults to 03:00",
				Optional:    true,
			},
			"auto_pull_interval": {
				Type:        schema.TypeInt,
				Description: "The interval in days to start pulling new images from the registry, Defaults to 1",
				Optional:    true,
			},
			"auto_cleanup": {
				Type:        schema.TypeBool,
				Description: "Automatically clean up images and repositories which are no longer present in the registry from Aqua console",
				Optional:    true,
			},
			"advanced_settings_cleanup": {
				Type:        schema.TypeBool,
				Description: "Automatically clean up that don't match the pull criteria",
				Optional:    true,
			},
			"image_creation_date_condition": {
				Type:        schema.TypeString,
				Description: "Additional condition for pulling and rescanning images, Defaults to 'none'",
				Optional:    true,
				Computed:    true,
			},
			"pull_image_age": {
				Type:        schema.TypeString,
				Description: "When auto pull image enabled, sets maximum age of auto pulled images (for example for 5 Days the value should be: 5D), Requires `image_creation_date_condition = \"image_age\"` ",
				Optional:    true,
				Computed:    true,
			},
			"pull_image_count": {
				Type:        schema.TypeInt,
				Description: "When auto pull image enabled, sets maximum age of auto pulled images tags from each repository (based on image creation date) Requires `image_creation_date_condition = \"image_count\"`",
				Optional:    true,
				Computed:    true,
			},
			"registry_scan_timeout": {
				Type:        schema.TypeInt,
				Description: "Registry scan timeout in Minutes",
				Optional:    true,
			},
			"scanner_type": {
				Type:         schema.TypeString,
				Description:  "The Scanner type (either \"any\" or \"specific\")",
				Optional:     true,
				Computed:     true,
				ValidateFunc: validation.StringInSlice([]string{"any", "specific"}, false),
			},
			"scanner_name": {
				Type:        schema.TypeList,
				Description: "List of scanner names",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"scanner_group_name": {
				Type:        schema.TypeString,
				Description: "The scanner group name (required when scanner_type = \"specific\" type)",
				Optional:    true,
				Computed:    true,
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
			"prefixes": {
				Type:        schema.TypeList,
				Description: "List of possible prefixes to image names pulled from the registry",
				Optional:    true,
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
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
			"webhook": {
				Type:        schema.TypeSet,
				Description: "When enabled, registry events are sent to the given Aqua webhook url",
				Optional:    true,
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:     schema.TypeBool,
							Optional: true,
							Computed: true,
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
							Computed: true,
						},
					},
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

func resourceRegistryCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	var scannerGroupName string
	scannerType := d.Get("scanner_type").(string)
	if scannerType == "" {
		scannerType = "any"
	}

	if scannerType == "specific" {
		scannerGroupName = d.Get("scanner_group_name").(string)
		if len(scannerGroupName) == 0 {
			return diag.FromErr(fmt.Errorf("scanner_group_name must be provided when scanner_type is \"specific\""))
		}
	}

	autoPull := d.Get("auto_pull").(bool)
	autoPullRescan := d.Get("auto_pull_rescan").(bool)
	autoPullInterval := d.Get("auto_pull_interval").(int)
	if (autoPull || autoPullRescan) && (autoPullInterval < 1) {
		autoPullInterval = 1
	}

	// Get and Convert Roles
	prefixes := d.Get("prefixes").([]interface{})
	always_pull_patterns := d.Get("always_pull_patterns").([]interface{})
	pull_repo_patterns_excluded := d.Get("pull_repo_patterns_excluded").([]interface{})
	pull_image_tag_pattern := d.Get("pull_image_tag_pattern").([]interface{})
	scanner_name := d.Get("scanner_name").([]interface{})
	image_s3_prefixes := d.Get("image_s3_prefixes").([]interface{})
	cloud_resources := d.Get("cloud_resources").([]interface{})
	pull_repo_patterns := d.Get("pull_repo_patterns").([]interface{})
	pull_tags_pattern := d.Get("pull_tags_pattern").([]interface{})

	old, new := d.GetChange("scanner_name")

	existing_scanners := old.([]interface{})

	scanner_name_added, scanner_name_removed := scannerNamesListCreate(old.([]interface{}), new.([]interface{}))

	registry := client.Registry{
		Username:                    d.Get("username").(string),
		Password:                    d.Get("password").(string),
		Name:                        d.Get("name").(string),
		Description:                 d.Get("description").(string),
		Type:                        d.Get("type").(string),
		URL:                         d.Get("url").(string),
		AutoPull:                    d.Get("auto_pull").(bool),
		AutoPullRescan:              d.Get("auto_pull_rescan").(bool),
		AutoPullMax:                 d.Get("auto_pull_max").(int),
		AutoPullTime:                d.Get("auto_pull_time").(string),
		AutoCleanUp:                 d.Get("auto_cleanup").(bool),
		AdvancedSettingsCleanup:     d.Get("advanced_settings_cleanup").(bool),
		ImageCreationDateCondition:  d.Get("image_creation_date_condition").(string),
		PullImageAge:                d.Get("pull_image_age").(string),
		PullImageCount:              d.Get("pull_image_count").(int),
		RegistryScanTimeout:         d.Get("registry_scan_timeout").(int),
		AutoPullInterval:            autoPullInterval,
		ScannerType:                 scannerType,
		ScannerGroupName:            scannerGroupName,
		ScannerName:                 convertStringArr(scanner_name),
		ScannerNameAdded:            convertStringArr(scanner_name_added),
		ScannerNameRemoved:          convertStringArr(scanner_name_removed),
		ExistingScanners:            convertStringArr(existing_scanners),
		Prefixes:                    convertStringArr(prefixes),
		AlwaysPullPatterns:          convertStringArr(always_pull_patterns),
		PullRepoPatternsExcluded:    convertStringArr(pull_repo_patterns_excluded),
		PullImageTagPattern:         convertStringArr(pull_image_tag_pattern),
		IsArchitectureSystemDefault: d.Get("is_architecture_system_default").(bool),
		ClientCert:                  d.Get("client_cert").(string),
		ClientKey:                   d.Get("client_key").(string),
		Architecture:                d.Get("architecture").(string),
		CloudResources:              convertStringArr(cloud_resources),
		ErrorMsg:                    d.Get("error_msg").(string),
		NexusMttsFfEnabled:          d.Get("nexus_mtts_ff_enabled").(bool),
		ForceOotb:                   d.Get("force_ootb").(bool),
		ForceSave:                   d.Get("force_save").(bool),
		ImageS3Prefixes:             convertStringArr(image_s3_prefixes),
		Permission:                  d.Get("permission").(string),
		PullMaxTags:                 d.Get("pull_max_tags").(int),
		PullRepoPatterns:            convertStringArr(pull_repo_patterns),
		PullTagsPattern:             convertStringArr(pull_tags_pattern),
		AutoPullLatestXffEnabled:    d.Get("auto_pull_latest_xff_enabled").(bool),
	}
	options, ok := d.GetOk("options")
	if ok {
		options1 := options.([]interface{})
		optionsarray := make([]client.Options, len(options1))
		for i, Data := range options1 {
			options2 := Data.(map[string]interface{})
			Options := client.Options{
				Option: options2["option"].(string),
				Value:  options2["value"].(string),
			}
			optionsarray[i] = Options
		}
		registry.Options = optionsarray
	}
	webhook, ok := d.GetOk("webhook")
	if ok {
		for _, webhookMap := range webhook.(*schema.Set).List() {
			webhookentries, ok := webhookMap.(map[string]interface{})
			if !ok {
				continue
			}
			Webhook := client.Webhook{
				Enabled:      webhookentries["enabled"].(bool),
				URL:          webhookentries["url"].(string),
				AuthToken:    webhookentries["auth_token"].(string),
				UnQuarantine: webhookentries["un_quarantine"].(bool),
			}
			registry.Webhook = Webhook
		}
	}

	autoscantime, ok := d.GetOk("auto_scan_time")
	if ok {
		for _, autoscantimeMap := range autoscantime.(*schema.Set).List() {
			autoscantimeentries, ok := autoscantimeMap.(map[string]interface{})
			if !ok {
				continue
			}
			AutoScanTime := client.AutoScanTime{
				AutoPullDay:   autoscantimeentries["auto_pull_day"].(int),
				Iteration:     autoscantimeentries["iteration"].(int),
				IterationType: autoscantimeentries["iteration_type"].(string),
				Time:          autoscantimeentries["time"].(string),
				WeekDays:      convertStringArr(autoscantimeentries["week_days"].([]interface{})),
			}
			registry.AutoScanTime = AutoScanTime
		}
	} else {
		registry.AutoScanTime = client.AutoScanTime{
			AutoPullDay:   0,
			Iteration:     0,
			IterationType: "",
			Time:          "",
			WeekDays:      []string{},
		}
	}

	err := ac.CreateRegistry(registry)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(d.Get("name").(string))

	return resourceRegistryRead(ctx, d, m)

}

func resourceRegistryRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	r, err := ac.GetRegistry(d.Id())
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	prefixes := r.Prefixes

	if err = d.Set("auto_pull", r.AutoPull); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("auto_pull_rescan", r.AutoPullRescan); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("auto_pull_interval", r.AutoPullInterval); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("auto_cleanup", r.AutoCleanUp); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("image_creation_date_condition", r.ImageCreationDateCondition); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("pull_image_age", r.PullImageAge); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("pull_image_count", r.PullImageCount); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("registry_scan_timeout", r.RegistryScanTimeout); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("name", r.Name); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("description", r.Description); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("author", r.Author); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("password", r.Password); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("scanner_type", r.ScannerType); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("type", r.Type); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("url", r.URL); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("username", r.Username); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("prefixes", prefixes); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("advanced_settings_cleanup", r.AdvancedSettingsCleanup); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("always_pull_patterns", r.AlwaysPullPatterns); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("pull_repo_patterns_excluded", r.PullRepoPatternsExcluded); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("pull_image_tag_pattern", r.PullImageTagPattern); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("options", flattenoptions(r.Options)); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("webhook", flattenwebhook(r.Webhook)); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("scanner_group_name", r.ScannerGroupName); err != nil {
		return diag.FromErr(err)
	}
	scannerType := d.Get("scanner_type").(string)
	if scannerType == "specific" {
		if err := d.Set("scanner_name", r.ScannerName); err != nil {
			return diag.FromErr(err)
		}
	}
	if err = d.Set("auto_scan_time", flattenautoscantime(r.AutoScanTime)); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("is_architecture_system_default", r.IsArchitectureSystemDefault); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("client_cert", r.ClientCert); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("client_key", r.ClientKey); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("auto_pull_in_progress", r.AutoPullInProgress); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("auto_pull_processed_page_number", r.AutoPullProcessedPageNumber); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("architecture", r.Architecture); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("cloud_resources", r.CloudResources); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("error_msg", r.ErrorMsg); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("nexus_mtts_ff_enabled", r.NexusMttsFfEnabled); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("force_save", r.ForceSave); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("force_ootb", r.ForceOotb); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("image_s3_prefixes", r.ImageS3Prefixes); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("is_registry_connected", r.IsRegistryConnected); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("permission", r.Permission); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("pull_max_tags", r.PullMaxTags); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("pull_tags_pattern", r.PullTagsPattern); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("pull_repo_patterns", r.PullRepoPatterns); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("registries_type", r.RegistriesType); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("detected_type", r.DetectedType); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("auto_pull_latest_xff_enabled", r.AutoPullLatestXffEnabled); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func resourceRegistryUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	var scannerGroupName string
	scannerType := d.Get("scanner_type").(string)
	if scannerType == "" {
		scannerType = "any"
	}
	if scannerType == "specific" {
		scannerGroupName = d.Get("scanner_group_name").(string)
		if len(scannerGroupName) == 0 {
			return diag.FromErr(fmt.Errorf("scanner_group_name must be provided when scanner_type is \"specific\""))
		}
	}
	autoPull := d.Get("auto_pull").(bool)
	autoPullRescan := d.Get("auto_pull_rescan").(bool)
	autoPullInterval := d.Get("auto_pull_interval").(int)
	if (autoPull || autoPullRescan) && (autoPullInterval < 1) {
		autoPullInterval = 1
	}

	if d.HasChanges("name", "registry_scan_timeout", "username", "description", "pull_image_tag_pattern", "password", "url", "type", "auto_pull", "auto_pull_rescan", "auto_pull_max", "advanced_settings_cleanup", "auto_pull_time", "auto_pull_interval", "auto_cleanup", "image_creation_date_condition", "scanner_name", "prefixes", "pull_image_count", "pull_image_age", "options", "webhook", "always_pull_patterns", "pull_repo_patterns_excluded", "scanner_group_name", "auto_scan_time", "client_cert", "client_key", "architecture", "cloud_resources", "error_msg", "force_save", "force_ootb", "image_s3_prefixes", "permission", "pull_max_tags", "pull_tags_pattern", "pull_repo_patterns", "auto_pull_latest_xff_enabled", "nexus_mtts_ff_enabled", "is_architecture_system_default") {
		prefixes := d.Get("prefixes").([]interface{})
		var defaultPrefix string
		// Add default_prefix to prefixes
		r, errs := c.GetRegistry(d.Id())
		if errs != nil {
			return diag.FromErr(errs)
		}
		prefixesSet := make(map[string]struct{})
		for _, p := range prefixes {
			prefixesSet[p.(string)] = struct{}{}
		}
		if r.DefaultPrefix != "" {
			if _, exists := prefixesSet[r.DefaultPrefix]; exists {
				defaultPrefix = r.DefaultPrefix
			}
		}
		always_pull_patterns := d.Get("always_pull_patterns").([]interface{})
		pull_repo_patterns_excluded := d.Get("pull_repo_patterns_excluded").([]interface{})
		pull_image_tag_pattern := d.Get("pull_image_tag_pattern").([]interface{})
		scanner_name := d.Get("scanner_name").([]interface{})
		image_s3_prefixes := d.Get("image_s3_prefixes").([]interface{})
		cloud_resources := d.Get("cloud_resources").([]interface{})
		pull_repo_patterns := d.Get("pull_repo_patterns").([]interface{})
		pull_tags_pattern := d.Get("pull_tags_pattern").([]interface{})

		old, new := d.GetChange("scanner_name")

		existing_scanners := old.([]interface{})

		scanner_name_added, scanner_name_removed := scannerNamesListCreate(old.([]interface{}), new.([]interface{}))

		registry := client.Registry{
			Name:                        d.Get("name").(string),
			Type:                        d.Get("type").(string),
			Description:                 d.Get("description").(string),
			Username:                    d.Get("username").(string),
			Password:                    d.Get("password").(string),
			URL:                         d.Get("url").(string),
			AutoPull:                    d.Get("auto_pull").(bool),
			AutoPullRescan:              d.Get("auto_pull_rescan").(bool),
			AutoPullMax:                 d.Get("auto_pull_max").(int),
			AutoPullTime:                d.Get("auto_pull_time").(string),
			AutoCleanUp:                 d.Get("auto_cleanup").(bool),
			AutoPullInterval:            autoPullInterval,
			AdvancedSettingsCleanup:     d.Get("advanced_settings_cleanup").(bool),
			ImageCreationDateCondition:  d.Get("image_creation_date_condition").(string),
			PullImageAge:                d.Get("pull_image_age").(string),
			PullImageCount:              d.Get("pull_image_count").(int),
			RegistryScanTimeout:         d.Get("registry_scan_timeout").(int),
			ScannerType:                 scannerType,
			ScannerGroupName:            scannerGroupName,
			ScannerName:                 convertStringArr(scanner_name),
			ScannerNameAdded:            convertStringArr(scanner_name_added),
			ScannerNameRemoved:          convertStringArr(scanner_name_removed),
			ExistingScanners:            convertStringArr(existing_scanners),
			Prefixes:                    convertStringArr(prefixes),
			DefaultPrefix:               defaultPrefix,
			AlwaysPullPatterns:          convertStringArr(always_pull_patterns),
			PullRepoPatternsExcluded:    convertStringArr(pull_repo_patterns_excluded),
			PullImageTagPattern:         convertStringArr(pull_image_tag_pattern),
			IsArchitectureSystemDefault: d.Get("is_architecture_system_default").(bool),
			ClientCert:                  d.Get("client_cert").(string),
			ClientKey:                   d.Get("client_key").(string),
			Architecture:                d.Get("architecture").(string),
			CloudResources:              convertStringArr(cloud_resources),
			ErrorMsg:                    d.Get("error_msg").(string),
			NexusMttsFfEnabled:          d.Get("nexus_mtts_ff_enabled").(bool),
			ForceOotb:                   d.Get("force_ootb").(bool),
			ForceSave:                   d.Get("force_save").(bool),
			ImageS3Prefixes:             convertStringArr(image_s3_prefixes),
			Permission:                  d.Get("permission").(string),
			PullMaxTags:                 d.Get("pull_max_tags").(int),
			PullTagsPattern:             convertStringArr(pull_tags_pattern),
			PullRepoPatterns:            convertStringArr(pull_repo_patterns),
			AutoPullLatestXffEnabled:    d.Get("auto_pull_latest_xff_enabled").(bool),
		}

		options, ok := d.GetOk("options")
		if ok {
			options1 := options.([]interface{})
			optionsarray := make([]client.Options, len(options1))
			for i, Data := range options1 {
				options2 := Data.(map[string]interface{})
				Options := client.Options{
					Option: options2["option"].(string),
					Value:  options2["value"].(string),
				}
				optionsarray[i] = Options
			}
			registry.Options = optionsarray
		}
		webhook, ok := d.GetOk("webhook")
		if ok {
			for _, webhookMap := range webhook.(*schema.Set).List() {
				webhookentries, ok := webhookMap.(map[string]interface{})
				if !ok {
					continue
				}
				Webhook := client.Webhook{
					Enabled:      webhookentries["enabled"].(bool),
					URL:          webhookentries["url"].(string),
					AuthToken:    webhookentries["auth_token"].(string),
					UnQuarantine: webhookentries["un_quarantine"].(bool),
				}
				registry.Webhook = Webhook
			}
		}

		autoscantime, ok := d.GetOk("auto_scan_time")
		if ok {
			for _, autoscantimeMap := range autoscantime.(*schema.Set).List() {
				autoscantimeentries, ok := autoscantimeMap.(map[string]interface{})
				if !ok {
					continue
				}
				AutoScanTime := client.AutoScanTime{
					AutoPullDay:   autoscantimeentries["auto_pull_day"].(int),
					Iteration:     autoscantimeentries["iteration"].(int),
					IterationType: autoscantimeentries["iteration_type"].(string),
					Time:          autoscantimeentries["time"].(string),
					WeekDays:      convertStringArr(autoscantimeentries["week_days"].([]interface{})),
				}
				registry.AutoScanTime = AutoScanTime
			}
		} else {
			registry.AutoScanTime = client.AutoScanTime{
				AutoPullDay:   0,
				Iteration:     0,
				IterationType: "",
				Time:          "",
				WeekDays:      []string{},
			}
		}

		err := c.UpdateRegistry(registry)
		if err == nil {
			_ = d.Set("lastupdate", time.Now().Unix())
		} else {
			log.Println("[DEBUG]  error while updating registry: ", err)
			return diag.FromErr(err)
		}
		//_ = d.Set("last_updated", time.Now().Format(time.RFC850))
	}

	return nil
}

func resourceRegistryDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	id := d.Id()
	err := c.DeleteRegistry(id)

	if err == nil {
		d.SetId("")
	} else {
		log.Println("[DEBUG]  error deleting registry: ", err)
		return diag.FromErr(err)
	}
	//d.SetId("")

	return diag.FromErr(err)
}

func scannerNamesListCreate(a, b []interface{}) (d, e []interface{}) {
	m1 := make(map[interface{}]bool)
	m2 := make(map[interface{}]bool)

	for _, item := range a {
		m1[item] = true
	}
	for _, item := range b {
		m2[item] = true
	}

	for _, item := range b {
		if _, ok := m1[item]; ok {
			continue
		} else {
			d = append(d, item)
		}
	}
	for _, item := range a {
		if _, ok := m2[item]; ok {
			continue
		} else {
			e = append(e, item)
		}
	}
	return
}

func flattenoptions(options []client.Options) []map[string]interface{} {
	option := make([]map[string]interface{}, len(options))
	for i := range options {
		option[i] = map[string]interface{}{
			"option": options[i].Option,
			"value":  options[i].Value,
		}
	}
	return option
}

func flattenwebhook(webhook1 client.Webhook) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"enabled":       webhook1.Enabled,
			"url":           webhook1.URL,
			"auth_token":    webhook1.AuthToken,
			"un_quarantine": webhook1.UnQuarantine,
		},
	}
}

func flattenautoscantime(autoscantime client.AutoScanTime) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"auto_pull_day":  autoscantime.AutoPullDay,
			"iteration":      autoscantime.Iteration,
			"iteration_type": autoscantime.IterationType,
			"time":           autoscantime.Time,
			"week_days":      autoscantime.WeekDays,
		},
	}
}
