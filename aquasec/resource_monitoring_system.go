package aquasec

import (
	"context"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceMonitoringSystem() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMonitoringSystemCreate,
		ReadContext:   resourceMonitoringSystemRead,
		UpdateContext: resourceMonitoringSYstemUpdate,
		DeleteContext: resourceMonitoringSystemDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "The name of the monitoring system.",
				Optional:    true,
				Default:     "Prometheus",
			},
			"type": {
				Type:        schema.TypeString,
				Description: "The type of the monitoring system.",
				Required:    true,
			},
			"token": {
				Type:        schema.TypeString,
				Description: "The authentication token for the monitoring system.",
				Optional:    true,
				Sensitive:   true,
			},
			"enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates whether the monitoring system is enabled.",
				Required:    true,
			},
			"interval": {
				Type:        schema.TypeInt,
				Description: "The interval in minutes for monitoring checks.",
				Optional:    true,
			},
		},
	}
}

func resourceMonitoringSystemCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	enabled := d.Get("enabled").(bool)
	interval := d.Get("interval").(int)
	typeMonSys := d.Get("type").(string)
	var tokenPtr *string
	if v, ok := d.GetOk("token"); ok {
		s := v.(string)
		if s != "" {
			tokenPtr = &s
		}
	}

	monitoringSystem := client.MonitoringSystem{
		Name:     name,
		Enabled:  enabled,
		Interval: interval,
		Token:    tokenPtr,
		Type:     typeMonSys,
	}

	err := ac.CreateMonitoringSystem(monitoringSystem)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(name)
	return resourceMonitoringSystemRead(ctx, d, m)
}

func resourceMonitoringSystemRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	name := d.Id()
	if name == "" {
		if v, ok := d.GetOk("name"); ok {
			name = v.(string)
		}
	}

	monitor, err := ac.GetMonitoringSystem(name)
	if err != nil {
		return diag.FromErr(err)
	}

	if monitor == nil {
		d.SetId("")
		return nil
	}
	_ = d.Set("name", monitor.Name)
	_ = d.Set("type", monitor.Type)
	_ = d.Set("enabled", monitor.Enabled)
	_ = d.Set("interval", monitor.Interval)
	if monitor.Token != nil {
		_ = d.Set("token", *monitor.Token)
	} else {
		_ = d.Set("token", "")
	}
	d.SetId(monitor.Name)
	return nil
}

func resourceMonitoringSYstemUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	oldName := d.Id()

	if d.HasChanges("interval", "enabled", "token", "type") {
		enabled := d.Get("enabled").(bool)
		interval := d.Get("interval").(int)
		msType := d.Get("type").(string)
		var tokenPtr *string
		if v, ok := d.GetOk("token"); ok {
			s := v.(string)
			if s != "" {
				tokenPtr = &s
			}
		}

		monitor := client.MonitoringSystem{
			Name:     oldName,
			Enabled:  enabled,
			Token:    tokenPtr,
			Interval: interval,
			Type:     msType,
		}
		err := ac.UpdateMonitoringSystem(monitor)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	return resourceMonitoringSystemRead(ctx, d, m)
}
func resourceMonitoringSystemDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	enabled := false
	interval := d.Get("interval").(int)
	msType := d.Get("type").(string)

	monitoringSystem := client.MonitoringSystem{
		Name:     name,
		Enabled:  enabled,
		Interval: interval,
		Type:     msType,
	}
	err := ac.DeleteMonitoringSystem(monitoringSystem)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	return nil
}
