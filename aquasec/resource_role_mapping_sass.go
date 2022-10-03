package aquasec

import (
	"context"
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
)

func resourceRoleMappingSaas() *schema.Resource {
	return &schema.Resource{
		ReadContext:   resourceRoleMappingSaasRead,
		CreateContext: resourceRoleMappingSaasCreate,
		UpdateContext: resourceRoleMappingSaasUpdate,
		DeleteContext: resourceRoleMappingSaasDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"saml_groups": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"role_mapping_id": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"created": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"csp_role": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"account_id": {
				Type:     schema.TypeInt,
				Computed: true,
			},
		},
	}
}

func resourceRoleMappingSaasRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	r, err := ac.GetRoleMappingSass(d.Id())
	if err == nil {
		d.Set("role_mapping_id", r.Id)
		d.Set("created", r.Created)
		d.Set("account_id", r.AccountId)
	} else {
		log.Println("[DEBUG]  error calling ac.ReadRole: ", r)
		return diag.FromErr(err)
	}
	return nil
}

func resourceRoleMappingSaasCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	roleMapping, err := expandRoleMappingSaas(d)
	if err != nil {
		return diag.FromErr(err)
	}
	err = c.CreateRoleMappingSaas(roleMapping)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(fmt.Sprintf("%v", roleMapping.Id))
	d.Set("role_mapping_id", roleMapping.Id)
	d.Set("created", roleMapping.Created)
	d.Set("account_id", roleMapping.AccountId)

	return resourceRoleMappingSaasRead(ctx, d, m)
}

func resourceRoleMappingSaasUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.HasChanges("saml_groups") {
		c := m.(*client.Client)
		roleMapping, err := expandRoleMappingSaas(d)
		if err != nil {
			return diag.FromErr(err)
		}
		err = c.UpdateRoleMappingSaas(roleMapping, d.Id())
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func resourceRoleMappingSaasDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	err := c.DeleteRoleMappingSass(d.Id())
	if err == nil {
		d.SetId("")
	} else {
		log.Println("[DEBUG]  error deleting user: ", err)
		return diag.FromErr(err)
	}

	return nil
}

func expandRoleMappingSaas(d *schema.ResourceData) (*client.RoleMappingSaas, error) {

	roleMappingSaas := client.RoleMappingSaas{
		CspRole:    d.Get("csp_role").(string),
		SamlGroups: convertStringArr(d.Get("saml_groups").([]interface{})),
	}

	return &roleMappingSaas, nil
}
