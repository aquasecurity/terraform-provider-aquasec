package aquasec

import (
	"context"
	"fmt"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceRolesMappingSaas() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataRolesMappingSaasRead,
		Schema: map[string]*schema.Schema{
			"roles_mapping": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"saml_groups": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"created": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"csp_role": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"account_id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func dataRolesMappingSaasRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	result, err := c.GetRolesMappingSaas()
	if err == nil {
		rolesMappingSaas, id := flattenRolesMappingSaasData(result)
		d.SetId(id)
		if err := d.Set("roles_mapping", rolesMappingSaas); err != nil {
			return diag.FromErr(err)
		}
	} else {
		return diag.FromErr(err)
	}
	return nil
}

func flattenRolesMappingSaasData(rolesMapping *client.RoleMappingSaasList) ([]interface{}, string) {
	id := ""
	if rolesMapping != nil {
		rolesM := make([]interface{}, len(rolesMapping.Items))

		for i, roleMapping := range rolesMapping.Items {
			id = id + fmt.Sprintf("%v", roleMapping.Id)
			roleM := make(map[string]interface{})

			roleM["saml_groups"] = roleMapping.SamlGroups
			roleM["id"] = roleMapping.Id
			roleM["created"] = roleMapping.Created
			roleM["csp_role"] = roleMapping.CspRole
			roleM["account_id"] = roleMapping.AccountId

			rolesM[i] = roleM
		}
		return rolesM, id
	}
	return make([]interface{}, 0), ""
}
