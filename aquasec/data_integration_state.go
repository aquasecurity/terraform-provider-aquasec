package aquasec

import (
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataIntegrationState() *schema.Resource {
	return &schema.Resource{
		Read: dataIntegrationStateRead,
		Schema: map[string]*schema.Schema{
			"oidc_settings": {
				Type:        schema.TypeBool,
				Description: "OIDCSettings enabled status",
				Computed:    true,
			},
			"openid_settings": {
				Type:        schema.TypeBool,
				Description: "OpenIdSettings enabled status",
				Computed:    true,
			},
			"saml_settings": {
				Type:        schema.TypeBool,
				Description: "SAMLSettings enabled status",
				Computed:    true,
			},
		},
	}
}

func dataIntegrationStateRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	iap, err := ac.GetIntegrationState()
	if err == nil {
		d.Set("oidc_settings", iap.OIDCSettings)
		d.Set("openid_settings", iap.OpenIdSettings)
		d.Set("saml_settings", iap.SAMLSettings)
		_, id := flattenIntegrationEnablesStateData(iap)
		d.SetId(id)
	} else {
		return err
	}
	return nil
}

func flattenIntegrationEnablesStateData(integrationEnabledState *client.IntegrationState) (interface{}, string) {
	id := ""
	if integrationEnabledState != nil {
		id = fmt.Sprintf("%v%v%v", integrationEnabledState.OIDCSettings, integrationEnabledState.OpenIdSettings, integrationEnabledState.SAMLSettings)
		fis := make(map[string]bool)

		fis["OIDCSettings"] = integrationEnabledState.OIDCSettings
		fis["OpenIdSettings"] = integrationEnabledState.OpenIdSettings
		fis["SAMLSettings"] = integrationEnabledState.SAMLSettings
		return fis, id
	}
	return make(map[string]bool), ""
}
