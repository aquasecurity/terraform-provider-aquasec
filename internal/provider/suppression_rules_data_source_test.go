package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSuppressionRulesDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + `data "aquasec_suppression_rules" "test" {}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify number of suppression rules returned
					resource.TestCheckResourceAttr("data.aquasec_suppression_rules.test", "suppression_rules.#", "0"),
				),
			},
		},
	})
}
