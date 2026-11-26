package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecCspmPlugin(t *testing.T) {
	t.Parallel()
	title := acctest.RandomWithPrefix("terraform-test")
	description := "Created using Terraform"
	updatedDescription := "Updated using Terraform"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_cspm_plugin.tftest"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCspmPlugin(title, description),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCspmPluginExists("aquasec_cspm_plugin.tftest"),
					resource.TestCheckResourceAttr("aquasec_cspm_plugin.tftest", "title", title),
					resource.TestCheckResourceAttr("aquasec_cspm_plugin.tftest", "description", description),
					resource.TestCheckResourceAttr("aquasec_cspm_plugin.tftest", "cloud", "aws"),
					resource.TestCheckResourceAttr("aquasec_cspm_plugin.tftest", "asl.target_resource", "ELBv2:describeListeners"),
				),
			},
			{
				Config: testAccCheckCspmPlugin(title, updatedDescription),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCspmPluginExists("aquasec_cspm_plugin.tftest"),
					resource.TestCheckResourceAttr("aquasec_cspm_plugin.tftest", "description", updatedDescription),
				),
			},
			{
				ResourceName:      "aquasec_cspm_plugin.tftest",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckCspmPlugin(title string, description string) string {
	return fmt.Sprintf(`
	resource "aquasec_cspm_plugin" "tftest" {
		cloud       = "aws"
		category_id = 1
		title       = "%s"
		description = <<-EOT
			%s
		EOT
			
		more_info = "more info"

		recommended_action = <<-EOT
			here are things you need to do
		EOT

		custom_id = "TEST002"
		severity  = "high"

		asl {
			target_resource = "ELBv2:describeListeners"
			apis            = ["ELBv2:describeLoadBalancers", "ELBv2:describeListeners", "ELBv2:describeRules"]

			scope = jsonencode({
			type     = "condition"
			api      = "ELBv2:describeListeners"
			property = "Listeners[].Protocol"
			op       = "EQ"
			value    = "HTTP"
			})

			conditions = jsonencode({
			type       = "group"
			operator   = "OR"
			conditions = [
				{
				type     = "condition"
				api      = "ELBv2:describeListeners"
				property = "Listeners[].DefaultActions[].RedirectConfig.Protocol"
				op       = "EQ"
				value    = "HTTPS"
				},
				{
				type     = "condition"
				api      = "ELBv2:describeRules"
				property = "Rules[].Actions[].RedirectConfig.Protocol"
				op       = "EQ"
				value    = "HTTPS"
				},
			]
			})
		}
	}
	`, title, description)
}

func testAccCheckCspmPluginExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]

		if !ok {
			return fmt.Errorf("%s not found in state", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("ID for %s not set in state", n)
		}

		return nil
	}
}
