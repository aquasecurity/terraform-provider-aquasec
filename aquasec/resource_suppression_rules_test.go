package aquasec

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceSuppressionRule(t *testing.T) {
	resourceName := "aquasec_suppression_rule.test"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceSuppressionRuleConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", "example-suppression-rule"),
					resource.TestCheckResourceAttr(resourceName, "description", "An example suppression rule"),
				),
			},
			/*			{
						Config: testAccResourceSuppressionRuleConfig_updated(),
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr(resourceName, "description", "Updated Description"),
						),
					},*/
		},
	})
}

func testAccResourceSuppressionRuleConfig_basic() string {
	return `
	resource "aquasec_suppression_rule" "test" {
		name               = "example-suppression-rule"
		application_scopes = ["Global"]
		enable             = true
		controls {
			direct_only = true
			file_globs  = []
			published_date_filter {
			enabled = false
			days    = 30
			}
			reachable_only = true
			scan_type      = "vulnerability"
			severity       = "critical"
			target_file    = ""
			target_line    = 0
			type           = "vulnerabilitySeverity"
			vendorfix      = true
		}
		description    = "An example suppression rule"
		clear_schedule = false
		scope {
			expression = "(v1) && (v2)"
			variables {
			attribute = "repository.branch"
			value     = "main"
			}
			variables {
			attribute = "repository.provider"
			value     = "github"
			}
		}
	}
	`
}

/*func testAccResourceSuppressionRuleConfig_updated() string {
	return `
		resource "aquasec_suppression_rule" "test" {
			name               = "example-suppression-rule"
			application_scopes = ["terraform-suppression-scope-testing"]
			enable             = true
			controls {
				direct_only = true
				file_globs  = []
				published_date_filter {
				enabled = false
				days    = 30
				}
				reachable_only = true
				scan_type      = "vulnerability"
				severity       = "critical"
				target_file    = ""
				target_line    = 0
				type           = "vulnerabilitySeverity"
				vendorfix      = true
			}
			description    = "Updated Description"
			clear_schedule = false
			scope {
				expression = "(v1) && (v2)"
				variables {
				attribute = "repository.branch"
				value     = "main"
				}
				variables {
				attribute = "repository.provider"
				value     = "github"
				}
			}
		}
    `
} */
