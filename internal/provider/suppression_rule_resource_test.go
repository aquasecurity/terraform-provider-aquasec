package provider

import (
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"testing"
)

func TestAccSuppressionRuleResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: providerConfig + `
resource "aquasec_suppression_rule" "test" {
  name = "test-suppression-rule"
  application_scopes = ["Global"]
  scope = {
    expression = "v1"
    variables = [
      {
        attribute = "aqua.registry"
        value = "\"Docker Hub\""
      }
    ]
  }
  score = [1]
  severity = "test-severity"
  fix_available = "false"
  vulnerabilities = "test-vulnerabilities"
  expiry = 1
  comment = "test-comment"
  status = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verity suppression rule is created
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "name", "test-suppression-rule"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "application_scopes.#", "1"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "scope.expression", "v1"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "scope.variables.#", "1"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "scope.variables.0.attribute", "aqua.registry"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "scope.variables.0.value", "\"Docker Hub\""),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "score.#", "1"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "score.0", "1"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "severity", "test-severity"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "fix_available", "false"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "vulnerabilities", "test-vulnerabilities"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "expiry", "1"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "comment", "test-comment"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "status", "true"),
					// Verify dynamic values have any value set in the state
					resource.TestCheckResourceAttrSet("aquasec_suppression_rule.test", "id"),
					resource.TestCheckResourceAttrSet("aquasec_suppression_rule.test", "created"),
					resource.TestCheckResourceAttrSet("aquasec_suppression_rule.test", "author"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "aquasec_suppression_rule.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing
			{
				Config: providerConfig + `
resource "aquasec_suppression_rule" "test" {
  name = "test-suppression-rule-updated"
  application_scopes = ["Global"]
  scope = {
    expression = "v1 && v2"
    variables = [
      {
        attribute = "image.repo"
        value = "vpu/*"
      },
      {
        attribute = "image.name"
        value = "vpu/*-direkt*"
      }
    ]
  }
  score = [2]
  severity = "test-severity-updated"
  fix_available = "true"
  vulnerabilities = "test-vulnerabilities-updated"
  expiry = 2
  comment = "test-comment-updated"
  status = false
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify suppression rule is updated
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "name", "test-suppression-rule-updated"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "application_scopes.#", "1"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "scope.expression", "v1 && v2"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "scope.variables.#", "2"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "scope.variables.0.attribute", "image.repo"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "scope.variables.0.value", "vpu/*"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "scope.variables.1.attribute", "image.name"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "scope.variables.1.value", "vpu/*-direkt*"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "score.#", "1"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "score.0", "2"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "severity", "test-severity-updated"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "fix_available", "true"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "vulnerabilities", "test-vulnerabilities-updated"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "expiry", "2"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "comment", "test-comment-updated"),
					resource.TestCheckResourceAttr("aquasec_suppression_rule.test", "status", "false"),
					// Verify dynamic values have any value set in the state
					resource.TestCheckResourceAttrSet("aquasec_suppression_rule.test", "id"),
					resource.TestCheckResourceAttrSet("aquasec_suppression_rule.test", "created"),
					resource.TestCheckResourceAttrSet("aquasec_suppression_rule.test", "author"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
