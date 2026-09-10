package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceResponsePolicy(t *testing.T) {
	resourceName := "aquasec_response_policy.test"
	policyTitle := acctest.RandomWithPrefix("tf-response-policy")
	outputName := acctest.RandomWithPrefix("tf-response-output")

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceResponsePolicyConfig(policyTitle, outputName, "This is a test response policy", true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "title", policyTitle),
					resource.TestCheckResourceAttr(resourceName, "description", "This is a test response policy"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "outputs.0.name", outputName),
					resource.TestCheckResourceAttr(resourceName, "outputs.0.type", "teams"),
				),
			},
			{
				Config: testAccResourceResponsePolicyConfig(policyTitle, outputName, "This is an updated test response policy", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "This is an updated test response policy"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
				),
			},
		},
	})
}

func testAccResourceResponsePolicyConfig(policyTitle, outputName, description string, enabled bool) string {
	return fmt.Sprintf(`
resource "aquasec_notification" "response_policy_output" {
  name = %q
  type = "teams"
  properties = {
    url = "1.1.1.1"
  }
}

resource "aquasec_response_policy" "test" {
  title              = %q
  description        = %q
  enabled            = %t
  application_scopes = ["Global"]

  trigger {
    predefined = "Incidents with critical severity"

    input {
      name = "Incident event"
    }
  }

  outputs {
    name = aquasec_notification.response_policy_output.name
    type = aquasec_notification.response_policy_output.type
  }
}
`, outputName, policyTitle, description, enabled)
}
