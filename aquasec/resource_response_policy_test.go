package aquasec

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceResponsePolicy(t *testing.T) {
	resourceName := "aquasec_response_policy.test"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceResponsePolicyConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "title", "Test Response Policy"),
					resource.TestCheckResourceAttr(resourceName, "description", "This is a test response policy"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
				),
			},
			{
				Config: testAccResourceResponsePolicyConfig_updated(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "This is an updated test response policy"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
				),
			},
		},
	})
}

func testAccResourceResponsePolicyConfig_basic() string {
	return `
resource "aquasec_response_policy" "test" {
  title       = "Test Response Policy"
  description = "This is a test response policy"
  enabled     = true
  application_scopes = ["Global"]

  trigger {
    predefined = "Incidents with critical severity"

    input {
      name = "Incident event"
    }

    # custom block may be omitted if you don't have anything to set
  }

  outputs {
    name = "Terraform Provider Test"
    type = "email"
  }

}
`
}

func testAccResourceResponsePolicyConfig_updated() string {
	return `
resource "aquasec_response_policy" "test" {
  title       = "Test Response Policy"
  description = "This is an updated test response policy"
  enabled     = false
  application_scopes = ["Global"]

  trigger {
    predefined = "Incidents with critical severity"

    input {
      name = "Incident event"
    }
  }

  outputs {
    name = "Terraform Provider Test"
    type = "email"
  }

}
`
}
